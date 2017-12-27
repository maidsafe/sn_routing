// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::{TestClient, TestNode, create_connected_clients, create_connected_nodes, gen_range,
            gen_range_except, poll_and_resend, verify_invariant_for_all_nodes};
use fake_clock::FakeClock;
use itertools::Itertools;
use rand::Rng;
use routing::{Authority, BootstrapConfig, Event, EventStream, ImmutableData, MessageId, PublicId,
              QUORUM_DENOMINATOR, QUORUM_NUMERATOR, Request, Response, XorName};
use routing::mock_crust::Network;
use routing::test_consts::{ACCUMULATION_TIMEOUT_SECS, CANDIDATE_ACCEPT_TIMEOUT_SECS,
                           JOINING_NODE_TIMEOUT_SECS, RESOURCE_PROOF_DURATION_SECS};
use std::cmp;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::iter;

// Randomly removes some nodes.
//
// Note: it's necessary to call `poll_all` afterwards, as this function doesn't call it itself.
fn drop_random_nodes<R: Rng>(
    rng: &mut R,
    nodes: &mut Vec<TestNode>,
    min_section_size: usize,
) -> BTreeSet<XorName> {
    let mut dropped_nodes = BTreeSet::new();
    let len = nodes.len();
    // Nodes needed for quorum with minimum section size. Round up.
    let min_quorum = 1 + (min_section_size * QUORUM_NUMERATOR) / QUORUM_DENOMINATOR;
    if rng.gen_weighted_bool(3) {
        // Pick a section then remove as many nodes as possible from it without breaking quorum.
        let i = gen_range(rng, 0, len);
        let prefix = *nodes[i].routing_table().our_prefix();

        // Any network must allow at least one node to be lost:
        let num_excess = cmp::max(
            1,
            nodes[i].routing_table().our_section().len() - min_section_size,
        );
        assert!(num_excess > 0);

        let mut removed = 0;
        // Remove nodes from the chosen section
        while removed < num_excess {
            let i = gen_range(rng, 0, nodes.len());
            if *nodes[i].routing_table().our_prefix() != prefix {
                continue;
            }
            let _ = dropped_nodes.insert(nodes[i].name());
            let _ = nodes.remove(i);
            removed += 1;
        }
    } else {
        // It should always be safe to remove min_section_size - min_quorum_size nodes (if we
        // ensured they did not all come from the same section we could remove more):
        let num_excess = cmp::min(min_section_size - min_quorum, len - min_section_size);
        let mut removed = 0;
        while num_excess - removed > 0 {
            let index = gen_range(rng, 0, len - removed);
            let _ = dropped_nodes.insert(nodes[index].name());
            let _ = nodes.remove(index);
            removed += 1;
        }
    }
    dropped_nodes
}

// Randomly adds a node. Returns new node index if successfully added.
//
// Note: This fn will call `poll_and_resend` itself
fn add_node_and_poll<R: Rng>(
    rng: &mut R,
    network: &Network<PublicId>,
    mut nodes: &mut Vec<TestNode>,
    min_section_size: usize,
    mut dropped_nodes: BTreeSet<XorName>,
) -> Option<usize> {
    let len = nodes.len();
    // A non-first node without min_section_size nodes in routing table cannot be proxy
    let (proxy, index) = if len <= min_section_size {
        (0, gen_range(rng, 1, len + 1))
    } else {
        (gen_range(rng, 0, len), gen_range(rng, 0, len + 1))
    };
    let bootstrap_config = BootstrapConfig::with_contacts(&[nodes[proxy].handle.endpoint()]);

    nodes.insert(
        index,
        TestNode::builder(network)
            .bootstrap_config(bootstrap_config)
            .create(),
    );
    let (new_node, proxy) = if index <= proxy {
        (index, proxy + 1)
    } else {
        (index, proxy)
    };

    if len > (2 * min_section_size) {
        let exclude = vec![new_node, proxy].into_iter().collect();
        let block_peer = gen_range_except(rng, 1, nodes.len(), &exclude);

        // Status to the proxy of the new node doesn't matter.
        let _ = dropped_nodes.insert(nodes[proxy].name());
        if nodes[block_peer].inner.has_unnormalised_routing_conn(
            &dropped_nodes,
        )
        {
            FakeClock::advance_time(JOINING_NODE_TIMEOUT_SECS * 1000);
        }
        debug!(
            "Connection between {} and {} blocked.",
            nodes[new_node].name(),
            nodes[block_peer].name()
        );
        network.block_connection(
            nodes[new_node].handle.endpoint(),
            nodes[block_peer].handle.endpoint(),
        );
        network.block_connection(
            nodes[block_peer].handle.endpoint(),
            nodes[new_node].handle.endpoint(),
        );
    }

    // new_node might be rejected here due to the current network state with ongoing merge or
    // lack of accumulation for Candidate/Node Approval due to blocked connections.
    poll_and_resend(&mut nodes, &mut []);

    // Check if the new node failed to join. If it failed we need to further cleanup existing nodes
    // as the call from poll_and_resend to clear_state would not remove this failed node from
    // existing nodes who have added it to their RT and will later attempt to re-connect.
    // This can occur due to NodeApproval not being sent out in some cases but nodes adding
    // joining nodes to their RT and expecting the joining node to eventually terminate itself
    match nodes[new_node].inner.try_next_ev() {
        Err(_) |
        Ok(Event::Terminate) => (),
        Ok(_) => return Some(new_node),
    };

    // Drop failed node and poll remaining nodes so any node which may have added failed node
    // to their RT will now purge this entry as part of poll_and_resend -> clear_state.
    let failed_node = nodes.remove(new_node);
    drop(failed_node);
    poll_and_resend(&mut nodes, &mut []);
    let duration_ms = cmp::max(
        RESOURCE_PROOF_DURATION_SECS + ACCUMULATION_TIMEOUT_SECS,
        CANDIDATE_ACCEPT_TIMEOUT_SECS,
    ) * 1000;

    FakeClock::advance_time(duration_ms);
    None
}

// Randomly adds or removes some nodes, causing churn.
// If a new node was added, returns the index of this node. Otherwise
// returns `None` (it never adds more than one node).
fn random_churn<R: Rng>(
    rng: &mut R,
    network: &Network<PublicId>,
    nodes: &mut Vec<TestNode>,
) -> Option<usize> {
    let len = nodes.len();

    if count_sections(nodes) > 1 && rng.gen_weighted_bool(3) {
        let _ = nodes.remove(gen_range(rng, 1, len));
        let _ = nodes.remove(gen_range(rng, 1, len - 1));
        let _ = nodes.remove(gen_range(rng, 1, len - 2));

        None
    } else {
        let mut proxy = gen_range(rng, 0, len);
        let index = gen_range(rng, 1, len + 1);

        if nodes.len() > 2 * network.min_section_size() {
            let peer_1 = gen_range(rng, 1, len);
            let peer_2 = gen_range_except(rng, 1, len, &iter::once(peer_1).collect());
            debug!(
                "Lost connection between {} and {}",
                nodes[peer_1].name(),
                nodes[peer_2].name()
            );
            network.lost_connection(
                nodes[peer_1].handle.endpoint(),
                nodes[peer_2].handle.endpoint(),
            );
        }

        let bootstrap_config = BootstrapConfig::with_contacts(&[nodes[proxy].handle.endpoint()]);
        nodes.insert(
            index,
            TestNode::builder(network)
                .bootstrap_config(bootstrap_config)
                .create(),
        );

        if nodes.len() > 2 * network.min_section_size() {
            if index <= proxy {
                // When new node sits before the proxy node, proxy index increases by 1
                proxy += 1;
            }
            let exclude = vec![index, proxy].into_iter().collect();
            let block_peer = gen_range_except(rng, 1, nodes.len(), &exclude);
            debug!(
                "Connection between {} and {} blocked.",
                nodes[index].name(),
                nodes[block_peer].name()
            );
            network.block_connection(
                nodes[index].handle.endpoint(),
                nodes[block_peer].handle.endpoint(),
            );
            network.block_connection(
                nodes[block_peer].handle.endpoint(),
                nodes[index].handle.endpoint(),
            );
        }

        Some(index)
    }
}

/// The entries of a Put request: the data ID, message ID, source and destination authority.
type PutKey = (XorName, MessageId, Authority<XorName>, Authority<XorName>);

/// A set of expectations: Which nodes, groups and sections are supposed to receive Put requests.
#[derive(Default)]
struct ExpectedPuts {
    /// The Put requests expected to be received.
    messages: HashSet<PutKey>,
    /// The section or section members of receiving groups or sections, at the time of sending.
    sections: HashMap<Authority<XorName>, HashSet<XorName>>,
}

impl ExpectedPuts {
    /// Sends a request using the nodes specified by `src`, and adds the expectation. Panics if not
    /// enough nodes sent a section message, or if an individual sending node could not be found.
    fn send_and_expect(
        &mut self,
        data: &ImmutableData,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        nodes: &mut [TestNode],
        min_section_size: usize,
    ) {
        let msg_id = MessageId::new();
        let mut sent_count = 0;
        for node in nodes.iter_mut().filter(|node| node.is_recipient(&src)) {
            if dst.is_client() {
                unwrap!(node.inner.send_get_idata_response(
                    src,
                    dst,
                    Ok(data.clone()),
                    msg_id,
                ));
            } else {
                unwrap!(node.inner.send_put_idata_request(
                    src,
                    dst,
                    data.clone(),
                    msg_id,
                ));
            }
            sent_count += 1;
        }
        if src.is_multiple() {
            assert!(sent_count * QUORUM_DENOMINATOR > min_section_size * QUORUM_NUMERATOR);
        } else {
            assert_eq!(sent_count, 1);
        }
        self.expect(nodes, dst, (*data.name(), msg_id, src, dst));
    }

    /// Sends a request from the client, and adds the expectation.
    fn client_send_and_expect(
        &mut self,
        data: &ImmutableData,
        client_auth: Authority<XorName>,
        dst: Authority<XorName>,
        client: &mut TestClient,
        nodes: &mut [TestNode],
    ) {
        let msg_id = MessageId::new();
        unwrap!(client.inner.put_idata(dst, data.clone(), msg_id));
        self.expect(nodes, dst, (*data.name(), msg_id, client_auth, dst));
    }

    /// Adds the expectation that the nodes belonging to `dst` receive the message.
    fn expect(&mut self, nodes: &mut [TestNode], dst: Authority<XorName>, key: PutKey) {
        if dst.is_multiple() && !self.sections.contains_key(&dst) {
            let is_recipient = |n: &&TestNode| n.is_recipient(&dst);
            let section = nodes
                .iter()
                .filter(is_recipient)
                .map(TestNode::name)
                .collect();
            let _ = self.sections.insert(dst, section);
        }
        let _ = self.messages.insert(key);
    }

    /// Verifies that all sent messages have been received by the appropriate nodes.
    fn verify(
        mut self,
        nodes: &mut [TestNode],
        clients: &mut [TestClient],
        new_node_name: Option<XorName>,
    ) {
        // The minimum of the section lengths when sending and now. If a churn event happened, both
        // cases are valid: that the message was received before or after that. The number of
        // recipients thus only needs to reach a quorum for the smaller of the section sizes.
        let section_sizes: HashMap<_, _> = self.sections
            .iter_mut()
            .map(|(dst, section)| {
                let is_recipient = |n: &&TestNode| n.is_recipient(dst);
                let new_section = nodes
                    .iter()
                    .filter(is_recipient)
                    .map(TestNode::name)
                    .collect_vec();
                let count = cmp::min(section.len(), new_section.len());
                section.extend(new_section);
                (*dst, count)
            })
            .collect();
        let mut section_msgs_received = HashMap::new(); // The count of received section messages.
        for node in nodes {
            while let Ok(event) = node.try_next_ev() {
                if let Event::Request {
                    request: Request::PutIData { data, msg_id },
                    src,
                    dst,
                } = event
                {
                    let name = *data.name();
                    let key = (name, msg_id, src, dst);
                    if dst.is_multiple() {
                        let checker = |entry: &HashSet<XorName>| entry.contains(&node.name());
                        if !self.sections.get(&key.3).map_or(false, checker) {
                            // TODO: depends on the affected tunnels due to the dropped nodes, there
                            // will be unexpected receiver for group (only used NaeManager in this
                            // test). This shall no longer happen once routing refactored.
                            if let Authority::NaeManager(_) = dst {
                                trace!(
                                    "Unexpected request for node {}: {:?} / {:?}",
                                    node.name(),
                                    key,
                                    self.sections
                                );
                            } else if new_node_name == Some(node.name()) {
                                // A new joined node may receive the message first, then receives
                                // the section split it incurs, hence becomes non-recipient in this
                                // call but received the request event.
                                trace!(
                                    "Unexpected request for new joined node {}: {:?} / {:?}",
                                    node.name(),
                                    key,
                                    self.sections
                                );
                            } else {
                                panic!(
                                    "Unexpected request for node {}: {:?} / {:?}",
                                    node.name(),
                                    key,
                                    self.sections
                                );
                            }
                        } else {
                            *section_msgs_received.entry(key).or_insert(0usize) += 1;
                        }
                    } else {
                        assert_eq!(node.name(), dst.name());
                        assert!(
                            self.messages.remove(&key),
                            "Unexpected request for node {}: {:?}",
                            node.name(),
                            key
                        );
                    }
                }
            }
        }
        for client in clients {
            while let Ok(event) = client.inner.try_next_ev() {
                if let Event::Response {
                    response: Response::GetIData { res, msg_id },
                    src,
                    dst,
                } = event
                {
                    let data = unwrap!(res);
                    let key = (*data.name(), msg_id, src, dst);
                    assert!(
                        self.messages.remove(&key),
                        "Unexpected request for client {}: {:?}",
                        client.name(),
                        key
                    );
                }
            }
        }
        for key in self.messages {
            // All received messages for single nodes were removed: if any are left, they failed.
            assert!(key.3.is_multiple(), "Failed to receive request {:?}", key);
            let section_size = section_sizes[&key.3];
            let count = section_msgs_received.remove(&key).unwrap_or(0);
            assert!(
                count * QUORUM_DENOMINATOR > section_size * QUORUM_NUMERATOR,
                "Only received {} out of {} messages {:?}.",
                count,
                section_size,
                key
            );
        }
    }
}

fn send_and_receive<R: Rng>(rng: &mut R, nodes: &mut [TestNode], min_section_size: usize) {
    // Create random data ID and pick random sending and receiving nodes.
    let data = ImmutableData::new(rng.gen_iter().take(100).collect());
    let index0 = gen_range(rng, 0, nodes.len());
    let index1 = gen_range(rng, 0, nodes.len());
    let auth_n0 = Authority::ManagedNode(nodes[index0].name());
    let auth_n1 = Authority::ManagedNode(nodes[index1].name());
    let auth_g0 = Authority::NaeManager(rng.gen());
    let auth_g1 = Authority::NaeManager(rng.gen());
    let section_name: XorName = rng.gen();
    let auth_s0 = Authority::Section(section_name);
    // this makes sure we have two different sections if there exists more than one
    let auth_s1 = Authority::Section(!section_name);

    let mut expected_puts = ExpectedPuts::default();

    // Test messages from a node to itself, another node, a group and a section...
    expected_puts.send_and_expect(&data, auth_n0, auth_n0, nodes, min_section_size);
    expected_puts.send_and_expect(&data, auth_n0, auth_n1, nodes, min_section_size);
    expected_puts.send_and_expect(&data, auth_n0, auth_g0, nodes, min_section_size);
    expected_puts.send_and_expect(&data, auth_n0, auth_s0, nodes, min_section_size);
    // ... and from a section to itself, another section, a group and a node...
    expected_puts.send_and_expect(&data, auth_g0, auth_g0, nodes, min_section_size);
    expected_puts.send_and_expect(&data, auth_g0, auth_g1, nodes, min_section_size);
    expected_puts.send_and_expect(&data, auth_g0, auth_s0, nodes, min_section_size);
    expected_puts.send_and_expect(&data, auth_g0, auth_n0, nodes, min_section_size);
    // ... and from a section to itself, another section, a group and a node...
    expected_puts.send_and_expect(&data, auth_s0, auth_s0, nodes, min_section_size);
    expected_puts.send_and_expect(&data, auth_s0, auth_s1, nodes, min_section_size);
    expected_puts.send_and_expect(&data, auth_s0, auth_g0, nodes, min_section_size);
    expected_puts.send_and_expect(&data, auth_s0, auth_n0, nodes, min_section_size);

    poll_and_resend(nodes, &mut []);

    expected_puts.verify(nodes, &mut [], None);
}

fn client_puts(network: &mut Network<PublicId>, nodes: &mut [TestNode], min_section_size: usize) {
    let mut clients = create_connected_clients(network, nodes, 1);
    let cl_auth = Authority::Client {
        client_id: *clients[0].full_id.public_id(),
        proxy_node_name: nodes[0].name(),
    };

    let mut rng = network.new_rng();
    let data = ImmutableData::new(rng.gen_iter().take(100).collect());
    let auth_g0 = Authority::NaeManager(rng.gen());
    let auth_g1 = Authority::NaeManager(rng.gen());
    let section_name: XorName = rng.gen();
    let auth_s0 = Authority::Section(section_name);

    let mut expected_puts = ExpectedPuts::default();
    // Test messages from a client to a group and a section...
    expected_puts.client_send_and_expect(&data, cl_auth, auth_g0, &mut clients[0], nodes);
    expected_puts.client_send_and_expect(&data, cl_auth, auth_s0, &mut clients[0], nodes);
    // ... and from group to the client
    expected_puts.send_and_expect(&data, auth_g1, cl_auth, nodes, min_section_size);

    poll_and_resend(nodes, &mut clients);
    expected_puts.verify(nodes, &mut clients, None);
}

fn count_sections(nodes: &[TestNode]) -> usize {
    let mut prefixes = HashSet::new();
    for node in nodes {
        let _ = prefixes.insert(*node.routing_table().our_prefix());
    }
    prefixes.len()
}

fn verify_section_list_signatures(nodes: &[TestNode]) {
    for node in nodes {
        let rt = node.routing_table();
        let section_size = rt.our_section().len();
        for prefix in rt.prefixes() {
            if prefix != *rt.our_prefix() {
                let sigs = unwrap!(
                    node.inner.section_list_signatures(prefix),
                    "{:?} Tried to unwrap None returned from \
                                    section_list_signatures({:?})",
                    node.name(),
                    prefix
                );
                assert!(
                    sigs.len() * QUORUM_DENOMINATOR > section_size * QUORUM_NUMERATOR,
                    "{:?} Not enough signatures for prefix {:?} - {}/{}\n\tSignatures from: \
                         {:?}",
                    node.name(),
                    prefix,
                    sigs.len(),
                    section_size,
                    sigs.keys().collect_vec()
                );
            }
        }
    }
}

#[test]
fn aggressive_churn() {
    let min_section_size = 5;
    let target_section_num = 5;
    let target_network_size = 50;
    let mut network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();

    // Create an initial network, increase until we have several sections, then
    // decrease back to min_section_size, then increase to again.
    let mut nodes = create_connected_nodes(&network, min_section_size);

    info!(
        "Churn [{} nodes, {} sections]: adding nodes",
        nodes.len(),
        count_sections(&nodes)
    );
    while count_sections(&nodes) <= target_section_num || nodes.len() < target_network_size {
        if nodes.len() > (2 * min_section_size) {
            let peer_1 = gen_range(&mut rng, 0, nodes.len());
            let peer_2 = gen_range_except(&mut rng, 0, nodes.len(), &iter::once(peer_1).collect());
            debug!(
                "Lost connection between {} and {}",
                nodes[peer_1].name(),
                nodes[peer_2].name()
            );
            network.lost_connection(
                nodes[peer_1].handle.endpoint(),
                nodes[peer_2].handle.endpoint(),
            );
        }

        // A candidate could be blocked if some nodes of the section it connected to has lost node
        // due to loss of tunnel. In that case, a restart of candidate shall be carried out.
        if let Some(added_index) =
            add_node_and_poll(
                &mut rng,
                &network,
                &mut nodes,
                min_section_size,
                BTreeSet::new(),
            )
        {
            debug!("Added {}", nodes[added_index].name());
        } else {
            debug!("Unable to add new node.");
        }

        verify_invariant_for_all_nodes(&mut nodes);
        verify_section_list_signatures(&nodes);
        send_and_receive(&mut rng, &mut nodes, min_section_size);
    }

    info!(
        "Churn [{} nodes, {} sections]: simultaneous adding and dropping nodes",
        nodes.len(),
        count_sections(&nodes)
    );
    while nodes.len() > target_network_size / 2 {
        let dropped_nodes = drop_random_nodes(&mut rng, &mut nodes, min_section_size);

        // A candidate could be blocked if it connected to a pre-merge minority section.
        // Or be rejected when the proxy node's RT is not large enough due to a lost tunnel.
        // In that case, a restart of candidate shall be carried out.
        if let Some(added_index) =
            add_node_and_poll(
                &mut rng,
                &network,
                &mut nodes,
                min_section_size,
                dropped_nodes,
            )
        {
            debug!("Simultaneous added {}", nodes[added_index].name());
        } else {
            debug!("Unable to add new node.");
        }

        verify_invariant_for_all_nodes(&mut nodes);
        verify_section_list_signatures(&nodes);

        send_and_receive(&mut rng, &mut nodes, min_section_size);
        client_puts(&mut network, &mut nodes, min_section_size);
    }

    info!(
        "Churn [{} nodes, {} sections]: dropping nodes",
        nodes.len(),
        count_sections(&nodes)
    );
    while count_sections(&nodes) > 1 && nodes.len() > min_section_size {
        debug!(
            "Dropping random nodes.  Current node count: {}",
            nodes.len()
        );
        let _ = drop_random_nodes(&mut rng, &mut nodes, min_section_size);
        poll_and_resend(&mut nodes, &mut []);
        verify_invariant_for_all_nodes(&mut nodes);
        verify_section_list_signatures(&nodes);
        send_and_receive(&mut rng, &mut nodes, min_section_size);
        client_puts(&mut network, &mut nodes, min_section_size);
    }

    info!(
        "Churn [{} nodes, {} sections]: done",
        nodes.len(),
        count_sections(&nodes)
    );
}

#[test]
fn messages_during_churn() {
    let min_section_size = 8;
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, 20);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);
    let cl_auth = Authority::Client {
        client_id: *clients[0].full_id.public_id(),
        proxy_node_name: nodes[0].name(),
    };

    for i in 0..100 {
        trace!("Iteration {}", i);
        let added_index = random_churn(&mut rng, &network, &mut nodes);

        // Create random data and pick random sending and receiving nodes.
        let data = ImmutableData::new(rng.gen_iter().take(100).collect());
        let exclude = added_index.map_or(BTreeSet::new(), |index| iter::once(index).collect());
        let index0 = gen_range_except(&mut rng, 0, nodes.len(), &exclude);
        let index1 = gen_range_except(&mut rng, 0, nodes.len(), &exclude);
        let auth_n0 = Authority::ManagedNode(nodes[index0].name());
        let auth_n1 = Authority::ManagedNode(nodes[index1].name());
        let auth_g0 = Authority::NaeManager(rng.gen());
        let auth_g1 = Authority::NaeManager(rng.gen());
        let section_name: XorName = rng.gen();
        let auth_s0 = Authority::Section(section_name);
        // this makes sure we have two different sections if there exists more than one
        // let auth_s1 = Authority::Section(!section_name);

        let mut expected_puts = ExpectedPuts::default();

        // Test messages from a node to itself, another node, a group and a section...
        expected_puts.send_and_expect(&data, auth_n0, auth_n0, &mut nodes, min_section_size);
        expected_puts.send_and_expect(&data, auth_n0, auth_n1, &mut nodes, min_section_size);
        expected_puts.send_and_expect(&data, auth_n0, auth_g0, &mut nodes, min_section_size);
        expected_puts.send_and_expect(&data, auth_n0, auth_s0, &mut nodes, min_section_size);
        // ... and from a group to itself, another group, a section and a node...
        expected_puts.send_and_expect(&data, auth_g0, auth_g0, &mut nodes, min_section_size);
        expected_puts.send_and_expect(&data, auth_g0, auth_g1, &mut nodes, min_section_size);
        expected_puts.send_and_expect(&data, auth_g0, auth_s0, &mut nodes, min_section_size);
        expected_puts.send_and_expect(&data, auth_g0, auth_n0, &mut nodes, min_section_size);
        // ... and from a section to itself, another section, a group and a node...
        // TODO: Enable these once MAID-1920 is fixed.
        // expected_puts.send_and_expect(data.clone(), auth_s0, auth_s0, &nodes, min_section_size);
        // expected_puts.send_and_expect(data.clone(), auth_s0, auth_s1, &nodes, min_section_size);
        // expected_puts.send_and_expect(data.clone(), auth_s0, auth_g0, &nodes, min_section_size);
        // expected_puts.send_and_expect(data.clone(), auth_s0, auth_n0, &nodes, min_section_size);

        let data = ImmutableData::new(rng.gen_iter().take(100).collect());
        // Test messages from a client to a group and a section...
        expected_puts.client_send_and_expect(&data, cl_auth, auth_g0, &mut clients[0], &mut nodes);
        expected_puts.client_send_and_expect(&data, cl_auth, auth_s0, &mut clients[0], &mut nodes);
        // ... and from group to the client
        expected_puts.send_and_expect(&data, auth_g1, cl_auth, &mut nodes, min_section_size);

        poll_and_resend(&mut nodes, &mut clients);

        let new_node_name = added_index.map(|index| nodes[index].name());
        expected_puts.verify(&mut nodes, &mut clients, new_node_name);

        verify_invariant_for_all_nodes(&mut nodes);
        verify_section_list_signatures(&nodes);
    }
}

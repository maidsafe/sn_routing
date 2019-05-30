// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    clear_relocation_overrides, count_sections, create_connected_clients, create_connected_nodes,
    create_connected_nodes_until_split, current_sections, gen_range, gen_range_except,
    poll_and_resend, verify_invariant_for_all_nodes, TestClient, TestNode,
};
use itertools::Itertools;
use rand::Rng;
use routing::mock_crust::Network;
use routing::{
    Authority, BootstrapConfig, Event, EventStream, ImmutableData, MessageId, PublicId, Request,
    Response, XorName, XorTargetInterval, QUORUM_DENOMINATOR, QUORUM_NUMERATOR,
};
use std::cmp;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Randomly removes some nodes, but <1/3 from each section and never node 0.
/// max_per_pfx: limits dropping to the specified count per pfx. It would also
/// skip prefixes randomly allowing sections to split if this is executed in the same
/// iteration as `add_nodes_and_poll`.
///
/// Note: it's necessary to call `poll_all` afterwards, as this function doesn't call it itself.
fn drop_random_nodes<R: Rng>(
    rng: &mut R,
    nodes: &mut Vec<TestNode>,
    max_per_pfx: Option<usize>,
) -> BTreeSet<XorName> {
    let mut dropped_nodes = BTreeSet::new();
    let node_section_size = |node: &TestNode| node.chain().our_info().members().len();
    let sections: BTreeMap<_, _> = nodes
        .iter()
        .map(|node| (*node.our_prefix(), node_section_size(node)))
        .collect();
    let mut drop_count: BTreeMap<_, _> = sections.keys().map(|pfx| (*pfx, 0)).collect();
    loop {
        let i = gen_range(rng, 1, nodes.len());
        let pfx = nodes[i].our_prefix();
        if drop_count.is_empty() {
            break;
        } else if drop_count.get(&pfx).is_none() {
            continue;
        }

        let early_terminate = max_per_pfx.map_or(false, |n| {
            drop_count[&pfx] >= n || rng.gen_weighted_bool(drop_count.keys().len() as u32)
        });
        let normal_terminate = (drop_count[&pfx] + 1) * 3 >= sections[&pfx];
        if early_terminate || normal_terminate {
            let _ = drop_count.remove(&pfx);
            continue;
        }

        *unwrap!(drop_count.get_mut(&pfx)) += 1;
        let dropped = nodes.remove(i);
        assert!(dropped_nodes.insert(dropped.name()));
    }
    dropped_nodes
}

/// Adds node per existing prefix using a random proxy. Returns new node indices.
/// skip_some_prefixes: skip adding to prefixes randomly to allowing sections to merge
/// when this is executed in the same iteration as `drop_random_nodes`.
///
/// Note: This does not clear relocation overrides. Should be cleared after polling.
fn add_nodes<R: Rng>(
    rng: &mut R,
    network: &Network<PublicId>,
    nodes: &mut Vec<TestNode>,
    skip_some_prefixes: bool,
) -> BTreeSet<usize> {
    let mut prefixes: BTreeSet<_> = nodes
        .iter_mut()
        .map(|node| {
            let pfx = *node.our_prefix();
            node.inner.set_next_relocation_dst(Some(pfx.lower_bound()));
            node.inner
                .set_next_relocation_interval(Some(XorTargetInterval(
                    pfx.lower_bound(),
                    pfx.upper_bound(),
                )));
            pfx
        })
        .collect();

    let mut added_nodes = Vec::new();
    while !prefixes.is_empty() {
        let proxy_index = if nodes.len() > nodes[0].chain().min_sec_size() {
            gen_range(rng, 0, nodes.len())
        } else {
            0
        };
        let bootstrap_config =
            BootstrapConfig::with_contacts(&[nodes[proxy_index].handle.endpoint()]);
        let node = TestNode::builder(&network)
            .bootstrap_config(bootstrap_config.clone())
            .create();
        if let Some(&pfx) = prefixes.iter().find(|pfx| pfx.matches(&node.name())) {
            assert!(prefixes.remove(&pfx));
            if skip_some_prefixes && !rng.gen_weighted_bool(prefixes.len() as u32) {
                continue;
            }
            added_nodes.push(node);
        }
    }

    for added_node in added_nodes {
        let index = gen_range(rng, 1, nodes.len() + 1);
        nodes.insert(index, added_node);
    }

    nodes
        .iter()
        .enumerate()
        .filter_map(|(index, node)| {
            if !node.inner.is_node() {
                Some(index)
            } else {
                None
            }
        })
        .collect()
}

/// Checks if the given indices have been accepted to the network.
/// Returns the names of added nodes and indices of failed nodes.
fn check_added_indices(
    nodes: &mut Vec<TestNode>,
    new_indices: BTreeSet<usize>,
) -> (BTreeSet<XorName>, Vec<usize>) {
    let mut added = BTreeSet::new();
    let mut failed = Vec::new();
    for (index, node) in nodes.iter_mut().enumerate() {
        if !new_indices.contains(&index) {
            continue;
        }

        loop {
            match node.inner.try_next_ev() {
                Err(_) => {
                    failed.push(index);
                    break;
                }
                Ok(Event::Connected) => {
                    assert!(added.insert(node.name()));
                    break;
                }
                _ => (),
            }
        }
    }

    (added, failed)
}

// Shuffle nodes excluding the first node
fn shuffle_nodes<R: Rng>(rng: &mut R, nodes: &mut Vec<TestNode>) {
    rng.shuffle(&mut nodes[1..]);
}

/// Adds node per existing prefix. Returns new node names if successfully added.
/// allow_add_failure: Allows nodes to fail getting accepted. It would also
/// skip adding to prefixes randomly to allowing sections to merge when this is executed
/// in the same iteration as `drop_random_nodes`.
///
/// Note: This fn will call `poll_and_resend` itself
fn add_nodes_and_poll<R: Rng>(
    rng: &mut R,
    network: &Network<PublicId>,
    mut nodes: &mut Vec<TestNode>,
    allow_add_failure: bool,
) -> BTreeSet<XorName> {
    let new_indices = add_nodes(rng, &network, nodes, allow_add_failure);
    poll_and_resend(&mut nodes, &mut []);
    let (added_names, failed_indices) = check_added_indices(nodes, new_indices);

    if !allow_add_failure && !failed_indices.is_empty() {
        panic!("Unable to add new nodes. {} failed.", failed_indices.len());
    }

    // Drop failed_indices and poll remaining nodes to clear pending states.
    for index in failed_indices.into_iter().rev() {
        drop(nodes.remove(index));
    }

    clear_relocation_overrides(nodes);
    poll_and_resend(&mut nodes, &mut []);
    shuffle_nodes(rng, nodes);

    added_names
}

// Churns the given network randomly. Returns any newly added indices.
// If introducing churn, would either drop/add nodes in each prefix.
fn random_churn<R: Rng>(
    rng: &mut R,
    network: &Network<PublicId>,
    nodes: &mut Vec<TestNode>,
    max_prefixes_len: usize,
) -> BTreeSet<usize> {
    // 20% chance to not churn.
    if rng.gen_weighted_bool(5) {
        return BTreeSet::new();
    }

    let section_count = count_sections(nodes);
    if section_count < max_prefixes_len {
        return add_nodes(rng, &network, nodes, false);
    }

    // Use min_sec_size rather than section size to prevent collapsing any groups.
    let max_drop = (nodes[0].chain().min_sec_size() - 1) * (QUORUM_DENOMINATOR - QUORUM_NUMERATOR)
        / QUORUM_DENOMINATOR;
    assert!(max_drop > 0);
    let dropped_nodes = drop_random_nodes(rng, nodes, Some(max_drop));
    warn!("Dropping nodes: {:?}", dropped_nodes);
    BTreeSet::new()
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
                unwrap!(node
                    .inner
                    .send_get_idata_response(src, dst, Ok(data.clone()), msg_id,));
            } else {
                unwrap!(node
                    .inner
                    .send_put_idata_request(src, dst, data.clone(), msg_id,));
            }
            sent_count += 1;
        }
        if src.is_multiple() {
            assert!(
                sent_count * QUORUM_DENOMINATOR > min_section_size * QUORUM_NUMERATOR,
                "sent_count: {}. min_section_size: {}",
                sent_count,
                min_section_size
            );
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
    fn verify(mut self, nodes: &mut [TestNode], clients: &mut [TestClient]) {
        // The minimum of the section lengths when sending and now. If a churn event happened, both
        // cases are valid: that the message was received before or after that. The number of
        // recipients thus only needs to reach a quorum for the smaller of the section sizes.
        let section_sizes: HashMap<_, _> = self
            .sections
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
                if let Event::RequestReceived {
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
                            if let Authority::NaeManager(_) = dst {
                                trace!(
                                    "Unexpected request for node {}: {:?} / {:?}",
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
                if let Event::ResponseReceived {
                    response: Response::GetIData { res, msg_id },
                    src,
                    dst,
                } = event
                {
                    let data = unwrap!(res);
                    let key = (*data.name(), msg_id, src, dst);
                    assert!(
                        self.messages.remove(&key),
                        "Unexpected response for client {}: {:?}",
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

    expected_puts.verify(nodes, &mut []);
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
    expected_puts.verify(nodes, &mut clients);
}

#[test]
fn aggressive_churn() {
    let min_section_size = 4;
    let target_section_num = 5;
    let target_network_size = 35;
    let mut network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();

    // Create an initial network, increase until we have several sections, then
    // decrease back to min_section_size, then increase to again.
    let mut nodes = create_connected_nodes(&network, min_section_size);

    warn!(
        "Churn [{} nodes, {} sections]: adding nodes",
        nodes.len(),
        count_sections(&nodes)
    );

    // Add nodes to trigger splits.
    while count_sections(&nodes) < target_section_num || nodes.len() < target_network_size {
        let added = add_nodes_and_poll(&mut rng, &network, &mut nodes, false);
        if !added.is_empty() {
            warn!("Added {:?}. Total: {}", added, nodes.len());
        } else {
            warn!("Unable to add new node.");
        }

        verify_invariant_for_all_nodes(&mut nodes);
        send_and_receive(&mut rng, &mut nodes, min_section_size);
    }

    // Simultaneous Add/Drop nodes in the same iteration.
    warn!(
        "Churn [{} nodes, {} sections]: simultaneous adding and dropping nodes",
        nodes.len(),
        count_sections(&nodes)
    );
    let mut count = 0;
    while nodes.len() > target_network_size / 2 && count < 15 {
        count += 1;

        // Only max drop a node per pfx as the node added in this iteration could split a pfx
        // making the 1/3rd calculation in drop_random_nodes incorrect for the split pfx when we poll.
        let max_drop = 1;
        let dropped = drop_random_nodes(&mut rng, &mut nodes, Some(max_drop));
        let added = add_nodes_and_poll(&mut rng, &network, &mut nodes, true);
        warn!("Simultaneously added {:?} and dropped {:?}", added, dropped);

        verify_invariant_for_all_nodes(&mut nodes);

        send_and_receive(&mut rng, &mut nodes, min_section_size);
        client_puts(&mut network, &mut nodes, min_section_size);
        warn!("Remaining Prefixes: {:?}", current_sections(&nodes));
    }

    // Drop nodes to trigger merges.
    warn!(
        "Churn [{} nodes, {} sections]: dropping nodes",
        nodes.len(),
        count_sections(&nodes)
    );
    while count_sections(&nodes) > 1 && nodes.len() > min_section_size {
        let dropped_nodes = drop_random_nodes(&mut rng, &mut nodes, None);
        warn!("Dropping random nodes. Dropped: {:?}", dropped_nodes);
        poll_and_resend(&mut nodes, &mut []);
        verify_invariant_for_all_nodes(&mut nodes);
        send_and_receive(&mut rng, &mut nodes, min_section_size);
        client_puts(&mut network, &mut nodes, min_section_size);
        shuffle_nodes(&mut rng, &mut nodes);
        warn!("Remaining Prefixes: {:?}", current_sections(&nodes));
    }

    warn!(
        "Churn [{} nodes, {} sections]: done",
        nodes.len(),
        count_sections(&nodes)
    );
}

#[test]
fn messages_during_churn() {
    let min_section_size = 4;
    let network = Network::new(min_section_size, None);
    let mut rng = network.new_rng();
    let prefixes = vec![2, 2, 2, 3, 3];
    let prefixes_len = prefixes.len();
    let mut nodes = create_connected_nodes_until_split(&network, prefixes, false);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);
    let cl_auth = Authority::Client {
        client_id: *clients[0].full_id.public_id(),
        proxy_node_name: nodes[0].name(),
    };

    for i in 0..50 {
        warn!("Iteration {}. Prefixes: {:?}", i, current_sections(&nodes));
        let new_indices = random_churn(&mut rng, &network, &mut nodes, prefixes_len);

        // Create random data and pick random sending and receiving nodes.
        let data = ImmutableData::new(rng.gen_iter().take(100).collect());
        let index0 = gen_range_except(&mut rng, 0, nodes.len(), &new_indices);
        let index1 = gen_range_except(&mut rng, 0, nodes.len(), &new_indices);
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
        expected_puts.send_and_expect(&data, auth_s0, auth_s0, &mut nodes, min_section_size);
        expected_puts.send_and_expect(&data, auth_s0, auth_s1, &mut nodes, min_section_size);
        expected_puts.send_and_expect(&data, auth_s0, auth_g0, &mut nodes, min_section_size);
        expected_puts.send_and_expect(&data, auth_s0, auth_n0, &mut nodes, min_section_size);

        let data = ImmutableData::new(rng.gen_iter().take(100).collect());
        // Test messages from a client to a group and a section...
        expected_puts.client_send_and_expect(&data, cl_auth, auth_g0, &mut clients[0], &mut nodes);
        expected_puts.client_send_and_expect(&data, cl_auth, auth_s0, &mut clients[0], &mut nodes);
        // ... and from group to the client
        expected_puts.send_and_expect(&data, auth_g1, cl_auth, &mut nodes, min_section_size);

        poll_and_resend(&mut nodes, &mut clients);
        let (added_names, failed_indices) = check_added_indices(&mut nodes, new_indices);
        assert!(failed_indices.is_empty());
        clear_relocation_overrides(&mut nodes);
        shuffle_nodes(&mut rng, &mut nodes);

        if !added_names.is_empty() {
            warn!("Added nodes: {:?}", added_names);
        }
        expected_puts.verify(&mut nodes, &mut clients);
        verify_invariant_for_all_nodes(&mut nodes);
    }
}

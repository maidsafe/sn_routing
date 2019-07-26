// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    init_mock, Block, ConsensusMode, NetworkEvent, Observation, Parsec, PublicId, Request,
    Response, SecretId,
};
use maidsafe_utilities::SeededRng;
use rand::Rng;
use std::{
    cmp,
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug, Formatter},
    ops::{Deref, DerefMut},
};
use unwrap::unwrap;

#[test]
fn smoke() {
    init_mock();

    let alice_id = PeerId(0);
    let bob_id = PeerId(1);

    let mut genesis_group = BTreeSet::new();
    let _ = genesis_group.insert(alice_id);
    let _ = genesis_group.insert(bob_id);

    let mut alice = from_genesis(alice_id, &genesis_group, ConsensusMode::Supermajority);

    let mut bob = from_genesis(bob_id, &genesis_group, ConsensusMode::Supermajority);

    alice
        .vote_for(Observation::OpaquePayload(Payload(1)))
        .unwrap();

    bob.vote_for(Observation::OpaquePayload(Payload(1)))
        .unwrap();

    let request = bob.create_gossip(&alice_id).unwrap();
    let response_0 = alice.handle_request(&bob_id, request).unwrap();

    alice
        .vote_for(Observation::OpaquePayload(Payload(0)))
        .unwrap();
    bob.vote_for(Observation::OpaquePayload(Payload(0)))
        .unwrap();

    let request = bob.create_gossip(&alice_id).unwrap();
    let response_1 = alice.handle_request(&bob_id, request).unwrap();

    // Deliver the responses in reverse order.
    bob.handle_response(&bob_id, response_1).unwrap();
    bob.handle_response(&bob_id, response_0).unwrap();

    let alice_blocks: Vec<_> = poll_all(&mut alice).collect();
    let bob_blocks: Vec<_> = poll_all(&mut bob).collect();

    assert_eq!(alice_blocks.len(), 3); // Genesis + Payload(1) + Payload(0)
    assert_eq!(alice_blocks, bob_blocks);
}

#[test]
fn add_peer() {
    init_mock();

    let alice_id = PeerId(0);
    let bob_id = PeerId(1);
    let carol_id = PeerId(2);

    let mut genesis_group = BTreeSet::new();
    let _ = genesis_group.insert(bob_id);
    let _ = genesis_group.insert(carol_id);

    let mut bob = from_genesis(bob_id, &genesis_group, ConsensusMode::Supermajority);
    let mut carol = from_genesis(carol_id, &genesis_group, ConsensusMode::Supermajority);

    let mut alice = from_existing(
        alice_id,
        &genesis_group,
        &genesis_group,
        ConsensusMode::Supermajority,
    );

    let mut alice_blocks = vec![];
    let mut bob_blocks = vec![];
    let mut carol_blocks = vec![];

    assert!(!is_gossip_recipient(&bob, alice_id));
    assert!(!is_gossip_recipient(&carol, alice_id));

    let add_alice = Observation::Add {
        peer_id: alice_id,
        related_info: vec![],
    };

    let payload0 = Observation::OpaquePayload(Payload(0));

    bob.vote_for(add_alice.clone()).unwrap();
    carol.vote_for(add_alice.clone()).unwrap();

    exchange_gossip(&mut bob, &mut carol);

    bob_blocks.extend(poll_all(&mut bob));
    carol_blocks.extend(poll_all(&mut carol));

    assert!(is_gossip_recipient(&bob, alice_id));
    assert!(is_gossip_recipient(&carol, alice_id));

    bob.vote_for(payload0.clone()).unwrap();
    carol.vote_for(payload0.clone()).unwrap();

    exchange_gossip(&mut bob, &mut alice);

    alice.vote_for(payload0.clone()).unwrap();

    exchange_gossip(&mut carol, &mut alice);
    exchange_gossip(&mut carol, &mut bob);

    alice_blocks.extend(poll_all(&mut alice));
    bob_blocks.extend(poll_all(&mut bob));
    carol_blocks.extend(poll_all(&mut carol));

    assert_eq!(alice_blocks.len(), 3);
    assert_eq!(alice_blocks, bob_blocks);
    assert_eq!(bob_blocks, carol_blocks);
}

#[test]
fn consensus_mode_single() {
    init_mock();

    let alice_id = PeerId(0);
    let bob_id = PeerId(1);

    let mut genesis_group = BTreeSet::new();
    let _ = genesis_group.insert(alice_id);
    let _ = genesis_group.insert(bob_id);

    let mut alice = from_genesis(alice_id, &genesis_group, ConsensusMode::Single);
    let mut bob = from_genesis(bob_id, &genesis_group, ConsensusMode::Single);

    // First cast votes with different payloads. They should all get consensused.
    alice
        .vote_for(Observation::OpaquePayload(Payload(0)))
        .unwrap();
    bob.vote_for(Observation::OpaquePayload(Payload(1)))
        .unwrap();

    exchange_gossip(&mut bob, &mut alice);

    let alice_blocks: Vec<_> = poll_all(&mut alice).collect();
    let bob_blocks: Vec<_> = poll_all(&mut bob).collect();
    assert_eq!(alice_blocks.len(), 3); // Genesis + Payload(0) + Payload(1)
    assert_eq!(alice_blocks, bob_blocks);

    // Now cast votes with the same payload. They should get consensused separately.
    alice
        .vote_for(Observation::OpaquePayload(Payload(2)))
        .unwrap();
    bob.vote_for(Observation::OpaquePayload(Payload(2)))
        .unwrap();

    exchange_gossip(&mut bob, &mut alice);

    let alice_blocks: Vec<_> = poll_all(&mut alice).collect();
    let bob_blocks: Vec<_> = poll_all(&mut bob).collect();
    assert_eq!(alice_blocks.len(), 2); // Alice's Payload(2) + Bob's Payload(2)
    assert_eq!(alice_blocks, bob_blocks);
}

#[test]
fn reevaluate_previously_insufficient_votes() {
    init_mock();

    // Create 5 nodes (Alice, Bob, Carol, Dave, Eric). 3 of them vote to remove Dave, which is not
    // enough to reach consensus. Then all vote to remove Eric which gets consensused and Eric is
    // removed. The previous votes to remove Dave are now enough to reach consensus and so Dave
    // should be removed too.
    let mut nodes: Vec<_> = create_nodes(5, ConsensusMode::Single).collect();
    let dave = PeerId(3);
    let eric = PeerId(4);

    // Drain the `Genesis` blocks.
    gossip_all(&mut nodes);
    for node in &mut nodes {
        for _ in poll_all(node) {}
    }

    // 3 votes to Remove(Dave) - should not get consensus yet.
    vote_for_remove(&mut nodes[..3], dave);
    gossip_all(&mut nodes);
    assert_no_consensus(&mut nodes);

    // Remove Eric
    vote_for_remove(&mut nodes, eric);
    gossip_all(&mut nodes);
    assert_consensus_on_remove(&mut nodes, eric);
    let _ = nodes.remove(4);

    // We should now get consensus on Remove(Dave) too.
    assert_consensus_on_remove(&mut nodes, dave);
}

#[test]
fn randomized_static_network() {
    init_mock();

    let num_peers = 10;
    let num_votes = 10;
    let gossip_prob = 0.1;
    let max_steps = 1000;

    let mut rng = SeededRng::new();
    let mut peers: BTreeMap<_, _> = create_nodes(num_peers, ConsensusMode::Supermajority)
        .map(|peer| (*peer.our_pub_id(), Peer::from(peer)))
        .collect();

    // Everybody votes for everything, but in random order.
    let mut votes: Vec<_> = (0..num_votes)
        .map(|num| Observation::OpaquePayload(Payload(num)))
        .collect();

    for peer in peers.values_mut() {
        rng.shuffle(&mut votes);
        for vote in votes.iter().cloned() {
            peer.vote_for(vote).unwrap();
        }
    }

    let mut messages = Vec::new();

    for _ in 0..max_steps {
        // Every peer gossips with a probability `gossip_prob`.
        for (peer_id, peer) in &mut peers {
            if rng.gen::<f64>() < gossip_prob {
                let dst = if let Some(dst) = pick_gossip_recipient(&mut rng, peer) {
                    *dst
                } else {
                    continue;
                };

                let request = peer.create_gossip(&dst).unwrap();

                messages.push(Message {
                    src: *peer_id,
                    dst,
                    content: MessageContent::Request(request),
                });
            }
        }

        // Deliver the messages in random order
        rng.shuffle(&mut messages);
        messages = messages
            .drain(..)
            .filter_map(|message| {
                let recipient = peers.get_mut(&message.dst).unwrap();

                match message.content {
                    MessageContent::Request(request) => {
                        let response = recipient.handle_request(&message.src, request).unwrap();

                        Some(Message {
                            src: message.dst,
                            dst: message.src,
                            content: MessageContent::Response(response),
                        })
                    }
                    MessageContent::Response(response) => {
                        recipient.handle_response(&message.src, response).unwrap();
                        None
                    }
                }
            })
            .collect();

        // Poll..
        for peer in peers.values_mut() {
            peer.poll();
        }

        if check_consensus(&peers, num_votes + 1) {
            return;
        }
    }

    panic!("Consensus hasn't been reached after {} steps.", max_steps);
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
struct PeerId(usize);

impl SecretId for PeerId {
    type PublicId = PeerId;

    fn public_id(&self) -> &Self::PublicId {
        self
    }

    fn sign_detached(&self, _: &[u8]) -> <Self::PublicId as PublicId>::Signature {}

    fn encrypt<M: AsRef<[u8]>>(&self, _to: &Self::PublicId, _msg: M) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _from: &Self::PublicId, _ct: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

impl PublicId for PeerId {
    type Signature = ();

    fn verify_signature(&self, _: &Self::Signature, _: &[u8]) -> bool {
        true
    }
}

const NAMES: &[&str] = &[
    "Alice", "Bob", "Carol", "Dave", "Eric", "Fred", "Gina", "Hank",
];

impl Debug for PeerId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if let Some(name) = NAMES.get(self.0) {
            write!(f, "{}", name)
        } else {
            write!(f, "Peer{}", self.0)
        }
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, Debug)]
struct Payload(usize);

impl NetworkEvent for Payload {}

struct Peer {
    parsec: Parsec<Payload, PeerId>,
    blocks: Vec<Observation<Payload, PeerId>>,
}

impl Peer {
    fn poll(&mut self) {
        while let Some(block) = self.parsec.poll() {
            self.blocks.push(block.payload().clone());
        }
    }
}

impl From<Parsec<Payload, PeerId>> for Peer {
    fn from(parsec: Parsec<Payload, PeerId>) -> Self {
        Peer {
            parsec,
            blocks: vec![],
        }
    }
}

impl Deref for Peer {
    type Target = Parsec<Payload, PeerId>;
    fn deref(&self) -> &Self::Target {
        &self.parsec
    }
}

impl DerefMut for Peer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.parsec
    }
}

fn create_nodes(
    count: usize,
    consensus_mode: ConsensusMode,
) -> impl Iterator<Item = Parsec<Payload, PeerId>> {
    let genesis_group: BTreeSet<_> = (0..count).map(PeerId).collect();
    genesis_group
        .clone()
        .into_iter()
        .map(move |peer_id| from_genesis(peer_id, &genesis_group, consensus_mode))
}

fn from_genesis(
    our_id: PeerId,
    genesis_group: &BTreeSet<PeerId>,
    consensus_mode: ConsensusMode,
) -> Parsec<Payload, PeerId> {
    Parsec::from_genesis(
        Default::default(),
        our_id,
        genesis_group,
        vec![],
        consensus_mode,
        Box::new(rand::os::OsRng::new().unwrap()),
    )
}

fn from_existing(
    our_id: PeerId,
    genesis_group: &BTreeSet<PeerId>,
    section: &BTreeSet<PeerId>,
    consensus_mode: ConsensusMode,
) -> Parsec<Payload, PeerId> {
    Parsec::from_existing(
        Default::default(),
        our_id,
        genesis_group,
        section,
        consensus_mode,
        Box::new(rand::os::OsRng::new().unwrap()),
    )
}

fn pick_gossip_recipient<'a, R: Rng>(
    rng: &mut R,
    src: &'a Parsec<Payload, PeerId>,
) -> Option<&'a PeerId> {
    let recipients: Vec<_> = src.gossip_recipients().collect();
    rng.choose(&recipients[..]).cloned()
}

fn is_gossip_recipient(parsec: &Parsec<Payload, PeerId>, peer_id: PeerId) -> bool {
    parsec
        .gossip_recipients()
        .any(|recipient_id| *recipient_id == peer_id)
}

fn check_consensus(peers: &BTreeMap<PeerId, Peer>, expected_votes: usize) -> bool {
    let mut iter = peers.values();
    let first = unwrap!(iter.next());

    for other in iter {
        let len = cmp::min(first.blocks.len(), other.blocks.len());
        assert_eq!(&first.blocks[..len], &other.blocks[..len]);
    }

    peers
        .values()
        .all(|peer| peer.blocks.len() == expected_votes)
}

fn exchange_gossip(src: &mut Parsec<Payload, PeerId>, dst: &mut Parsec<Payload, PeerId>) {
    let request = src.create_gossip(dst.our_pub_id()).unwrap();
    let response = dst.handle_request(src.our_pub_id(), request).unwrap();
    src.handle_response(dst.our_pub_id(), response).unwrap();
}

fn gossip_all(nodes: &mut [Parsec<Payload, PeerId>]) {
    for i in 0..nodes.len() {
        let j = (i + 1) % nodes.len();
        let (src, dst) = get_pair_mut(nodes, i, j);
        exchange_gossip(src, dst);
    }
}
fn get_pair_mut<T>(slice: &mut [T], i: usize, j: usize) -> (&mut T, &mut T) {
    assert!(i != j);

    if i < j {
        let (start, end) = slice.split_at_mut(j);
        (&mut start[i], &mut end[0])
    } else {
        let (start, end) = slice.split_at_mut(i);
        (&mut end[0], &mut start[j])
    }
}

fn vote_for<'a, I>(nodes: I, observation: Observation<Payload, PeerId>)
where
    I: IntoIterator<Item = &'a mut Parsec<Payload, PeerId>>,
{
    for node in nodes {
        unwrap!(node.vote_for(observation.clone()))
    }
}

fn vote_for_remove<'a, I>(nodes: I, peer_to_remove: PeerId)
where
    I: IntoIterator<Item = &'a mut Parsec<Payload, PeerId>>,
{
    vote_for(
        nodes,
        Observation::Remove {
            peer_id: peer_to_remove,
            related_info: vec![],
        },
    )
}

fn assert_no_consensus<'a, I>(nodes: I)
where
    I: IntoIterator<Item = &'a mut Parsec<Payload, PeerId>>,
{
    for node in nodes {
        if let Some(block) = node.poll() {
            panic!(
                "{:?}: Unexpected consensus on {:?}.",
                node.our_pub_id(),
                block.payload()
            )
        }
    }
}

fn assert_consensus_on_remove<'a, I>(nodes: I, removed_peer: PeerId)
where
    I: IntoIterator<Item = &'a mut Parsec<Payload, PeerId>>,
{
    for node in nodes {
        let block = unwrap!(node.poll());
        match block.payload() {
            Observation::Remove { peer_id, .. } if *peer_id == removed_peer => (),
            x => panic!("Unexpected block {:?}", x),
        }
    }
}

enum MessageContent {
    Request(Request<Payload, PeerId>),
    Response(Response<Payload, PeerId>),
}

struct Message {
    src: PeerId,
    dst: PeerId,
    content: MessageContent,
}

struct PollAll<'a>(&'a mut Parsec<Payload, PeerId>);

impl<'a> Iterator for PollAll<'a> {
    type Item = Block<Payload, PeerId>;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.poll()
    }
}

fn poll_all(parsec: &mut Parsec<Payload, PeerId>) -> PollAll {
    PollAll(parsec)
}

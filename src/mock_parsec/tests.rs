// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    init, Block, ConsensusMode, NetworkEvent, Observation, Parsec, PublicId, Request, Response,
    SecretId,
};
use maidsafe_utilities::SeededRng;
use rand::Rng;
use std::{
    cmp,
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug, Formatter},
    ops::{Deref, DerefMut},
};

#[test]
fn smoke() {
    init();

    let alice_id = PeerId(0);
    let bob_id = PeerId(1);

    let mut genesis_group = BTreeSet::new();
    let _ = genesis_group.insert(alice_id.clone());
    let _ = genesis_group.insert(bob_id.clone());

    let mut alice = Parsec::from_genesis(
        Default::default(),
        alice_id.clone(),
        &genesis_group,
        ConsensusMode::Supermajority,
    );

    let mut bob = Parsec::from_genesis(
        Default::default(),
        bob_id.clone(),
        &genesis_group,
        ConsensusMode::Supermajority,
    );

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
    init();

    let alice_id = PeerId(0);
    let bob_id = PeerId(1);
    let carol_id = PeerId(2);

    let mut genesis_group = BTreeSet::new();
    let _ = genesis_group.insert(bob_id.clone());
    let _ = genesis_group.insert(carol_id.clone());

    let mut bob = Parsec::from_genesis(
        Default::default(),
        bob_id.clone(),
        &genesis_group,
        ConsensusMode::Supermajority,
    );
    let mut carol = Parsec::from_genesis(
        Default::default(),
        carol_id.clone(),
        &genesis_group,
        ConsensusMode::Supermajority,
    );

    let mut alice = Parsec::from_existing(
        Default::default(),
        alice_id.clone(),
        &genesis_group,
        &genesis_group,
        ConsensusMode::Supermajority,
    );

    let mut alice_blocks = vec![];
    let mut bob_blocks = vec![];
    let mut carol_blocks = vec![];

    assert!(!is_gossip_recipient(&bob, &alice_id));
    assert!(!is_gossip_recipient(&carol, &alice_id));

    let add_alice = Observation::Add {
        peer_id: alice_id.clone(),
        related_info: vec![],
    };

    let payload0 = Observation::OpaquePayload(Payload(0));

    bob.vote_for(add_alice.clone()).unwrap();
    carol.vote_for(add_alice.clone()).unwrap();

    exchange_gossip(&mut bob, &mut carol);

    bob_blocks.extend(poll_all(&mut bob));
    carol_blocks.extend(poll_all(&mut carol));

    assert!(is_gossip_recipient(&bob, &alice_id));
    assert!(is_gossip_recipient(&carol, &alice_id));

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
    init();

    let alice_id = PeerId(0);
    let bob_id = PeerId(1);

    let mut genesis_group = BTreeSet::new();
    let _ = genesis_group.insert(alice_id.clone());
    let _ = genesis_group.insert(bob_id.clone());

    let mut alice = Parsec::from_genesis(
        Default::default(),
        alice_id.clone(),
        &genesis_group,
        ConsensusMode::Single,
    );
    let mut bob = Parsec::from_genesis(
        Default::default(),
        bob_id.clone(),
        &genesis_group,
        ConsensusMode::Single,
    );

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
fn randomized_static_network() {
    init();

    let num_peers = 10;
    let num_votes = 10;
    let gossip_prob = 0.1;
    let max_steps = 1000;

    let mut rng = SeededRng::new();

    let peer_ids: BTreeSet<_> = (0..num_peers).map(PeerId).collect();

    let mut peers: BTreeMap<_, _> = peer_ids
        .iter()
        .map(|peer_id| {
            let peer = Peer::from(Parsec::from_genesis(
                Default::default(),
                peer_id.clone(),
                &peer_ids,
                ConsensusMode::Supermajority,
            ));

            (peer_id.clone(), peer)
        })
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
                    dst.clone()
                } else {
                    continue;
                };

                let request = peer.create_gossip(&dst).unwrap();

                messages.push(Message {
                    src: peer_id.clone(),
                    dst: dst.clone(),
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

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
struct PeerId(usize);

impl SecretId for PeerId {
    type PublicId = PeerId;

    fn public_id(&self) -> &Self::PublicId {
        self
    }

    fn sign_detached(&self, _: &[u8]) -> <Self::PublicId as PublicId>::Signature {}
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
        while let Some(blocks) = self.parsec.poll() {
            self.blocks
                .extend(blocks.into_iter().map(|block| block.payload().clone()));
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

fn pick_gossip_recipient<'a, R: Rng>(
    rng: &mut R,
    src: &'a Parsec<Payload, PeerId>,
) -> Option<&'a PeerId> {
    let recipients: Vec<_> = src.gossip_recipients().collect();
    rng.choose(&recipients[..]).cloned()
}

fn is_gossip_recipient(parsec: &Parsec<Payload, PeerId>, peer_id: &PeerId) -> bool {
    parsec
        .gossip_recipients()
        .any(|recipient_id| recipient_id == peer_id)
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

enum MessageContent {
    Request(Request<Payload, PeerId>),
    Response(Response<Payload, PeerId>),
}

struct Message {
    src: PeerId,
    dst: PeerId,
    content: MessageContent,
}

struct PollAll<'a> {
    parsec: &'a mut Parsec<Payload, PeerId>,
    blocks: Vec<Block<Payload, PeerId>>,
}

impl<'a> Iterator for PollAll<'a> {
    type Item = Block<Payload, PeerId>;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(block) = self.blocks.pop() {
            Some(block)
        } else {
            self.blocks.extend(self.parsec.poll().into_iter().flatten());
            self.blocks.reverse();
            self.blocks.pop()
        }
    }
}

fn poll_all(parsec: &mut Parsec<Payload, PeerId>) -> PollAll {
    PollAll {
        parsec,
        blocks: Vec::new(),
    }
}

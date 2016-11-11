// copyright 2016 maidsafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

extern crate itertools;
#[macro_use]
extern crate log;
extern crate rand;
extern crate routing;
#[macro_use]
extern crate unwrap;

// use itertools::Itertools;
// use rand::Rng;
// use routing::{Authority, Cache, NullCache, Client};
// use routing::{Data, DataIdentifier, ImmutableData};
// use routing::{Event, FullId};
// use routing::{Request, Response};
// use routing::mock_crust::{self, Config, Endpoint, Network, ServiceHandle};
// use routing::mock_crust::crust::PeerId;
// use routing::Node;
// use routing::MIN_GROUP_SIZE;
// use routing::{Prefix, Xorable};
// use routing::{Destination, RoutingTable, verify_network_invariant};
// use routing::MessageId;
// use routing::XorName;
// use routing::mock_crust::utils::*;
// use std::cell::RefCell;
// use std::cmp;
// use std::collections::{HashMap, HashSet};
// use std::sync::mpsc;
// 
// /// Expect that the next event raised by the node matches the given pattern.
// /// Panics if no event, or an event that does not match the pattern is raised.
// /// (ignores ticks).
// macro_rules! expect_next_event {
//     ($node:expr, $pattern:pat) => {
//         loop {
//             match $node.event_rx.try_recv() {
//                 Ok($pattern) => break,
//                 Ok(Event::Tick) => (),
//                 other => panic!("Expected Ok({}) at {}, got {:?}",
//                     stringify!($pattern),
//                     unwrap!($node.inner.name()),
//                     other),
//             }
//         }
//     }
// }
// 
// /// Expects that the node raised no event, panics otherwise (ignores ticks).
// macro_rules! expect_no_event {
//     ($node:expr) => {
//         match $node.event_rx.try_recv() {
//             Ok(Event::Tick) => (),
//             Err(mpsc::TryRecvError::Empty) => (),
//             other => panic!("Expected no event at {}, got {:?}",
//                 unwrap!($node.inner.name()),
//                 other),
//         }
//     }
// }

// #[test]
// #[ignore]
// fn messages_accumulate_with_quorum() {
//     let network = Network::new(None);
//     let mut rng = network.new_rng();
//     let mut nodes = create_connected_nodes(&network, 15);
//
//     let data = gen_immutable_data(&mut rng, 8);
//     let src = Authority::NaeManager(*data.name()); // The data's NaeManager.
//     sort_nodes_by_distance_to(&mut nodes, src.name());
//
//     let send = |node: &mut TestNode, dst: &Authority, message_id: MessageId| {
//         assert!(node.inner
//             .send_get_success(src, *dst, data.clone(), message_id)
//             .is_ok());
//     };
//
//     let dst = Authority::ManagedNode(nodes[0].name()); // The closest node.
//
//     // Send a message from the group `src` to the node `dst`.
//     // Only the `QUORUM_SIZE`-th sender should cause accumulation and a
//     // `Response` event. The event should only occur once.
//     let message_id = MessageId::new();
//     for node in nodes.iter_mut().take(QUORUM_SIZE - 1) {
//         send(node, &dst, message_id);
//     }
//     let _ = poll_all(&mut nodes, &mut []);
//     expect_no_event!(nodes[0]);
//     send(&mut nodes[QUORUM_SIZE - 1], &dst, message_id);
//     let _ = poll_all(&mut nodes, &mut []);
//     expect_next_event!(nodes[0], Event::Response { response: Response::GetSuccess(..), .. });
//     send(&mut nodes[QUORUM_SIZE], &dst, message_id);
//     let _ = poll_all(&mut nodes, &mut []);
//     expect_no_event!(nodes[0]);
//
//     // If there are `QUORUM_SIZE` senders but they all only sent hashes, nothing can accumulate.
//     // Only after `nodes[0]`, which is closest to `src.name()`, has sent the full message, it
//     // accumulates.
//     let message_id = MessageId::new();
//     for node in nodes.iter_mut().skip(1).take(QUORUM_SIZE) {
//         send(node, &dst, message_id);
//     }
//     let _ = poll_all(&mut nodes, &mut []);
//     expect_no_event!(nodes[0]);
//     send(&mut nodes[0], &dst, message_id);
//     let _ = poll_all(&mut nodes, &mut []);
//     expect_next_event!(nodes[0], Event::Response { response: Response::GetSuccess(..), .. });
//     send(&mut nodes[QUORUM_SIZE + 1], &dst, message_id);
//     let _ = poll_all(&mut nodes, &mut []);
//     expect_no_event!(nodes[0]);
//
//     let dst_grp = Authority::NaeManager(*src.name()); // The whole group.
//
//     // Send a message from the group `src` to the group `dst_grp`.
//     // Only the `QUORUM_SIZE`-th sender should cause accumulation and a
//     // `Response` event. The event should only occur once.
//     let message_id = MessageId::new();
//     for node in nodes.iter_mut().take(QUORUM_SIZE - 1) {
//         send(node, &dst_grp, message_id);
//     }
//     let _ = poll_all(&mut nodes, &mut []);
//     for node in &mut nodes {
//         expect_no_event!(node);
//     }
//     send(&mut nodes[QUORUM_SIZE - 1], &dst_grp, message_id);
//     let _ = poll_all(&mut nodes, &mut []);
//     for node in &mut nodes {
//         expect_next_event!(node, Event::Response { response: Response::GetSuccess(..), .. });
//     }
//     send(&mut nodes[QUORUM_SIZE], &dst_grp, message_id);
//     let _ = poll_all(&mut nodes, &mut []);
//     for node in &mut nodes {
//         expect_no_event!(node);
//     }
//
//     // If there are `QUORUM_SIZE` senders but they all only sent hashes, nothing can accumulate.
//     // Only after `nodes[0]`, which is closest to `src.name()`, has sent the full message, it
//     // accumulates.
//     let message_id = MessageId::new();
//     for node in nodes.iter_mut().skip(1).take(QUORUM_SIZE) {
//         send(node, &dst_grp, message_id);
//     }
//     let _ = poll_all(&mut nodes, &mut []);
//     for node in &mut nodes {
//         expect_no_event!(node);
//     }
//     send(&mut nodes[0], &dst_grp, message_id);
//     let _ = poll_all(&mut nodes, &mut []);
//     for node in &mut nodes {
//         expect_next_event!(node, Event::Response { response: Response::GetSuccess(..), .. });
//     }
//     send(&mut nodes[QUORUM_SIZE + 1], &dst_grp, message_id);
//     let _ = poll_all(&mut nodes, &mut []);
//     for node in &mut nodes {
//         expect_no_event!(node);
//     }
// }

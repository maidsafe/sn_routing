// Copyright 2016 MaidSafe.net limited.
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

use id::PublicId;
use itertools::Itertools;
use maidsafe_utilities::serialisation;
use messages::SignedMessage;
use rust_sodium::crypto::hash::sha256;
use rust_sodium::crypto::sign;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::time::Instant;

/// Time (in seconds) within which a message and a quorum of signatures need to arrive to
/// accumulate.
const ACCUMULATION_TIMEOUT_SECS: u64 = 30;

#[derive(Default)]
pub struct SignatureAccumulator {
    sigs: HashMap<sha256::Digest, (Vec<(PublicId, sign::Signature)>, Instant)>,
    msgs: HashMap<sha256::Digest, (SignedMessage, u8, Instant)>,
}

impl SignatureAccumulator {
    /// Adds the given signature to the list of pending signatures or to the appropriate
    /// `SignedMessage`. Returns the message, if it has enough signatures now.
    pub fn add_signature(&mut self,
                         hash: sha256::Digest,
                         sig: sign::Signature,
                         pub_id: PublicId)
                         -> Option<(SignedMessage, u8)> {
        self.remove_expired();
        if let Some(&mut (ref mut msg, _, _)) = self.msgs.get_mut(&hash) {
            msg.add_signature(pub_id, sig);
        } else {
            let mut sigs_vec = self.sigs
                .entry(hash)
                .or_insert_with(|| (vec![], Instant::now()));
            sigs_vec.0.push((pub_id, sig));
            return None;
        }
        self.remove_if_complete(&hash)
    }

    /// Adds the given message to the list of pending messages. Returns it if it has enough
    /// signatures.
    pub fn add_message(&mut self,
                       mut msg: SignedMessage,
                       route: u8)
                       -> Option<(SignedMessage, u8)> {
        if msg.is_fully_signed() {
            return Some((msg, route));
        }
        self.remove_expired();
        let hash = match serialisation::serialise(msg.routing_message()) {
            Ok(serialised_msg) => sha256::hash(&serialised_msg),
            Err(err) => {
                error!("Failed to serialise {:?}: {:?}.", msg, err);
                return None;
            }
        };
        match self.msgs.entry(hash) {
            Entry::Occupied(mut entry) => {
                // TODO - should update `route` of `entry`?
                trace!("Received two full SignedMessages {:?}.", msg);
                entry.get_mut().0.add_signatures(msg);
            }
            Entry::Vacant(entry) => {
                for (pub_id, sig) in self.sigs
                        .remove(&hash)
                        .into_iter()
                        .flat_map(|(vec, _)| vec) {
                    msg.add_signature(pub_id, sig);
                }
                let _ = entry.insert((msg, route, Instant::now()));
            }
        }
        self.remove_if_complete(&hash)
    }

    fn remove_expired(&mut self) {
        let expired_sigs = self.sigs
            .iter()
            .filter(|&(_, &(_, ref time))| time.elapsed().as_secs() > ACCUMULATION_TIMEOUT_SECS)
            .map(|(hash, _)| *hash)
            .collect_vec();
        for hash in expired_sigs {
            let _ = self.sigs.remove(&hash);
        }
        let expired_msgs = self.msgs
            .iter()
            .filter(|&(_, &(_, _, ref time))| time.elapsed().as_secs() > ACCUMULATION_TIMEOUT_SECS)
            .map(|(hash, _)| *hash)
            .collect_vec();
        for hash in expired_msgs {
            let _ = self.msgs.remove(&hash);
        }
    }

    fn remove_if_complete(&mut self, hash: &sha256::Digest) -> Option<(SignedMessage, u8)> {
        match self.msgs.get_mut(hash) {
            None => return None,
            Some(&mut (ref mut msg, _, _)) => {
                if !msg.is_fully_signed() {
                    return None;
                }
                msg.remove_invalid_signatures();
                if !msg.is_fully_signed() {
                    return None;
                }
            }
        }
        self.msgs
            .remove(hash)
            .map(|(msg, route, _)| (msg, route))
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use authority::Authority;
    use id::FullId;
    use itertools::Itertools;
    use messages::{DirectMessage, GroupList, MessageContent, RoutingMessage, SignedMessage};
    use rand;
    use routing_table::Prefix;
    use std::collections::BTreeSet;

    struct MessageAndSignatures {
        signed_msg: SignedMessage,
        signature_msgs: Vec<DirectMessage>,
    }

    impl MessageAndSignatures {
        fn new<'a, I>(msg_sender_id: &FullId, other_ids: I) -> MessageAndSignatures
            where I: Iterator<Item = &'a FullId>
        {
            let routing_msg = RoutingMessage {
                src: Authority::ClientManager(rand::random()),
                dst: Authority::ClientManager(rand::random()),
                content: MessageContent::GroupSplit(Prefix::new(rand::random::<u8>() as usize,
                                                                rand::random())),
            };
            let signed_msg = unwrap!(SignedMessage::new(routing_msg, msg_sender_id));
            let signature_msgs = other_ids.map(|id| {
                    unwrap!(signed_msg.routing_message().to_signature(id.signing_private_key()))
                })
                .collect();
            MessageAndSignatures {
                signed_msg: signed_msg,
                signature_msgs: signature_msgs,
            }
        }
    }

    struct Env {
        _msg_sender_id: FullId,
        other_ids: Vec<FullId>,
        group_list: GroupList,
        msgs_and_sigs: Vec<MessageAndSignatures>,
    }

    impl Env {
        fn new() -> Env {
            let msg_sender_id = FullId::new();
            let mut pub_ids = vec![*msg_sender_id.public_id()]
                .into_iter()
                .collect::<BTreeSet<_>>();
            let mut other_ids = vec![];
            for _ in 0..8 {
                let full_id = FullId::new();
                let _ = pub_ids.insert(*full_id.public_id());
                other_ids.push(full_id);
            }
            let msgs_and_sigs = (0..5)
                .map(|_| MessageAndSignatures::new(&msg_sender_id, other_ids.iter()))
                .collect();
            Env {
                _msg_sender_id: msg_sender_id,
                other_ids: other_ids,
                group_list: GroupList { pub_ids: pub_ids },
                msgs_and_sigs: msgs_and_sigs,
            }
        }
    }

    #[test]
    fn group_src_add_message_last() {
        let mut sig_accumulator = SignatureAccumulator::default();
        let env = Env::new();

        // Add all signatures for all messages - none should accumulate.
        env.msgs_and_sigs
            .iter()
            .foreach(|msg_and_sigs| {
                msg_and_sigs
                    .signature_msgs
                    .iter()
                    .zip(env.other_ids.iter())
                    .foreach(|(signature_msg, full_id)| match *signature_msg {
                                 DirectMessage::MessageSignature(ref hash, ref sig) => {
                        assert!(sig_accumulator.add_signature(*hash, *sig, *full_id.public_id())
                            .is_none());
                    }
                                 ref unexpected_msg => {
                                     panic!("Unexpected message: {:?}", unexpected_msg)
                                 }
                             });
            });

        assert!(sig_accumulator.msgs.is_empty());
        assert_eq!(sig_accumulator.sigs.len(), env.msgs_and_sigs.len());
        sig_accumulator
            .sigs
            .values()
            .foreach(|&(ref pub_ids_and_sigs, _)| {
                         assert_eq!(pub_ids_and_sigs.len(), env.other_ids.len())
                     });

        // Add each message with the group list added - each should accumulate.
        let mut expected_sigs_count = env.msgs_and_sigs.len();
        assert_eq!(sig_accumulator.sigs.len(), expected_sigs_count);
        assert!(sig_accumulator.msgs.is_empty());
        env.msgs_and_sigs
            .iter()
            .foreach(|msg_and_sigs| {
                expected_sigs_count -= 1;
                let mut signed_msg = msg_and_sigs.signed_msg.clone();
                signed_msg.add_group_list(env.group_list.clone());
                let route = rand::random();
                let (returned_msg, returned_route) =
                    unwrap!(sig_accumulator.add_message(signed_msg.clone(), route));
                assert_eq!(sig_accumulator.sigs.len(), expected_sigs_count);
                assert!(sig_accumulator.msgs.is_empty());
                assert_eq!(route, returned_route);
                assert_eq!(signed_msg.routing_message(), returned_msg.routing_message());
                unwrap!(returned_msg.check_integrity());
                assert!(returned_msg.is_fully_signed());
                env.group_list
                    .pub_ids
                    .iter()
                    .foreach(|pub_id| assert!(returned_msg.signed_by(pub_id)));
            });
    }

    #[test]
    fn group_src_add_signature_last() {
        let mut sig_accumulator = SignatureAccumulator::default();
        let env = Env::new();

        // Add each message with the group list added - none should accumulate.
        env.msgs_and_sigs.iter().enumerate().foreach(|(route, msg_and_sigs)| {
            let mut signed_msg = msg_and_sigs.signed_msg.clone();
            signed_msg.add_group_list(env.group_list.clone());
            assert!(sig_accumulator.add_message(signed_msg.clone(), route as u8).is_none());
        });
        let mut expected_msgs_count = env.msgs_and_sigs.len();
        assert_eq!(sig_accumulator.msgs.len(), expected_msgs_count);
        assert!(sig_accumulator.sigs.is_empty());

        // Add each message's signatures - each should accumulate once quorum has been reached.
        env.msgs_and_sigs
            .iter()
            .enumerate()
            .foreach(|(route, msg_and_sigs)| {
                msg_and_sigs
                    .signature_msgs
                    .iter()
                    .zip(env.other_ids.iter())
                    .foreach(|(signature_msg, full_id)| {
                        let result = match *signature_msg {
                            DirectMessage::MessageSignature(hash, sig) => {
                                sig_accumulator.add_signature(hash, sig, *full_id.public_id())
                            }
                            ref unexpected_msg => {
                                panic!("Unexpected message: {:?}", unexpected_msg)
                            }
                        };

                        if let Some((returned_msg, returned_route)) = result {
                            expected_msgs_count -= 1;
                            assert_eq!(sig_accumulator.msgs.len(), expected_msgs_count);
                            assert_eq!(route as u8, returned_route);
                            assert_eq!(msg_and_sigs.signed_msg.routing_message(),
                                   returned_msg.routing_message());
                            unwrap!(returned_msg.check_integrity());
                            assert!(returned_msg.is_fully_signed());
                        }
                    });
            });
    }
}

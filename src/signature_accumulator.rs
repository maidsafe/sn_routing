// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    crypto::Digest256,
    messages::{AccumulatingMessage, Message, MessageWithBytes},
    time::{Duration, Instant},
    utils::LogIdent,
};
use itertools::Itertools;
use std::collections::HashMap;

/// Time (in seconds) within which a message and a quorum of signatures need to arrive to
/// accumulate.
pub const ACCUMULATION_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Default)]
pub struct SignatureAccumulator {
    msgs: HashMap<Digest256, (Option<AccumulatingMessage>, Instant)>,
}

impl SignatureAccumulator {
    /// Adds the given signature to the list of pending signatures or to the appropriate
    /// `Message`. Returns the message, if it has enough signatures now.
    pub fn add_proof(
        &mut self,
        msg: AccumulatingMessage,
        log_ident: &LogIdent,
    ) -> Option<MessageWithBytes> {
        self.remove_expired();
        let hash = msg.crypto_hash().ok()?;
        if let Some((existing_msg, _)) = self.msgs.get_mut(&hash) {
            if let Some(existing_msg) = existing_msg {
                existing_msg.add_signature_shares(msg);
            }
        } else {
            let _ = self.msgs.insert(hash, (Some(msg), Instant::now()));
        }

        let msg = self.remove_if_complete(&hash)?;
        match MessageWithBytes::new(msg, log_ident) {
            Ok(msg) => Some(msg),
            Err(error) => {
                error!("{} - Failed to make message: {:?}", log_ident, error);
                None
            }
        }
    }

    fn remove_expired(&mut self) {
        let expired_msgs = self
            .msgs
            .iter()
            .filter(|&(_, &(_, ref time))| time.elapsed() > ACCUMULATION_TIMEOUT)
            .map(|(hash, _)| *hash)
            .collect_vec();
        for hash in expired_msgs {
            if let Some((Some(existing_msg), clock)) = self.msgs.remove(&hash) {
                error!(
                    "Remove unaccumulated expired message clock {:?}, msg {:?}",
                    clock, existing_msg,
                );
            }
        }
    }

    fn remove_if_complete(&mut self, hash: &Digest256) -> Option<Message> {
        self.msgs.get_mut(hash).and_then(|(msg, _)| {
            if msg.as_mut().map_or(false, |msg| msg.check_fully_signed()) {
                msg.take().and_then(|msg| msg.combine_signatures())
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
#[cfg(feature = "mock_base")]
mod tests {
    use super::*;
    use crate::{
        chain::{EldersInfo, SectionKeyInfo, SectionKeyShare, SectionProofSlice},
        id::{FullId, P2pNode},
        location::{DstLocation, SrcLocation},
        messages::{Message, PlainMessage, Variant},
        parsec::generate_bls_threshold_secret_key,
        rng, unwrap, ConnectionInfo, Prefix, XorName,
    };
    use itertools::Itertools;
    use rand;
    use std::{collections::BTreeMap, net::SocketAddr};

    struct MessageAndSignatures {
        signed_msg: AccumulatingMessage,
        signature_msgs: Vec<Message>,
    }

    impl MessageAndSignatures {
        fn new(
            secret_ids: &BTreeMap<XorName, FullId>,
            all_nodes: &BTreeMap<XorName, P2pNode>,
            secret_bls_ids: &BTreeMap<XorName, SectionKeyShare>,
            pk_set: &bls::PublicKeySet,
        ) -> Self {
            let content = PlainMessage {
                src: Prefix::default(),
                dst: DstLocation::Section(rand::random()),
                variant: Variant::UserMessage(vec![rand::random(), rand::random(), rand::random()]),
            };

            let msg_sender_secret_bls = unwrap!(secret_bls_ids.values().next());
            let other_ids = secret_ids.values().zip(secret_bls_ids.values()).skip(1);

            let prefix = Prefix::new(0, *unwrap!(all_nodes.keys().next()));
            let elders_info = unwrap!(EldersInfo::new(all_nodes.clone(), prefix, None));
            let key_info = SectionKeyInfo::from_elders_info(&elders_info, pk_set.public_key());
            let proof = SectionProofSlice::from_genesis(key_info);

            let signed_msg = unwrap!(AccumulatingMessage::new(
                content.clone(),
                msg_sender_secret_bls,
                pk_set.clone(),
                proof.clone(),
            ));

            let signature_msgs = other_ids
                .map(|(id, bls_id)| {
                    unwrap!(Message::single_src(
                        id,
                        DstLocation::Direct,
                        Variant::MessageSignature(Box::new(unwrap!(AccumulatingMessage::new(
                            content.clone(),
                            bls_id,
                            pk_set.clone(),
                            proof.clone(),
                        ))))
                    ))
                })
                .collect();

            Self {
                signed_msg,
                signature_msgs,
            }
        }
    }

    struct Env {
        msgs_and_sigs: Vec<MessageAndSignatures>,
    }

    impl Env {
        fn new() -> Self {
            let mut rng = rng::new();

            let socket_addr: SocketAddr = ([127, 0, 0, 1], 9999).into();
            let connection_info = ConnectionInfo::from(socket_addr);

            let keys = generate_bls_threshold_secret_key(&mut rng, 9);
            let full_ids: BTreeMap<_, _> = (0..9)
                .map(|_| {
                    let full_id = FullId::gen(&mut rng);
                    (*full_id.public_id().name(), full_id)
                })
                .collect();

            let pub_ids: BTreeMap<_, _> = full_ids
                .iter()
                .map(|(name, full_id)| {
                    (
                        *name,
                        P2pNode::new(*full_id.public_id(), connection_info.clone()),
                    )
                })
                .collect();

            let secret_ids: BTreeMap<_, _> = pub_ids
                .keys()
                .enumerate()
                .map(|(idx, name)| {
                    let share = SectionKeyShare::new_with_position(idx, keys.secret_key_share(idx));
                    (*name, share)
                })
                .collect();

            let pk_set = keys.public_keys();

            let msgs_and_sigs = (0..5)
                .map(|_| MessageAndSignatures::new(&full_ids, &pub_ids, &secret_ids, &pk_set))
                .collect();
            Self { msgs_and_sigs }
        }
    }

    #[test]
    fn section_src_add_signature_last() {
        use fake_clock::FakeClock;

        let mut sig_accumulator = SignatureAccumulator::default();
        let env = Env::new();
        let log_ident = LogIdent::new("Node");

        // Add each message with the section list added - none should accumulate.
        env.msgs_and_sigs.iter().foreach(|msg_and_sigs| {
            let signed_msg = msg_and_sigs.signed_msg.clone();
            let result = sig_accumulator.add_proof(signed_msg, &log_ident);
            assert!(result.is_none());
        });
        let expected_msgs_count = env.msgs_and_sigs.len();
        assert_eq!(sig_accumulator.msgs.len(), expected_msgs_count);

        // Add each message's signatures - each should accumulate once quorum has been reached.
        let mut count = 0;
        for msg_and_sigs in env.msgs_and_sigs {
            for signature_msg in msg_and_sigs.signature_msgs {
                let old_num_msgs = sig_accumulator.msgs.len();

                let result = match signature_msg.variant {
                    Variant::MessageSignature(msg) => sig_accumulator.add_proof(*msg, &log_ident),
                    unexpected_msg => panic!("Unexpected message: {:?}", unexpected_msg),
                };

                if let Some(mut returned_msg) = result {
                    let returned_msg = unwrap!(returned_msg.take_or_deserialize_message());

                    // the message hash is not being removed upon accumulation, only when it
                    // expires
                    assert_eq!(sig_accumulator.msgs.len(), old_num_msgs);
                    assert_eq!(
                        SrcLocation::Section(msg_and_sigs.signed_msg.content.src),
                        returned_msg.src.location()
                    );
                    assert_eq!(msg_and_sigs.signed_msg.content.dst, returned_msg.dst);
                    assert_eq!(
                        msg_and_sigs.signed_msg.content.variant,
                        returned_msg.variant
                    );
                    count += 1;
                }
            }
        }

        assert_eq!(count, expected_msgs_count);

        FakeClock::advance_time(ACCUMULATION_TIMEOUT.as_secs() * 1000 + 1000);

        sig_accumulator.remove_expired();
        assert!(sig_accumulator.msgs.is_empty());
    }
}

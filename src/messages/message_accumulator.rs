// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    messages::{AccumulatingMessage, Message, MessageHash},
    time::{Duration, Instant},
};
use std::collections::HashMap;

/// Time (in seconds) within which a message and a quorum of signatures need to arrive to
/// accumulate.
pub const ACCUMULATION_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Default)]
pub struct MessageAccumulator {
    msgs: HashMap<MessageHash, (Option<AccumulatingMessage>, Instant)>,
}

impl MessageAccumulator {
    /// Adds the given signature to the list of pending signatures or to the appropriate
    /// `Message`. Returns the message, if it has enough signatures now.
    pub fn add_proof(&mut self, msg: AccumulatingMessage) -> Option<Message> {
        self.remove_expired();
        let hash = msg.crypto_hash().ok()?;
        if let Some((existing_msg, _)) = self.msgs.get_mut(&hash) {
            if let Some(existing_msg) = existing_msg {
                existing_msg.add_signature_shares(msg);
            }
        } else {
            let _ = self.msgs.insert(hash, (Some(msg), Instant::now()));
        }

        self.remove_if_complete(&hash)
    }

    fn remove_expired(&mut self) {
        self.msgs.retain(|_, (msg, timestamp)| {
            if timestamp.elapsed() <= ACCUMULATION_TIMEOUT {
                true
            } else {
                if let Some(msg) = msg {
                    error!("Expired unaccumulated message: {:?}", msg);
                }
                false
            }
        });
    }

    fn remove_if_complete(&mut self, hash: &MessageHash) -> Option<Message> {
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
        consensus::{self, generate_secret_key_set},
        id::{FullId, P2pNode},
        location::{DstLocation, SrcLocation},
        messages::{Message, PlainMessage, Variant},
        rng::{self, MainRng},
        section::SectionProofChain,
        Prefix, XorName,
    };
    use rand::{distributions::Standard, Rng};
    use std::{collections::BTreeMap, net::SocketAddr};

    struct MessageAndSignatures {
        signed_msg: AccumulatingMessage,
        signature_msgs: Vec<Message>,
    }

    impl MessageAndSignatures {
        fn new(
            rng: &mut MainRng,
            secret_ids: &BTreeMap<XorName, FullId>,
            secret_key_shares: &BTreeMap<XorName, bls::SecretKeyShare>,
            pk_set: &bls::PublicKeySet,
        ) -> Self {
            let content = PlainMessage {
                src: Prefix::default(),
                dst: DstLocation::Section(rng.gen()),
                dst_key: consensus::test_utils::gen_secret_key(rng).public_key(),
                variant: Variant::UserMessage(rng.sample_iter(Standard).take(3).collect()),
            };

            let msg_sender_secret_key_share = secret_key_shares
                .values()
                .next()
                .expect("secret_key_shares can't be empty");

            let proof = SectionProofChain::new(pk_set.public_key());

            let signed_msg = AccumulatingMessage::new(
                content.clone(),
                pk_set.clone(),
                0,
                msg_sender_secret_key_share,
                proof.clone(),
            )
            .unwrap();

            let signature_msgs = secret_ids
                .values()
                .zip(secret_key_shares.values())
                .enumerate()
                .skip(1)
                .map(|(index, (id, sk_share))| {
                    Message::single_src(
                        id,
                        DstLocation::Direct,
                        None,
                        Variant::MessageSignature(Box::new(
                            AccumulatingMessage::new(
                                content.clone(),
                                pk_set.clone(),
                                index,
                                sk_share,
                                proof.clone(),
                            )
                            .unwrap(),
                        )),
                    )
                    .unwrap()
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

            let sk_set = generate_secret_key_set(&mut rng, 9);
            let full_ids: BTreeMap<_, _> = (0..9)
                .map(|_| {
                    let full_id = FullId::gen(&mut rng);
                    (*full_id.public_id().name(), full_id)
                })
                .collect();

            let pub_ids: BTreeMap<_, _> = full_ids
                .iter()
                .map(|(name, full_id)| (*name, P2pNode::new(*full_id.public_id(), socket_addr)))
                .collect();

            let sk_shares: BTreeMap<_, _> = pub_ids
                .keys()
                .enumerate()
                .map(|(idx, name)| (*name, sk_set.secret_key_share(idx)))
                .collect();

            let pk_set = sk_set.public_keys();

            let msgs_and_sigs = (0..5)
                .map(|_| MessageAndSignatures::new(&mut rng, &full_ids, &sk_shares, &pk_set))
                .collect();
            Self { msgs_and_sigs }
        }
    }

    #[test]
    fn section_src_add_signature_last() {
        use fake_clock::FakeClock;

        let mut sig_accumulator = MessageAccumulator::default();
        let env = Env::new();

        // Add each message with the section list added - none should accumulate.
        env.msgs_and_sigs.iter().for_each(|msg_and_sigs| {
            let signed_msg = msg_and_sigs.signed_msg.clone();
            let result = sig_accumulator.add_proof(signed_msg);
            assert!(result.is_none());
        });
        let expected_msgs_count = env.msgs_and_sigs.len();
        assert_eq!(sig_accumulator.msgs.len(), expected_msgs_count);

        // Add each message's signatures - each should accumulate once quorum has been reached.
        let mut count = 0;
        for msg_and_sigs in env.msgs_and_sigs {
            for signature_msg in msg_and_sigs.signature_msgs {
                let old_num_msgs = sig_accumulator.msgs.len();

                let result = match signature_msg.variant() {
                    Variant::MessageSignature(msg) => sig_accumulator.add_proof(*msg.clone()),
                    unexpected_msg => panic!("Unexpected message: {:?}", unexpected_msg),
                };

                if let Some(returned_msg) = result {
                    // the message hash is not being removed upon accumulation, only when it
                    // expires
                    assert_eq!(sig_accumulator.msgs.len(), old_num_msgs);
                    assert_eq!(
                        SrcLocation::Section(msg_and_sigs.signed_msg.content.src),
                        returned_msg.src().src_location()
                    );
                    assert_eq!(msg_and_sigs.signed_msg.content.dst, *returned_msg.dst());
                    assert_eq!(
                        msg_and_sigs.signed_msg.content.variant,
                        *returned_msg.variant()
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

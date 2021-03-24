// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    consensus::Vote,
    error::Result,
    messages::{Message, MessageHash, Variant},
    network::Network,
    node::Node,
    section::Section,
};
use sn_messaging::DstLocation;
use std::cmp::Ordering;
use xor_name::XorName;

/// On reception of an incoming message, determine the actions that need to be taken in order to
/// bring ours and the senders knowledge about each other up to date.
pub(crate) fn process(
    node: &Node,
    section: &Section,
    network: &Network,
    msg: &Message,
) -> Result<Actions> {
    let src_name = msg.src().name();
    let src_prefix = if section.prefix().matches(&src_name) {
        Some(section.prefix())
    } else {
        network
            .section_by_name(&src_name)
            .1
            .map(|info| &info.prefix)
    };
    let src_key = msg.proof_chain_last_key();

    let mut actions = Actions::default();
    let mut send_other_section = false;

    if let Some(src_prefix) = src_prefix {
        if !src_prefix.matches(&node.name())
            && !src_key
                .map(|src_key| network.has_key(src_key))
                .unwrap_or(false)
        {
            send_other_section = true;
        }
    }

    if let Some(new) = msg.dst_key() {
        if let Some(src_prefix) = src_prefix {
            let old = network
                .knowledge_by_name(&src_name)
                .unwrap_or_else(|| section.chain().root_key());

            if section.chain().cmp_by_position(new, old) == Ordering::Greater {
                actions.vote.push(Vote::TheirKnowledge {
                    prefix: *src_prefix,
                    key: *new,
                });
            }
        }

        if new != section.chain().last_key() {
            send_other_section = true;
        }
    }

    if send_other_section {
        // TODO: if src has split, consider sending to all child prefixes.
        let dst_key = network.key_by_name(&src_name).cloned();
        actions.send.push(create_other_section_message(
            node,
            section,
            network,
            src_name,
            *msg.hash(),
            dst_key,
        )?);
    }

    Ok(actions)
}

fn create_other_section_message(
    node: &Node,
    section: &Section,
    network: &Network,
    dst: XorName,
    nonce: MessageHash,
    dst_key: Option<bls::PublicKey>,
) -> Result<Message> {
    let dst_knowledge = network
        .knowledge_by_name(&dst)
        .unwrap_or_else(|| section.chain().root_key());
    let proof_chain = section
        .chain()
        .minimize(vec![section.chain().last_key(), dst_knowledge])?;

    let variant = Variant::OtherSection {
        elders_info: section.proven_elders_info().clone(),
        nonce,
    };

    Ok(Message::single_src(
        node,
        DstLocation::Section(dst),
        variant,
        Some(proof_chain),
        dst_key,
    )?)
}

#[derive(Default)]
pub(crate) struct Actions {
    // Messages to send.
    pub send: Vec<Message>,
    // Votes to cast.
    pub vote: Vec<Vote>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::test_utils::proven,
        crypto,
        section::{
            test_utils::{gen_addr, gen_elders_info},
            SectionChain,
        },
        ELDER_SIZE,
    };
    use anyhow::{Context, Result};
    use assert_matches::assert_matches;
    use bytes::Bytes;
    use xor_name::Prefix;

    #[test]
    fn everything_up_to_date() -> Result<()> {
        let env = Env::new(1)?;

        let proof_chain = SectionChain::new(env.their_sk.public_key());
        let msg = env.create_message(
            &env.their_prefix,
            proof_chain,
            *env.section.chain().last_key(),
        )?;

        let actions = process(&env.node, &env.section, &env.network, &msg)?;
        assert_eq!(actions.send, []);
        assert_eq!(actions.vote, []);

        Ok(())
    }

    #[test]
    fn unknown_src_key() -> Result<()> {
        let env = Env::new(1)?;

        let their_pk_old = env.their_sk.public_key();
        let their_pk_new = bls::SecretKey::random().public_key();
        let mut proof_chain = SectionChain::new(env.their_sk.public_key());
        proof_chain.insert(
            &their_pk_old,
            their_pk_new,
            env.their_sk.sign(&bincode::serialize(&their_pk_new)?),
        )?;

        let msg = env.create_message(
            &env.their_prefix,
            proof_chain,
            *env.section.chain().last_key(),
        )?;

        let actions = process(&env.node, &env.section, &env.network, &msg)?;

        assert_eq!(actions.vote, []);
        assert_matches!(&actions.send[..], &[ref message] => {
            assert_matches!(
                message.variant(),
                Variant::OtherSection { elders_info, .. } => {
                    assert_eq!(&elders_info.value, env.section.elders_info())
                }
            );
            assert_eq!(message.dst_key(), Some(&their_pk_old));
            assert_matches!(message.proof_chain(), Ok(chain) => {
                assert_eq!(chain.len(), 1);
                assert_eq!(chain.last_key(), env.section.chain().last_key());
            });
        });

        Ok(())
    }

    #[test]
    fn outdated_dst_key_from_other_section() -> Result<()> {
        let env = Env::new(2)?;

        let proof_chain = SectionChain::new(env.their_sk.public_key());
        let msg = env.create_message(
            &env.their_prefix,
            proof_chain,
            *env.section.chain().root_key(),
        )?;

        let actions = process(&env.node, &env.section, &env.network, &msg)?;

        assert_eq!(actions.vote, []);
        assert_matches!(&actions.send[..], &[ref message] => {
            assert_matches!(message.variant(), Variant::OtherSection { .. });
            assert_matches!(message.proof_chain(), Ok(chain) => {
                assert_eq!(chain, env.section.chain());
            })
        });

        Ok(())
    }

    #[test]
    #[ignore]
    fn outdated_dst_key_from_our_section() -> Result<()> {
        let env = Env::new(2)?;

        let proof_chain = SectionChain::new(*env.section.chain().root_key());
        let msg = env.create_message(
            env.section.prefix(),
            proof_chain,
            *env.section.chain().root_key(),
        )?;

        let actions = process(&env.node, &env.section, &env.network, &msg)?;

        assert_eq!(actions.send, []);
        assert_eq!(actions.vote, []);

        Ok(())
    }

    #[test]
    fn outdated_knowledge() -> Result<()> {
        let mut env = Env::new(2)?;

        let knowledge = proven(
            &env.our_sk,
            (env.their_prefix, *env.section.chain().root_key()),
        )?;
        env.network.update_knowledge(knowledge);

        let proof_chain = SectionChain::new(env.their_sk.public_key());
        let msg = env.create_message(
            &env.their_prefix,
            proof_chain,
            *env.section.chain().last_key(),
        )?;

        let actions = process(&env.node, &env.section, &env.network, &msg)?;

        assert_eq!(actions.send, []);
        assert_matches!(&actions.vote[..], &[Vote::TheirKnowledge { prefix, key }] => {
            assert_eq!(prefix, env.their_prefix);
            assert_eq!(key, *env.section.chain().last_key());
        });

        Ok(())
    }

    struct Env {
        node: Node,
        section: Section,
        network: Network,
        our_sk: bls::SecretKey,
        their_prefix: Prefix,
        their_sk: bls::SecretKey,
    }

    impl Env {
        fn new(chain_len: usize) -> Result<Self> {
            let prefix0 = Prefix::default().pushed(false);
            let prefix1 = Prefix::default().pushed(true);

            let (chain, our_sk) =
                create_chain(chain_len).context("failed to create section chain")?;

            let (elders_info0, mut nodes) = gen_elders_info(prefix0, ELDER_SIZE);
            let node = nodes.remove(0);

            let elders_info0 = proven(&our_sk, elders_info0)?;
            let section = Section::new(chain, elders_info0).context("failed to create section")?;

            let (elders_info1, _) = gen_elders_info(prefix1, ELDER_SIZE);
            let elders_info1 = proven(&our_sk, elders_info1)?;

            let their_sk = bls::SecretKey::random();
            let their_pk = their_sk.public_key();
            let key1 = proven(&our_sk, (prefix1, their_pk))?;

            let mut network = Network::new();
            assert!(network.update_section(elders_info1, None, section.chain()));
            assert!(network.update_their_key(key1));

            Ok(Self {
                node,
                section,
                network,
                our_sk,
                their_prefix: prefix1,
                their_sk,
            })
        }

        fn create_message(
            &self,
            src_section: &Prefix,
            proof_chain: SectionChain,
            dst_key: bls::PublicKey,
        ) -> Result<Message> {
            let sender = Node::new(
                crypto::gen_keypair_within_range(&src_section.range_inclusive()),
                gen_addr(),
            );

            Ok(Message::single_src(
                &sender,
                DstLocation::Section(self.node.name()),
                Variant::UserMessage(Bytes::from_static(b"hello")),
                Some(proof_chain),
                Some(dst_key),
            )?)
        }
    }

    fn create_chain(len: usize) -> Result<(SectionChain, bls::SecretKey)> {
        let mut sk = bls::SecretKey::random();
        let mut chain = SectionChain::new(sk.public_key());

        for _ in 1..len {
            let old_pk = *chain.last_key();

            let new_sk = bls::SecretKey::random();
            let new_pk = new_sk.public_key();
            let new_signature = sk.sign(&bincode::serialize(&new_pk)?);

            chain.insert(&old_pk, new_pk, new_signature)?;
            sk = new_sk
        }

        Ok((chain, sk))
    }
}

// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    agreement::Proposal,
    error::Result,
    messages::{Message, Variant},
    network::Network,
    node::Node,
    section::Section,
};
use sn_messaging::{DestInfo, DstLocation};
use std::cmp::Ordering;

/// On reception of an incoming message, determine the actions that need to be taken in order to
/// bring ours and the senders knowledge about each other up to date.
pub(crate) fn process(
    node: &Node,
    section: &Section,
    network: &Network,
    msg: &Message,
    dest_info: DestInfo,
) -> Result<Actions> {
    let mut actions = Actions::default();

    let src_name = msg.src().name();
    if section.prefix().matches(&src_name) {
        // This message is from our section. We update our members via the `Sync` message which is
        // done elsewhere.
        return Ok(actions);
    }

    if let Ok(src_chain) = msg.proof_chain() {
        if let Some(key) = network.key_by_name(&src_name) {
            match src_chain.cmp_by_position(src_chain.last_key(), key) {
                Ordering::Greater => {
                    trace!("Anti-Entropy: We do not know source's key, need to update ourselves");
                    let msg = create_other_section_message(
                        node,
                        section,
                        network,
                        Variant::SrcAhead,
                        DstLocation::Node(src_name),
                    )?;
                    actions.send.push(msg);
                    // send_other_section = true;
                }
                Ordering::Less => {
                    // TODO: Send our knowledge to Src. SrcOutdated
                }
                Ordering::Equal => {}
            }
        }
    }

    // TODO: Check if Src has an advanced key than us.
    // i.e. check if we are lagging ourselves

    // let src_prefix = network
    //     .section_by_name(&src_name)
    //     .1
    //     .map(|info| &info.prefix);

    match section
        .chain()
        .cmp_by_position(&dest_info.dest_section_pk, section.chain().last_key())
    {
        Ordering::Greater => {
            // Their knowledge of our section is newer than what we have stored - update it.
            trace!("Anti-Entropy: We, the dst are outdated. Source has an greater key of ours");
            let msg = create_other_section_message(
                node,
                section,
                network,
                Variant::DstOutdated,
                DstLocation::Node(src_name),
            )?;
            actions.send.push(msg)
        }
        Ordering::Less => {
            trace!("Anti-Entropy: Source's knowledge of our key is outdated");
            let msg = create_other_section_message(
                node,
                section,
                network,
                Variant::DstAhead(section.chain().clone()),
                DstLocation::Node(src_name),
            )?;
            actions.send.push(msg)
        }
        Ordering::Equal => {}
    }

    Ok(actions)
}

fn create_other_section_message(
    node: &Node,
    section: &Section,
    network: &Network,
    variant: Variant,
    dst: DstLocation,
    // nonce: MessageHash,
) -> Result<Message> {
    let dst_knowledge = dst
        .name()
        .and_then(|dst| network.knowledge_by_name(&dst))
        .unwrap_or_else(|| section.chain().root_key());
    let proof_chain = section
        .chain()
        .minimize(vec![section.chain().last_key(), dst_knowledge])?;

    Message::single_src(node, dst, variant, Some(proof_chain))
}

#[derive(Default)]
pub(crate) struct Actions {
    // Message to send.
    pub send: Vec<Message>,
    // Proposal to cast.
    pub propose: Option<Proposal>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agreement::test_utils::proven,
        crypto,
        section::{
            test_utils::{gen_addr, gen_section_authority_provider},
            SectionChain,
        },
        XorName, ELDER_SIZE, MIN_ADULT_AGE,
    };
    use anyhow::{Context, Result};
    //use assert_matches::assert_matches;
    use bytes::Bytes;
    use xor_name::Prefix;

    #[test]
    fn everything_up_to_date() -> Result<()> {
        let env = Env::new(1)?;

        let proof_chain = SectionChain::new(env.their_sk.public_key());
        let msg = env.create_message(&env.their_prefix, proof_chain)?;
        let dest_info = DestInfo {
            dest: XorName::random(),
            dest_section_pk: *env.section.chain().last_key(),
        };

        let actions = process(&env.node, &env.section, &env.network, &msg, dest_info)?;
        assert_eq!(actions.send, vec![]);
        assert_eq!(actions.propose, None);

        Ok(())
    }

    #[test]
    fn new_src_key_from_other_section() -> Result<()> {
        let env = Env::new(1)?;

        let their_old_pk = env.their_sk.public_key();
        let their_new_pk = bls::SecretKey::random().public_key();
        let mut proof_chain = SectionChain::new(their_old_pk);
        proof_chain.insert(
            &their_old_pk,
            their_new_pk,
            env.their_sk.sign(&bincode::serialize(&their_new_pk)?),
        )?;

        let msg = env.create_message(&env.their_prefix, proof_chain)?;
        let dest_info = DestInfo {
            dest: XorName::random(),
            dest_section_pk: *env.section.chain().last_key(),
        };

        let actions = process(&env.node, &env.section, &env.network, &msg, dest_info)?;

        assert_eq!(actions.propose, None);
        // assert_matches!(&actions.send, Some(message) => {
        //     assert_matches!(
        //         message.variant(),
        //         Variant::OtherSection { section_auth, .. } => {
        //             assert_eq!(&section_auth.value, env.section.authority_provider())
        //         }
        //     );
        //     assert_matches!(message.proof_chain(), Ok(chain) => {
        //         assert_eq!(chain.len(), 1);
        //         assert_eq!(chain.last_key(), env.section.chain().last_key());
        //     });
        // });

        Ok(())
    }

    #[test]
    fn new_src_key_from_our_section() -> Result<()> {
        let env = Env::new(1)?;

        let our_old_pk = env.our_sk.public_key();
        let our_new_sk = bls::SecretKey::random();
        let our_new_pk = our_new_sk.public_key();
        let mut proof_chain = SectionChain::new(our_old_pk);
        proof_chain.insert(
            &our_old_pk,
            our_new_pk,
            env.our_sk.sign(&bincode::serialize(&our_new_pk)?),
        )?;

        let msg = env.create_message(env.section.prefix(), proof_chain)?;
        let dest_info = DestInfo {
            dest: XorName::random(),
            dest_section_pk: our_new_pk,
        };

        let actions = process(&env.node, &env.section, &env.network, &msg, dest_info)?;

        assert_eq!(actions.send, vec![]);
        assert_eq!(actions.propose, None);

        Ok(())
    }

    #[test]
    fn outdated_dst_key_from_other_section() -> Result<()> {
        let env = Env::new(2)?;

        let proof_chain = SectionChain::new(env.their_sk.public_key());
        let msg = env.create_message(&env.their_prefix, proof_chain)?;
        let dest_info = DestInfo {
            dest: XorName::random(),
            dest_section_pk: *env.section.chain().root_key(),
        };

        let actions = process(&env.node, &env.section, &env.network, &msg, dest_info)?;

        assert_eq!(actions.propose, None);
        // assert_matches!(&actions.send, Some(message) => {
        //     assert_matches!(message.variant(), Variant::OtherSection { .. });
        //     assert_matches!(message.proof_chain(), Ok(chain) => {
        //         assert_eq!(chain, env.section.chain());
        //     })
        // });

        Ok(())
    }

    #[test]
    fn outdated_dst_key_from_our_section() -> Result<()> {
        let env = Env::new(2)?;

        let proof_chain = SectionChain::new(*env.section.chain().root_key());
        let msg = env.create_message(env.section.prefix(), proof_chain)?;
        let dest_info = DestInfo {
            dest: XorName::random(),
            dest_section_pk: *env.section.chain().root_key(),
        };

        let actions = process(&env.node, &env.section, &env.network, &msg, dest_info)?;

        assert_eq!(actions.send, vec![]);
        assert_eq!(actions.propose, None);

        Ok(())
    }

    #[test]
    #[ignore]
    fn outdated_knowledge() -> Result<()> {
        let mut env = Env::new(2)?;

        let knowledge = proven(
            &env.our_sk,
            (env.their_prefix, *env.section.chain().root_key()),
        )?;
        env.network.update_knowledge(knowledge);

        let proof_chain = SectionChain::new(env.their_sk.public_key());
        let msg = env.create_message(&env.their_prefix, proof_chain)?;
        let dest_info = DestInfo {
            dest: XorName::random(),
            dest_section_pk: *env.section.chain().last_key(),
        };
        let actions = process(&env.node, &env.section, &env.network, &msg, dest_info)?;

        assert_eq!(actions.send, vec![]);
        // assert_matches!(&actions.propose, Some(Proposal::TheirKnowledge { prefix, key }) => {
        //     assert_eq!(prefix, &env.their_prefix);
        //     assert_eq!(key, env.section.chain().last_key());
        // });

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

            let (section_auth0, mut nodes) = gen_section_authority_provider(prefix0, ELDER_SIZE);
            let node = nodes.remove(0);

            let section_auth0 = proven(&our_sk, section_auth0)?;
            let section = Section::new(*chain.root_key(), chain, section_auth0)
                .context("failed to create section")?;

            let (section_auth1, _) = gen_section_authority_provider(prefix1, ELDER_SIZE);
            let section_auth1 = proven(&our_sk, section_auth1)?;

            let their_sk = bls::SecretKey::random();
            let their_pk = their_sk.public_key();
            let key1 = proven(&our_sk, (prefix1, their_pk))?;

            let mut network = Network::new();
            assert!(network.update_section(section_auth1, None, section.chain()));
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
        ) -> Result<Message> {
            let sender = Node::new(
                crypto::gen_keypair(&src_section.range_inclusive(), MIN_ADULT_AGE),
                gen_addr(),
            );

            Ok(Message::single_src(
                &sender,
                DstLocation::Section(self.node.name()),
                Variant::UserMessage(Bytes::from_static(b"hello")),
                Some(proof_chain),
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

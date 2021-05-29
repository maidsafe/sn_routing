// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::routing::command::Command;
use crate::routing::core::LaggingMessages;
use crate::{
    error::Result,
    messages::{RoutingMsgUtils, SrcAuthorityUtils},
    network::NetworkUtils,
    node::Node,
    section::SectionUtils,
};
use sn_messaging::{
    node::{Network, RoutingMsg, Section, Variant},
    DestInfo,
};
use std::cmp::Ordering;
use std::net::SocketAddr;

/// On reception of an incoming message, determine the actions that need to be taken in order to
/// bring ours and the senders knowledge about each other up to date. Returns a tuple of
/// `Actions` and `bool`. The boolean is flag for executing the message. If entropy is found, we do
/// not execute the message by returning `false`.
pub(crate) fn process(
    node: &Node,
    section: &Section,
    network: &Network,
    lagging_messages: &mut LaggingMessages,
    msg: &RoutingMsg,
    dest_info: DestInfo,
    sender: Option<SocketAddr>,
) -> Result<(Actions, bool)> {
    let mut actions = Actions::default();

    let src_name = msg.src.name();
    if section.prefix().matches(&src_name) {
        // This message is from our section. We update our members via the `Sync` message which is
        // done elsewhere.
        return Ok((actions, true));
    }

    let dst = msg.src.src_location().to_dst();

    if let Ok(src_chain) = msg.proof_chain() {
        if let Some(key) = network.key_by_name(&src_name) {
            match src_chain.cmp_by_position(src_chain.last_key(), key) {
                Ordering::Greater => {
                    trace!("Anti-Entropy: We do not know source's key, need to update ourselves");
                    let msg = RoutingMsg::single_src(
                        node,
                        dst,
                        Variant::SectionKnowledgeQuery {
                            last_known_key: Some(*key),
                            msg: Box::new(msg.clone()),
                        },
                        None,
                    )?;
                    actions.send.push(msg);
                }
                Ordering::Less => {
                    info!("Anti-Entropy: Src is lagging and needs to update himself. Do nothing as he will update himself");
                }
                Ordering::Equal => {}
            }
        } else {
            let msg = RoutingMsg::single_src(
                node,
                dst,
                Variant::SectionKnowledgeQuery {
                    last_known_key: None,
                    msg: Box::new(msg.clone()),
                },
                None,
            )?;
            actions.send.push(msg);
        }
    }

    if let Ordering::Less = section
        .chain()
        .cmp_by_position(&dest_info.dest_section_pk, section.chain().last_key())
    {
        if !section.chain().has_key(&dest_info.dest_section_pk) {
            // Their knowledge of our section is newer than what we have stored - store it and execute upon sync.
            info!("Anti-Entropy: We, the dst are outdated. Source has a greater key than ours.");
            info!("Enqueue the messages and act on them upon syncing in the future");
            let command = Command::HandleMessage {
                sender,
                message: msg.clone(),
                dest_info: dest_info.clone(),
            };
            match lagging_messages
                .src_ahead
                .get_mut(&dest_info.dest_section_pk)
            {
                Some(lagging) => {
                    lagging.push(command);
                }
                None => {
                    let _ = lagging_messages
                        .src_ahead
                        .insert(dest_info.dest_section_pk, vec![command]);
                }
            }
        } else {
            info!("Anti-Entropy: Source's knowledge of our key is outdated, send them an update.");
            info!("We can still execute the message as the key is a part of our chain");
            let chain = section
                .chain()
                .get_proof_chain_to_current(&dest_info.dest_section_pk)?;
            let section_auth = section.proven_authority_provider();
            let variant = Variant::SectionKnowledge {
                src_info: (section_auth.clone(), chain),
                msg: None,
            };
            let msg = RoutingMsg::single_src(node, dst, variant, None)?;
            actions.send.push(msg);
            return Ok((actions, true));
        }
    }

    Ok((actions, false))
}

#[derive(Default)]
pub(crate) struct Actions {
    // RoutingMsg to send.
    pub send: Vec<RoutingMsg>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agreement::test_utils::proven,
        crypto,
        section::test_utils::{gen_addr, gen_section_authority_provider},
        Error, XorName, ELDER_SIZE, MIN_ADULT_AGE,
    };
    use anyhow::{Context, Result};
    use assert_matches::assert_matches;
    use secured_linked_list::SecuredLinkedList;
    use sn_messaging::DstLocation;
    use xor_name::Prefix;

    #[test]
    fn everything_up_to_date() -> Result<()> {
        let env = Env::new(1)?;

        let proof_chain = SecuredLinkedList::new(env.their_pk);
        let msg = env.create_message(&env.their_prefix, proof_chain)?;
        let dest_info = DestInfo {
            dest: XorName::random(),
            dest_section_pk: *env.section.chain().last_key(),
        };

        let (actions, _) = process(
            &env.node,
            &env.section,
            &env.network,
            &mut LaggingMessages::default(),
            &msg,
            dest_info,
            None,
        )?;
        assert_eq!(actions.send, vec![]);

        Ok(())
    }

    #[test]
    fn new_src_key_from_other_section() -> Result<()> {
        let env = Env::new(1)?;

        let root_key =
            bls::PublicKey::from_bytes(env.their_sk.public_keys().public_key_share(0).to_bytes())
                .map_err(|_| Error::InvalidPayload)?;
        let their_new_pk = bls::SecretKey::random().public_key();
        let mut proof_chain = SecuredLinkedList::new(root_key);
        proof_chain.insert(
            &root_key,
            their_new_pk,
            env.their_sk
                .secret_key_share(0)
                .sign(&bincode::serialize(&their_new_pk)?)
                .0,
        )?;

        let msg = env.create_message(&env.their_prefix, proof_chain)?;
        let dest_info = DestInfo {
            dest: env.node.name(),
            dest_section_pk: *env.section.chain().last_key(),
        };

        let (mut actions, _) = process(
            &env.node,
            &env.section,
            &env.network,
            &mut LaggingMessages::default(),
            &msg,
            dest_info,
            None,
        )?;

        assert_matches!(&actions.send.pop(), Some(message) => {
            assert_matches!(
                message.variant(),
                Variant::SectionKnowledgeQuery { last_known_key, .. } => {
                    assert!(last_known_key.is_some());
                    assert_eq!(last_known_key.ok_or(Error::InvalidMessage)?, env.their_pk);
                }
            );
        });

        Ok(())
    }

    #[test]
    fn new_src_key_from_our_section() -> Result<()> {
        let env = Env::new(1)?;

        let our_old_pk = env.our_sk.public_key();
        let our_new_sk = bls::SecretKey::random();
        let our_new_pk = our_new_sk.public_key();
        let mut proof_chain = SecuredLinkedList::new(our_old_pk);
        proof_chain.insert(
            &our_old_pk,
            our_new_pk,
            env.our_sk.sign(&bincode::serialize(&our_new_pk)?),
        )?;

        let msg = env.create_message(env.section.prefix(), proof_chain)?;
        let dest_info = DestInfo {
            dest: env.node.name(),
            dest_section_pk: our_new_pk,
        };

        let (actions, _) = process(
            &env.node,
            &env.section,
            &env.network,
            &mut LaggingMessages::default(),
            &msg,
            dest_info,
            None,
        )?;

        assert_eq!(actions.send, vec![]);

        Ok(())
    }

    #[test]
    fn outdated_dst_key_from_other_section() -> Result<()> {
        let env = Env::new(2)?;

        let proof_chain = SecuredLinkedList::new(env.their_pk);
        let msg = env.create_message(&env.their_prefix, proof_chain)?;
        let dest_info = DestInfo {
            dest: XorName::random(),
            dest_section_pk: *env.section.chain().root_key(),
        };

        let (mut actions, _) = process(
            &env.node,
            &env.section,
            &env.network,
            &mut LaggingMessages::default(),
            &msg,
            dest_info,
            None,
        )?;

        assert_matches!(&actions.send.pop(), Some(message) => {
            assert_matches!(message.variant(), Variant::SectionKnowledge { src_info, .. } => {
                assert_eq!(src_info.0.value, *env.section.authority_provider());
                assert_eq!(src_info.1, *env.section.chain());
            });
        });

        Ok(())
    }

    #[test]
    fn outdated_dst_key_from_our_section() -> Result<()> {
        let env = Env::new(2)?;

        let proof_chain = SecuredLinkedList::new(*env.section.chain().root_key());
        let msg = env.create_message(env.section.prefix(), proof_chain)?;
        let dest_info = DestInfo {
            dest: XorName::random(),
            dest_section_pk: *env.section.chain().root_key(),
        };

        let (actions, _) = process(
            &env.node,
            &env.section,
            &env.network,
            &mut LaggingMessages::default(),
            &msg,
            dest_info,
            None,
        )?;

        assert_eq!(actions.send, vec![]);

        Ok(())
    }

    struct Env {
        node: Node,
        section: Section,
        network: Network,
        our_sk: bls::SecretKey,
        their_prefix: Prefix,
        their_sk: bls::SecretKeySet,
        their_pk: bls::PublicKey,
    }

    impl Env {
        fn new(chain_len: usize) -> Result<Self> {
            let prefix0 = Prefix::default().pushed(false);
            let prefix1 = Prefix::default().pushed(true);

            let (chain, our_sk) =
                create_chain(chain_len).context("failed to create section chain")?;

            let (section_auth0, mut nodes, _) = gen_section_authority_provider(prefix0, ELDER_SIZE);
            let node = nodes.remove(0);

            let section_auth0 = proven(&our_sk, section_auth0)?;
            let section = Section::new(*chain.root_key(), chain, section_auth0)
                .context("failed to create section")?;

            let (section_auth1, _, their_sk) = gen_section_authority_provider(prefix1, ELDER_SIZE);
            let their_pk = their_sk.public_keys().public_key();
            let section_auth1 = proven(&our_sk, section_auth1)?;

            let mut network = Network::new();
            assert!(network.update_section(section_auth1, None, section.chain()));

            Ok(Self {
                node,
                section,
                network,
                our_sk,
                their_prefix: prefix1,
                their_sk,
                their_pk,
            })
        }

        fn create_message(
            &self,
            src_section: &Prefix,
            proof_chain: SecuredLinkedList,
        ) -> Result<RoutingMsg> {
            let sender = Node::new(
                crypto::gen_keypair(&src_section.range_inclusive(), MIN_ADULT_AGE),
                gen_addr(),
            );

            Ok(RoutingMsg::single_src(
                &sender,
                DstLocation::Section(self.node.name()),
                Variant::UserMessage(b"hello".to_vec()),
                Some(proof_chain),
            )?)
        }
    }

    fn create_chain(len: usize) -> Result<(SecuredLinkedList, bls::SecretKey)> {
        let mut sk = bls::SecretKey::random();
        let mut chain = SecuredLinkedList::new(sk.public_key());

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

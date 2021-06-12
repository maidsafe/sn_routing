// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    error::Result,
    messages::{RoutingMsgUtils, SrcAuthorityUtils},
    node::Node,
    section::{SectionAuthorityProviderUtils, SectionUtils},
};
use sn_messaging::{
    node::{RoutingMsg, Section, Variant},
    DestInfo,
};
use std::cmp::Ordering;

/// On reception of an incoming message, determine the actions that need to be taken in order to
/// bring ours and the senders knowledge about each other up to date. Returns a tuple of
/// `Actions` and `bool`. The boolean is flag for executing the message. If entropy is found, we do
/// not execute the message by returning `false`.
pub(crate) fn process(
    node: &Node,
    section: &Section,
    msg: &RoutingMsg,
    dest_info: DestInfo,
) -> Result<(Actions, bool)> {
    let mut actions = Actions::default();

    let src_name = msg.src.name();
    if section.prefix().matches(&src_name) {
        // This message is from our section. We update our members via the `Sync` message which is
        // done elsewhere.
        return Ok((actions, true));
    }

    let dst = msg.src.src_location().to_dst();

    if let Ordering::Less = section
        .chain()
        .cmp_by_position(&dest_info.dest_section_pk, section.chain().last_key())
    {
        info!("Anti-Entropy: Source's knowledge of our key is outdated, send them an update.");
        let chain = section
            .chain()
            .get_proof_chain_to_current(&dest_info.dest_section_pk)?;
        let section_auth = section.proven_authority_provider();
        let variant = Variant::SectionKnowledge {
            src_info: (section_auth.clone(), chain),
            msg: Some(Box::new(msg.clone())),
        };
        let msg = RoutingMsg::single_src(
            node,
            dst,
            variant,
            section.authority_provider().section_key(),
        )?;
        actions.send.push(msg);
        return Ok((actions, false));
    }

    Ok((actions, true))
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
        dkg::test_utils::proven,
        ed25519,
        section::test_utils::{gen_addr, gen_section_authority_provider},
        XorName, ELDER_SIZE, MIN_ADULT_AGE,
    };
    use anyhow::{Context, Result};
    use assert_matches::assert_matches;
    use secured_linked_list::SecuredLinkedList;
    use sn_messaging::DstLocation;
    use xor_name::Prefix;

    #[test]
    fn everything_up_to_date() -> Result<()> {
        let env = Env::new(1)?;

        let msg = env.create_message(
            &env.their_prefix,
            env.section.authority_provider().section_key(),
        )?;
        let dest_info = DestInfo {
            dest: XorName::random(),
            dest_section_pk: *env.section.chain().last_key(),
        };

        let (actions, _) = process(&env.node, &env.section, &msg, dest_info)?;
        assert_eq!(actions.send, vec![]);

        Ok(())
    }

    #[test]
    fn new_src_key_from_our_section() -> Result<()> {
        let env = Env::new(1)?;

        let our_new_sk = bls::SecretKey::random();
        let our_new_pk = our_new_sk.public_key();

        let msg = env.create_message(
            env.section.prefix(),
            env.section.authority_provider().section_key(),
        )?;
        let dest_info = DestInfo {
            dest: env.node.name(),
            dest_section_pk: our_new_pk,
        };

        let (actions, _) = process(&env.node, &env.section, &msg, dest_info)?;

        assert_eq!(actions.send, vec![]);

        Ok(())
    }

    #[test]
    fn outdated_dst_key_from_other_section() -> Result<()> {
        let env = Env::new(2)?;

        let msg = env.create_message(
            &env.their_prefix,
            env.section.authority_provider().section_key(),
        )?;
        let dest_info = DestInfo {
            dest: XorName::random(),
            dest_section_pk: *env.section.chain().root_key(),
        };

        let (mut actions, _) = process(&env.node, &env.section, &msg, dest_info)?;

        assert_matches!(&actions.send.pop(), Some(message) => {
            assert_matches!(message.variant, Variant::SectionKnowledge { ref src_info, .. } => {
                assert_eq!(src_info.0.value, *env.section.authority_provider());
                assert_eq!(src_info.1, *env.section.chain());
            });
        });

        Ok(())
    }

    #[test]
    fn outdated_dst_key_from_our_section() -> Result<()> {
        let env = Env::new(2)?;

        let msg = env.create_message(
            env.section.prefix(),
            env.section.authority_provider().section_key(),
        )?;
        let dest_info = DestInfo {
            dest: XorName::random(),
            dest_section_pk: *env.section.chain().root_key(),
        };

        let (actions, _) = process(&env.node, &env.section, &msg, dest_info)?;

        assert_eq!(actions.send, vec![]);

        Ok(())
    }

    struct Env {
        node: Node,
        section: Section,
        their_prefix: Prefix,
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

            Ok(Self {
                node,
                section,
                their_prefix: prefix1,
            })
        }

        fn create_message(
            &self,
            src_section: &Prefix,
            section_pk: bls::PublicKey,
        ) -> Result<RoutingMsg> {
            let sender = Node::new(
                ed25519::gen_keypair(&src_section.range_inclusive(), MIN_ADULT_AGE),
                gen_addr(),
            );

            Ok(RoutingMsg::single_src(
                &sender,
                DstLocation::Section(self.node.name()),
                Variant::UserMessage(b"hello".to_vec()),
                section_pk,
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

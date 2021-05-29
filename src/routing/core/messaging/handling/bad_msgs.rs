// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Core;
use crate::{
    messages::{RoutingMsgUtils, SrcAuthorityUtils},
    peer::PeerUtils,
    routing::command::Command,
    section::SectionUtils,
    Error, Result,
};
use sn_messaging::{
    node::{Peer, RoutingMsg, Variant},
    DestInfo, DstLocation,
};
use std::net::SocketAddr;

// Bad msgs
impl Core {
    // Handle message whose trust we can't establish because its proof
    // contains only keys we don't know.
    pub(crate) fn handle_untrusted_message(
        &self,
        sender: Option<SocketAddr>,
        msg: RoutingMsg,
        received_dest_info: DestInfo,
    ) -> Result<Command> {
        let src_name = msg.src.name();
        let bounce_dst_key = *self.section_key_by_name(&src_name);
        let dest_info = DestInfo {
            dest: src_name,
            dest_section_pk: bounce_dst_key,
        };
        let bounce_msg = RoutingMsg::single_src(
            &self.node,
            DstLocation::DirectAndUnrouted,
            Variant::BouncedUntrustedMessage {
                msg: Box::new(msg),
                dest_info: received_dest_info,
            },
            None,
        )?;

        let cmd = if let Some(sender) = sender {
            Command::send_message_to_node((src_name, sender), bounce_msg, dest_info)
        } else {
            self.send_message_to_our_elders(bounce_msg)
        };

        Ok(cmd)
    }

    pub(crate) fn handle_bounced_untrusted_message(
        &self,
        sender: Peer,
        dst_key: bls::PublicKey,
        bounced_msg: RoutingMsg,
    ) -> Result<Command> {
        let span = trace_span!("Received BouncedUntrustedMessage", ?bounced_msg, %sender);
        let _span_guard = span.enter();

        let resend_msg = match bounced_msg.variant {
            Variant::Sync { section, network } => {
                // `Sync` messages are handled specially, because they don't carry a proof chain.
                // Instead we use the section chain that's part of the included `Section` struct.
                // Problem is we can't extend that chain as it would invalidate the signature. We
                // must construct a new message instead.
                let section = section
                    .extend_chain(&dst_key, self.section.chain())
                    .map_err(|err| {
                        error!("extending section chain failed: {:?}", err);
                        Error::InvalidMessage // TODO: more specific error
                    })?;

                RoutingMsg::single_src(
                    &self.node,
                    DstLocation::DirectAndUnrouted,
                    Variant::Sync { section, network },
                    None,
                )?
            }
            _ => bounced_msg
                .extend_proof_chain(&dst_key, self.section.chain())
                .map_err(|err| {
                    error!("extending proof chain failed: {:?}", err);
                    Error::InvalidMessage // TODO: more specific error
                })?,
        };

        let dest_info = DestInfo {
            dest: *sender.name(),
            dest_section_pk: dst_key,
        };
        trace!("resending with extended proof");
        Ok(Command::send_message_to_node(
            (*sender.name(), *sender.addr()),
            resend_msg,
            dest_info,
        ))
    }
}

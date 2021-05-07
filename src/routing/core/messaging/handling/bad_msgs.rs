// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::net::SocketAddr;

use super::Core;
use crate::{
    messages::{Message, Variant},
    peer::Peer,
    routing::command::Command,
    Error, Result,
};
use sn_messaging::DstLocation;

// Bad msgs
impl Core {
    // Handle message whose trust we can't establish because its proof
    // contains only keys we don't know.
    pub(crate) fn handle_untrusted_message(
        &self,
        sender: Option<SocketAddr>,
        msg: Message,
    ) -> Result<Command> {
        let dest = msg.src().name();
        let bounce_dst_key = *self.section_key_by_name(&dest);
        let bounce_msg = Message::single_src(
            &self.node,
            DstLocation::Direct,
            Variant::BouncedUntrustedMessage(Box::new(msg)),
            None,
            Some(bounce_dst_key),
        )?;

        let bounce_msg_bytes = bounce_msg.to_bytes();

        let cmd = if let Some(sender) = sender {
            Command::send_message_to_node(&sender, bounce_msg_bytes)
        } else {
            self.send_message_to_our_elders(bounce_msg_bytes)
        };

        Ok(cmd)
    }

    pub(crate) fn handle_bounced_untrusted_message(
        &self,
        sender: Peer,
        dst_key: Option<bls::PublicKey>,
        bounced_msg: Message,
    ) -> Result<Command> {
        let span = trace_span!("Received BouncedUntrustedMessage", ?bounced_msg, %sender);
        let _span_guard = span.enter();

        let dst_key = dst_key.ok_or_else(|| {
            error!("missing dst key");
            Error::InvalidMessage
        })?;

        let resend_msg = match bounced_msg.variant() {
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

                Message::single_src(
                    &self.node,
                    DstLocation::Direct,
                    Variant::Sync {
                        section,
                        network: network.clone(),
                    },
                    None,
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

        trace!("resending with extended proof");
        Ok(Command::send_message_to_node(
            sender.addr(),
            resend_msg.to_bytes(),
        ))
    }
}

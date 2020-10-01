// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{joining::Joining, Command, Context, NodeInfo, State};
use crate::{
    crypto::{keypair_within_range, name},
    error::Result,
    messages::{BootstrapResponse, Message, Variant, VerifyStatus},
    peer::Peer,
    relocation::{RelocatePayload, SignedRelocateDetails},
    section::EldersInfo,
    timer::Timer,
    DstLocation, MIN_AGE,
};
use std::{iter, net::SocketAddr, sync::Arc};
use xor_name::Prefix;

// TODO: review if we still need to set a timeout for joining
/// Time after which bootstrap is cancelled (and possibly returnried).
// pub const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(20);

// The bootstrapping stage - node is trying to find the section to join.
pub(crate) struct Bootstrapping {
    pub node_info: NodeInfo,
    relocate_details: Option<SignedRelocateDetails>,
    timer: Timer,
}

impl Bootstrapping {
    pub fn new(
        cx: &mut Context,
        relocate_details: Option<SignedRelocateDetails>,
        bootstrap_contacts: Vec<SocketAddr>,
        node_info: NodeInfo,
        timer: Timer,
    ) -> Self {
        cx.push(Command::SendBootstrapRequest(bootstrap_contacts));

        Self {
            node_info,
            relocate_details,
            timer,
        }
    }

    pub async fn handle_message(
        &mut self,
        cx: &mut Context,
        sender: SocketAddr,
        msg: Message,
    ) -> Result<()> {
        match msg.variant() {
            Variant::BootstrapResponse(response) => {
                msg.verify(iter::empty())
                    .and_then(VerifyStatus::require_full)?;

                match self.handle_bootstrap_response(
                    cx,
                    msg.src().to_sender_node(Some(sender))?,
                    response.clone(),
                )? {
                    Some(JoinParams {
                        elders_info,
                        section_key,
                        relocate_payload,
                    }) => {
                        let state = Joining::new(
                            cx,
                            elders_info,
                            section_key,
                            relocate_payload,
                            self.node_info.clone(),
                            self.timer.clone(),
                        )
                        .await?;
                        let state = State::Joining(state);
                        cx.push(Command::Transition(Box::new(state)));
                        Ok(())
                    }
                    None => Ok(()),
                }
            }

            Variant::NeighbourInfo { .. }
            | Variant::UserMessage(_)
            | Variant::BouncedUntrustedMessage(_) => {
                debug!("Unknown message from {}: {:?} ", sender, msg);
                Ok(())
            }

            Variant::NodeApproval(_)
            | Variant::Sync { .. }
            | Variant::Relocate(_)
            | Variant::RelocatePromise(_)
            | Variant::BootstrapRequest(_)
            | Variant::JoinRequest(_)
            | Variant::BouncedUnknownMessage { .. }
            | Variant::Vote { .. }
            | Variant::DKGResult { .. }
            | Variant::DKGStart { .. }
            | Variant::DKGMessage { .. } => {
                debug!("Useless message from {}: {:?}", sender, msg);
                Ok(())
            }
        }
    }

    pub async fn handle_timeout(&mut self, _token: u64) -> Result<()> {
        todo!()
    }

    pub fn send_bootstrap_request(
        &self,
        cx: &mut Context,
        recipients: &[SocketAddr],
    ) -> Result<()> {
        let (destination, age) = match &self.relocate_details {
            Some(details) => (*details.destination(), details.relocate_details().age),
            None => (self.node_info.name(), MIN_AGE),
        };

        let message = Message::single_src(
            &self.node_info.keypair,
            age,
            DstLocation::Direct,
            Variant::BootstrapRequest(destination),
            None,
            None,
        )?;

        debug!("Sending BootstrapRequest to {:?}", recipients);
        cx.send_message_to_targets(recipients, recipients.len(), message.to_bytes());

        Ok(())
    }

    fn handle_bootstrap_response(
        &mut self,
        cx: &mut Context,
        sender: Peer,
        response: BootstrapResponse,
    ) -> Result<Option<JoinParams>> {
        match response {
            BootstrapResponse::Join {
                elders_info,
                section_key,
            } => {
                info!(
                    "Joining a section {:?} (given by {:?})",
                    elders_info, sender
                );

                let relocate_payload = self.join_section(&elders_info)?;
                Ok(Some(JoinParams {
                    elders_info,
                    section_key,
                    relocate_payload,
                }))
            }
            BootstrapResponse::Rebootstrap(new_conn_infos) => {
                info!(
                    "Bootstrapping redirected to another set of peers: {:?}",
                    new_conn_infos
                );
                self.send_bootstrap_request(cx, &new_conn_infos)?;
                Ok(None)
            }
        }
    }

    fn join_section(&mut self, elders_info: &EldersInfo) -> Result<Option<RelocatePayload>> {
        let relocate_details = if let Some(details) = self.relocate_details.take() {
            details
        } else {
            return Ok(None);
        };

        // We are relocating so we need to change our name.
        // Use a name that will match the destination even after multiple splits
        let extra_split_count = 3;
        let name_prefix = Prefix::new(
            elders_info.prefix.bit_count() + extra_split_count,
            *relocate_details.destination(),
        );

        // FIXME: do we need to reuse MainRng everywhere really??
        // This will currently break tests.
        let mut rng = crate::rng::MainRng::default();
        let new_keypair = keypair_within_range(&mut rng, &name_prefix.range_inclusive());
        let new_name = name(&new_keypair.public);
        let relocate_payload =
            RelocatePayload::new(relocate_details, &new_name, &self.node_info.keypair)?;

        info!("Changing name to {}.", new_name);
        self.node_info.keypair = Arc::new(new_keypair);

        Ok(Some(relocate_payload))
    }
}

pub(crate) struct JoinParams {
    pub elders_info: EldersInfo,
    pub section_key: bls::PublicKey,
    pub relocate_payload: Option<RelocatePayload>,
}

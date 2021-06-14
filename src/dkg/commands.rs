// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    error::Result, messages::RoutingMsgUtils, node::Node, routing::command::Command,
    section::SectionKeyShare,
};
use bls_dkg::key_gen::message::Message as DkgMessage;
use sn_messaging::{
    node::{DkgFailureSigned, DkgFailureSignedSet, DkgKey, RoutingMsg, Variant},
    DestInfo, DstLocation, SectionAuthorityProvider,
};
use std::{collections::BTreeSet, fmt::Debug, net::SocketAddr, time::Duration};
use xor_name::XorName;
#[derive(Debug)]
pub(crate) enum DkgCommand {
    SendMessage {
        recipients: Vec<(XorName, SocketAddr)>,
        dkg_key: DkgKey,
        message: DkgMessage,
    },
    ScheduleTimeout {
        duration: Duration,
        token: u64,
    },
    HandleOutcome {
        section_auth: SectionAuthorityProvider,
        outcome: SectionKeyShare,
    },
    SendFailureObservation {
        recipients: Vec<(XorName, SocketAddr)>,
        dkg_key: DkgKey,
        signed: DkgFailureSigned,
        non_participants: BTreeSet<XorName>,
    },
    HandleFailureAgreement(DkgFailureSignedSet),
}

impl DkgCommand {
    fn into_command(self, node: &Node, key: bls::PublicKey) -> Result<Command> {
        match self {
            Self::SendMessage {
                recipients,
                dkg_key,
                message,
            } => {
                let variant = Variant::DkgMessage { dkg_key, message };
                let message =
                    RoutingMsg::single_src(node, DstLocation::DirectAndUnrouted, variant, key)?;

                Ok(Command::send_message_to_nodes(
                    recipients.clone(),
                    recipients.len(),
                    message,
                    DestInfo {
                        dest: XorName::random(),
                        dest_section_pk: key,
                    },
                ))
            }
            Self::ScheduleTimeout { duration, token } => {
                Ok(Command::ScheduleTimeout { duration, token })
            }
            Self::HandleOutcome {
                section_auth,
                outcome,
            } => Ok(Command::HandleDkgOutcome {
                section_auth,
                outcome,
            }),
            Self::SendFailureObservation {
                recipients,
                dkg_key,
                signed,
                non_participants,
            } => {
                let variant = Variant::DkgFailureObservation {
                    dkg_key,
                    signed,
                    non_participants,
                };
                let message =
                    RoutingMsg::single_src(node, DstLocation::DirectAndUnrouted, variant, key)?;

                Ok(Command::send_message_to_nodes(
                    recipients.clone(),
                    recipients.len(),
                    message,
                    DestInfo {
                        dest: XorName::random(),
                        dest_section_pk: key,
                    },
                ))
            }
            Self::HandleFailureAgreement(signeds) => Ok(Command::HandleDkgFailure(signeds)),
        }
    }
}

pub(crate) trait DkgCommands {
    fn into_commands(self, node: &Node, key: bls::PublicKey) -> Result<Vec<Command>>;
}

impl DkgCommands for Vec<DkgCommand> {
    fn into_commands(self, node: &Node, key: bls::PublicKey) -> Result<Vec<Command>> {
        self.into_iter()
            .map(|command| command.into_command(node, key))
            .collect()
    }
}

impl DkgCommands for Option<DkgCommand> {
    fn into_commands(self, node: &Node, key: bls::PublicKey) -> Result<Vec<Command>> {
        self.into_iter()
            .map(|command| command.into_command(node, key))
            .collect()
    }
}

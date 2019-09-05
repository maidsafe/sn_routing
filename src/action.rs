// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::error::InterfaceError;
use crate::id::PublicId;
use crate::messages::{DirectMessage, Request, UserMessage};
use crate::routing_table::Authority;
use crate::xor_name::XorName;
use std::fmt::{self, Debug, Formatter};
use std::sync::mpsc::Sender;

/// An Action initiates a message flow < A | B > where we are (a part of) A.
///    1. `Action::SendMessage` hands a fully formed `SignedMessage` over to `Core`
///       for it to be sent on across the network.
///    2. `Action::Terminate` indicates to `Core` that no new actions should be taken and all
///       pending events should be handled.
///       After completion `Core` will send `Event::Terminated`.
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
pub enum Action {
    NodeSendMessage {
        src: Authority<XorName>,
        dst: Authority<XorName>,
        content: UserMessage,
        result_tx: Sender<Result<(), InterfaceError>>,
    },
    ClientSendRequest {
        content: Request,
        dst: Authority<XorName>,
        result_tx: Sender<Result<(), InterfaceError>>,
    },
    GetId {
        result_tx: Sender<PublicId>,
    },
    HandleTimeout(u64),
    // Used to pass the messages created as a result of handling a resource proof request from the
    // worker thread back to the main event loop.
    TakeResourceProofResult(PublicId, Vec<DirectMessage>),
    Terminate,
}

impl Debug for Action {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Action::NodeSendMessage { ref content, .. } => write!(
                formatter,
                "Action::NodeSendMessage {{ {:?}, result_tx }}",
                content
            ),
            Action::ClientSendRequest {
                ref content,
                ref dst,
                ..
            } => write!(
                formatter,
                "Action::ClientSendRequest {{ {:?}, dst: {:?}, result_tx }}",
                content, dst
            ),
            Action::GetId { .. } => write!(formatter, "Action::GetId"),
            Action::HandleTimeout(token) => write!(formatter, "Action::HandleTimeout({})", token),
            Action::TakeResourceProofResult(pub_id, _) => write!(
                formatter,
                "Action::TakeResourceProofResult({:?}, ...)",
                pub_id
            ),
            Action::Terminate => write!(formatter, "Action::Terminate"),
        }
    }
}

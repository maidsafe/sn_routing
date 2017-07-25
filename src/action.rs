// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use error::InterfaceError;
use id::PublicId;
use messages::{Request, UserMessage};
use messages::DirectMessage;
use routing_table::Authority;
use std::fmt::{self, Debug, Formatter};
use std::sync::mpsc::Sender;
use xor_name::XorName;

/// An Action initiates a message flow < A | B > where we are (a part of) A.
///    1. `Action::SendMessage` hands a fully formed `SignedMessage` over to `Core`
///       for it to be sent on across the network.
///    2. `Action::Terminate` indicates to `Core` that no new actions should be taken and all
///       pending events should be handled.
///       After completion `Core` will send `Event::Terminated`.
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
pub enum Action {
    NodeSendMessage {
        src: Authority<XorName>,
        dst: Authority<XorName>,
        content: UserMessage,
        priority: u8,
        result_tx: Sender<Result<(), InterfaceError>>,
    },
    ClientSendRequest {
        content: Request,
        dst: Authority<XorName>,
        priority: u8,
        result_tx: Sender<Result<(), InterfaceError>>,
    },
    Id { result_tx: Sender<PublicId> },
    Timeout(u64),
    ResourceProofResult(PublicId, Vec<DirectMessage>),
    Terminate,
}

impl Debug for Action {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Action::NodeSendMessage { ref content, .. } => {
                write!(
                    formatter,
                    "Action::NodeSendMessage {{ {:?}, result_tx }}",
                    content
                )
            }
            Action::ClientSendRequest {
                ref content,
                ref dst,
                ..
            } => {
                write!(
                    formatter,
                    "Action::ClientSendRequest {{ {:?}, dst: {:?}, result_tx }}",
                    content,
                    dst
                )
            }
            Action::Id { .. } => write!(formatter, "Action::Id"),
            Action::Timeout(token) => write!(formatter, "Action::Timeout({})", token),
            Action::ResourceProofResult(pub_id, _) => {
                write!(formatter, "Action::ResourceProofResult({:?}, ...)", pub_id)
            }
            Action::Terminate => write!(formatter, "Action::Terminate"),
        }
    }
}

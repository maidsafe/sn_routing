// Copyright 2016 MaidSafe.net limited.
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

use super::{MpidHeader, MpidMessage};
use xor_name::XorName;

/// A serialisable wrapper to allow multiplexing all MPID message types and actions via a single
/// type.
#[derive(PartialEq, Eq, Hash, Clone, Debug, Deserialize, Serialize)]
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
pub enum MpidMessageWrapper {
    /// Sent by a Client to its MpidManagers to notify them that it has just connected to the
    /// network.
    Online,
    /// Sent by a Client to its MpidManagers when storing a new `MpidMessage`.
    PutMessage(MpidMessage),
    /// Sent by the sender's MpidManagers to the receiver's MpidManagers to alert them of a new
    /// message.
    PutHeader(MpidHeader),
    /// Sent by the receiver to its MpidManagers to try to retrieve the message corresponding to the
    /// header.
    GetMessage(MpidHeader),
    /// Sent by a Client to its MpidManagers to query whether the provided vector of message names
    /// continue to exist as messages in its outbox.
    OutboxHas(Vec<XorName>),
    /// Sent by MpidManagers to the Client as a response to an `OutboxHas`.  The contents is a
    /// subset of the list provided in the corresponding `OutboxHas`.
    OutboxHasResponse(Vec<MpidHeader>),
    /// Sent by a Client to its MpidManagers to retrieve the list of headers of all messages in its
    /// outbox.
    GetOutboxHeaders,
    /// Sent by MpidManagers to the Client as a response to a `GetOutboxHeaders`.  The contents is
    /// the list of headers of all messages in the outbox.
    GetOutboxHeadersResponse(Vec<MpidHeader>),
    /// Sent by a Client to its MpidManagers to delete the named message from its inbox or outbox.
    DeleteMessage(XorName),
    /// Sent by a receiving Client to the sender's MpidManagers to delete the named message's header
    /// from the sender's outbox.
    DeleteHeader(XorName),
}

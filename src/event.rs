// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use xor_name::XorName;
use types::{ChurnEventId, RefreshAccumulatorValue};
use messages::{RequestMessage, ResponseMessage};
use sodiumoxide::crypto::hash;

/// An Event is received at the effective close group of B of a message flow < A | B >
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Event {
    /// Request.
    Request(RequestMessage),
    /// Response.
    Response(ResponseMessage),
    /// Refresh reports to the user the collected accounts for a given refresh event
    Refresh(hash::sha512::Digest, Vec<RefreshAccumulatorValue>),
    /// Churn reports a change in close group
    Churn(ChurnEventId),
    /// Event fired when all connections to a close group node is lost
    LostCloseNode(XorName),
    /// Connected.
    Connected,
    /// Disconnected.
    Disconnected,
    /// Event::Terminated is called after Core::stop() has terminated internal processes
    Terminated,
}

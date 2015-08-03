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

use authority::Authority;
use data::Data;
use error::{RoutingError, ResponseError};
use messages::{ErrorReturn, GetDataResponse, MessageType, RoutingMessage, SignedMessage};
use name_type::NameType;
use sentinel::pure_sentinel::Source;
use types::{MessageId, SourceAddress, DestinationAddress};

/// An Event is received at the effective close group of B of a message flow < A | B >
///   1. Event::MessageSecured provides the RoutingMessage after being secured by routing,
///      our authority provides the base authority as validated by routing
///   2. Event::Refresh has accumulated Refresh messages centered on a name for a type_tag.
///      This can be used to transfer accounts between nodes of an effective close group.
///   3. Event::Churn occurs when our close group changes.  The new close group is provided.
///      Our close group always contains our own name first.  When we are connected to other
///      nodes the list contains minimally two names.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Event {
    MessageSecured(RoutingMessage, Authority),
    //             ~~|~~~~~~~~~~~  ~~|~~~~~~
    //               |               | our authority as calculated
    //               |               | note: can be removed if we enforce it to be identical
    //               |               |       to RoutingMessage::to_authority
    //               | secured routing message
    Refresh(u64, NameType, Vec<Vec<u8>>),
    //      ~|~  ~~|~~~~~  ~~|~~~~~~~~~
    //       |     |         | payloads
    //       |     | from group
    //       | type tag
    Churn(Vec<NameType>),
    //    ~~|~~~~~~~~~~
    //      | our close group sorted from our name; always including our name
    //      | if size > 1, we are connected to the network
}

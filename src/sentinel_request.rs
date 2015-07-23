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
use messages::{RoutingMessage};
use name_type::NameType;
use sentinel::pure_sentinel::Source;
use types::MessageId;
use data::Data;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct SentinelPutRequest {
    pub data: Data,
    pub source_group: NameType,
    pub destination_group: NameType,
    pub source_authority: Authority,
    pub our_authority: Authority,
    pub message_id: MessageId,
}

impl SentinelPutRequest {
    pub fn new(message: RoutingMessage, data: Data, our_authority: Authority, source_group: NameType)
        -> SentinelPutRequest {
        SentinelPutRequest { data: data,
                             source_group: source_group,
                             destination_group: message.destination.non_relayed_destination(),
                             source_authority: message.authority,
                             our_authority: our_authority,
                             message_id: message.message_id
                           }
    }
}

impl Source<NameType> for SentinelPutRequest {
    fn get_source(&self) -> NameType {
        self.source_group.clone()
    }
}

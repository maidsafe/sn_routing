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

use std::collections::{BTreeMap};

use sodiumoxide::crypto::sign::{PublicKey};

use authority::Authority;
use messages::{ErrorReturn, GetDataResponse, RoutingMessage, SignedMessage};
use name_type::NameType;
use sentinel::pure_sentinel::Source;
use types::{MessageId, SourceAddress, DestinationAddress};
use data::Data;
use messages::MessageType;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct SentinelPutRequest {
    pub data: Data,
    pub source_group: NameType,
    pub destination_group: NameType,
    pub source_authority: Authority,
    pub our_authority: Authority,
    pub message_id: MessageId,
    pub orig_message: SignedMessage,
}

impl SentinelPutRequest {
    pub fn new(message: RoutingMessage, orig_message: SignedMessage, data: Data,
               our_authority: Authority, source_group: NameType) -> SentinelPutRequest {
        SentinelPutRequest { data: data,
                             source_group: source_group,
                             destination_group: message.destination.non_relayed_destination(),
                             source_authority: message.authority,
                             our_authority: our_authority,
                             message_id: message.message_id,
                             orig_message: orig_message
                           }
    }

    pub fn create_forward(&self,
                          src    : NameType,
                          dst    : NameType,
                          msg_id : u32) -> RoutingMessage {
        RoutingMessage {
            destination  : DestinationAddress::Direct(dst),
            source       : SourceAddress::Direct(src),
            orig_message : Some(self.orig_message.clone()),
            message_type : MessageType::PutData(self.data.clone()),
            message_id   : msg_id,
            authority    : self.our_authority.clone(),
        }
    }

    pub fn create_reply(&self, reply_data: MessageType) -> RoutingMessage {
        RoutingMessage {
            destination  :  match self.orig_message.get_routing_message() {
                                Ok(routing_message) => routing_message.reply_destination(),
                                Err(_) => DestinationAddress::Direct(self.source_group),
                            },
            source       : SourceAddress::Direct(self.destination_group),
            orig_message : None,
            message_type : reply_data,
            message_id   : self.message_id,
            authority    : self.our_authority.clone(),
        }
    }
}

impl Source<NameType> for SentinelPutRequest {
    fn get_source(&self) -> NameType {
        self.source_group.clone()
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct SentinelPutResponse {
    pub response: ErrorReturn,
    pub source_group: NameType,
    pub destination_group: NameType,
    pub source_authority: Authority,
    pub our_authority: Authority,
    pub message_id: MessageId,
    pub orig_message: SignedMessage,
}

impl SentinelPutResponse {
    pub fn new(message: RoutingMessage, orig_message: SignedMessage, response: ErrorReturn,
               our_authority: Authority) -> SentinelPutResponse {
        SentinelPutResponse {
            response: response,
            source_group: message.source.non_relayed_source(),
            destination_group: message.destination.non_relayed_destination(),
            source_authority: message.authority,
            our_authority: our_authority,
            message_id: message.message_id,
            orig_message: orig_message
        }
    }
    pub fn create_forward(&self,
                          src               : NameType,
                          group_public_keys : BTreeMap<NameType, PublicKey>,
                          msg_id            : u32) -> RoutingMessage {
        RoutingMessage {
            destination  : DestinationAddress::Direct(self.destination_group),
            source       : SourceAddress::Direct(src),
            orig_message : Some(self.orig_message.clone()),
            message_type : MessageType::PutDataResponse(self.response.clone(),
                                                        group_public_keys),
            message_id   : msg_id,
            authority    : self.our_authority.clone(),
        }
    }
}

impl Source<NameType> for SentinelPutResponse {
    fn get_source(&self) -> NameType {
        self.source_group.clone()
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct SentinelGetDataResponse {
    pub response: GetDataResponse,
    pub source_group: NameType,
    pub destination_group: NameType,
    pub source_authority: Authority,
    pub our_authority: Authority,
    pub message_id: MessageId,
    pub orig_message: SignedMessage,
}

impl SentinelGetDataResponse {
    pub fn new(message: RoutingMessage, orig_message: SignedMessage, response: GetDataResponse,
               our_authority: Authority) -> SentinelGetDataResponse {
        SentinelGetDataResponse {
            response: response,
            source_group: message.source.non_relayed_source(),
            destination_group: message.destination.non_relayed_destination(),
            source_authority: message.authority,
            our_authority: our_authority,
            message_id: message.message_id,
            orig_message: orig_message,
        }
    }
    pub fn create_forward(&self,
                          src    : NameType,
                          msg_id : u32) -> RoutingMessage {
        RoutingMessage {
            destination  : DestinationAddress::Direct(self.destination_group),
            source       : SourceAddress::Direct(src),
            orig_message : Some(self.orig_message.clone()),
            message_type : MessageType::GetDataResponse(self.response.clone()),
            message_id   : msg_id,
            authority    : self.our_authority.clone(),
        }
    }
}

impl Source<NameType> for SentinelGetDataResponse {
    fn get_source(&self) -> NameType {
        self.source_group.clone()
    }
}

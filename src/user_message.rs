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
use error::{RoutingError, ResponseError};
use messages::{ErrorReturn, GetDataResponse, RoutingMessage, SignedMessage};
use name_type::NameType;
use sentinel::pure_sentinel::Source;
use types::{MessageId, SourceAddress, DestinationAddress};
use data::Data;
use messages::MessageType;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Event {
    PutRequest(SignedMessage, Data, NameType, NameType, Authority, Authority, MessageId),
}

impl Event {
    pub fn create_forward(&self, source: NameType, destination: NameType, msg_id : u32)
        -> Result<RoutingMessage, RoutingError> {
        match self {
            &Event::PutRequest(ref orig_message, ref data, ref source_group,
                               ref _destination_group, ref source_authority,
                               ref our_authority, ref _message_id) =>
            {
                return Ok(RoutingMessage {
                    destination  : DestinationAddress::Direct(destination),
                    source       : SourceAddress::Direct(source),
                    orig_message : Some(orig_message.clone()),
                    message_type : MessageType::PutData(data.clone()),
                    message_id   : msg_id,
                    authority    : our_authority.clone(),
                })
            },
        }
        return Err(RoutingError::RefreshNotFromGroup)    // TODO use the proper error code
    }

    pub fn create_reply(&self, reply_data: MessageType)
        -> Result<RoutingMessage, RoutingError> {
        match self {
            &Event::PutRequest(ref orig_message, ref data, ref source_group, ref destination_group,
                               ref source_authority, ref our_authority, ref message_id) => {
                return Ok(RoutingMessage {
                    destination  : match orig_message.get_routing_message() {
                                        Ok(routing_message) => routing_message.reply_destination(),
                                        Err(_) => DestinationAddress::Direct(source_group.clone()),
                                   },
                    source       : SourceAddress::Direct(destination_group.clone()),
                    orig_message : None,
                    message_type : reply_data,
                    message_id   : message_id.clone(),
                    authority    : our_authority.clone()
                })
            },
        }
        Err(RoutingError::RefreshNotFromGroup)    // TODO use the proper error code
    }

    pub fn get_orig_message(&self) -> Result<SignedMessage, RoutingError> {
        match self {
            &Event::PutRequest(ref orig_message, _, _, _, _, _, _) => Ok(orig_message.clone())
        }
    }
}

impl Source<NameType> for Event {
    fn get_source(&self) -> NameType {
        match self {
            &Event::PutRequest(_, _, source_group, _, _, _, _) => source_group
        }
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
            message_type : MessageType::PutDataResponse(self.response.clone(), group_public_keys),
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

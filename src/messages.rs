// Copyright 2015 MaidSafe.net limited
//
// This Safe Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the Safe Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://maidsafe.net/network-platform-licensing
//
// Unless required by applicable law or agreed to in writing, the Safe Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations relating to
// use of the Safe Network Software.

#![allow(unused_assignments)]

#[path="messages/connect_request.rs"]
pub mod connect_request;
#[path="messages/connect_response.rs"]
pub mod connect_response;
#[path="messages/connect_success.rs"]
pub mod connect_success;
#[path="messages/find_group.rs"]
pub mod find_group;
#[path="messages/find_group_response.rs"]
pub mod find_group_response;
#[path="messages/get_client_key.rs"]
pub mod get_client_key;
#[path="messages/get_client_key_response.rs"]
pub mod get_client_key_response;
#[path="messages/get_data.rs"]
pub mod get_data;
#[path="messages/get_data_response.rs"]
pub mod get_data_response;
#[path="messages/get_group_key.rs"]
pub mod get_group_key;
#[path="messages/get_group_key_response.rs"]
pub mod get_group_key_response;
#[path="messages/post.rs"]
pub mod post;
#[path="messages/put_data.rs"]
pub mod put_data;
#[path="messages/put_data_response.rs"]
pub mod put_data_response;


use cbor;
use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};

use message_header;
use types;

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum MessageTypeTag {
    ConnectRequest,
    ConnectResponse,
    FindGroup,
    FindGroupResponse,
    GetData,
    GetDataResponse,
    GetClientKey,
    GetClientKeyResponse,
    GetGroupKey,
    GetGroupKeyResponse,
    Post,
    PostResponse,
    PutData,
    PutDataResponse,
    PutKey,
    AccountTransfer,
    Unknown,
}

impl Encodable for MessageTypeTag {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        let mut type_tag = "";
        match *self {
            MessageTypeTag::ConnectRequest => type_tag = "ConnectRequest",
            MessageTypeTag::ConnectResponse => type_tag = "ConnectResponse",
            MessageTypeTag::FindGroup => type_tag = "FindGroup",
            MessageTypeTag::FindGroupResponse => type_tag = "FindGroupResponse",
            MessageTypeTag::GetData => type_tag = "GetData",
            MessageTypeTag::GetDataResponse => type_tag = "GetDataResponse",
            MessageTypeTag::GetClientKey => type_tag = "GetClientKey",
            MessageTypeTag::GetClientKeyResponse => type_tag = "GetClientKeyResponse",
            MessageTypeTag::GetGroupKey => type_tag = "GetGroupKey",
            MessageTypeTag::GetGroupKeyResponse => type_tag = "GetGroupKeyResponse",
            MessageTypeTag::Post => type_tag = "Post",
            MessageTypeTag::PostResponse => type_tag = "PostResponse",
            MessageTypeTag::PutData => type_tag = "PutData",
            MessageTypeTag::PutDataResponse => type_tag = "PutDataResponse",
            MessageTypeTag::PutKey => type_tag = "PutKey",
            MessageTypeTag::AccountTransfer => type_tag = "AccountTransfer",
                MessageTypeTag::Unknown => type_tag = "Unknown",
        };
        CborTagEncode::new(5483_100, &(&type_tag)).encode(e)
    }
}

impl Decodable for MessageTypeTag {
    fn decode<D: Decoder>(d: &mut D)->Result<MessageTypeTag, D::Error> {
        try!(d.read_u64());
        let mut type_tag : String = String::new();
        type_tag = try!(Decodable::decode(d));
        match &type_tag[..] {
            "ConnectRequest" => Ok(MessageTypeTag::ConnectRequest),
            "ConnectResponse" => Ok(MessageTypeTag::ConnectResponse),
            "FindGroup" => Ok(MessageTypeTag::FindGroup),
            "FindGroupResponse" => Ok(MessageTypeTag::FindGroupResponse),
            "GetData" => Ok(MessageTypeTag::GetData),
            "GetDataResponse" => Ok(MessageTypeTag::GetDataResponse),
            "GetClientKey" => Ok(MessageTypeTag::GetClientKey),
            "GetClientKeyResponse" => Ok(MessageTypeTag::GetClientKeyResponse),
            "GetGroupKey" => Ok(MessageTypeTag::GetGroupKey),
            "GetGroupKeyResponse" => Ok(MessageTypeTag::GetGroupKeyResponse),
            "Post" => Ok(MessageTypeTag::Post),
            "PostResponse" => Ok(MessageTypeTag::PostResponse),
            "PutData" => Ok(MessageTypeTag::PutData),
            "PutDataResponse" => Ok(MessageTypeTag::PutDataResponse),
            "PutKey" => Ok(MessageTypeTag::PutKey),
            "AccountTransfer" => Ok(MessageTypeTag::AccountTransfer),
                _ => Ok(MessageTypeTag::Unknown)
        }
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct RoutingMessage {
    pub message_type: MessageTypeTag,
    pub message_header: message_header::MessageHeader,
    pub serialised_body: Vec<u8>,
}

impl Encodable for RoutingMessage {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        CborTagEncode::new(5483_001, &(&self.message_type, &self.message_header, &self.serialised_body)).encode(e)
    }
}

impl Decodable for RoutingMessage {
    fn decode<D: Decoder>(d: &mut D)->Result<RoutingMessage, D::Error> {
        try!(d.read_u64());
        let (message_type, message_header, serialised_body) = try!(Decodable::decode(d));
        Ok(RoutingMessage { message_type: message_type, message_header: message_header, serialised_body: serialised_body })
    }
}

impl RoutingMessage {
    pub fn dummy_new(message_type: MessageTypeTag,
                     message_header: message_header::MessageHeader) -> RoutingMessage {
        RoutingMessage { message_type: message_type, message_header: message_header, serialised_body: Vec::<u8>::new() }
    }

    pub fn new<T>(message_type: MessageTypeTag, message_header: message_header::MessageHeader,
                  message : T) -> RoutingMessage where T: for<'a> Encodable + Decodable {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&message]).unwrap();
        RoutingMessage { message_type: message_type, message_header: message_header,
        serialised_body: types::array_as_vector(e.as_bytes()) }
    }

    pub fn get_message_body<T>(&self) -> T where T: for<'a> Encodable + Decodable {
        let mut d = cbor::Decoder::from_bytes(&self.serialised_body[..]);
        let obj: T = d.decode().next().unwrap().unwrap();
        obj
    }

    pub fn set_message_body<T>(&mut self, message: T) where T: for<'a> Encodable + Decodable {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&message]).unwrap();
        self.serialised_body = e.as_bytes().to_vec()
    }
}
#[test]
fn dummy()  {
}

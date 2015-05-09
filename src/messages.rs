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

#![allow(unused_assignments)]

#[path="messages/bootstrap_id_request.rs"]
pub mod bootstrap_id_request;
#[path="messages/bootstrap_id_response.rs"]
pub mod bootstrap_id_response;
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
#[path="messages/get_key.rs"]
pub mod get_client_key;
#[path="messages/get_key_response.rs"]
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
#[path="messages/put_public_id.rs"]
pub mod put_public_id;



use cbor;
use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use sodiumoxide::crypto;

use message_header;
use types;

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum MessageTypeTag {
    BootstrapIdRequest,
    BootstrapIdResponse,
    ConnectRequest,
    ConnectResponse,
    FindGroup,
    FindGroupResponse,
    GetData,
    GetDataResponse,
    GetKey,
    GetKeyResponse,
    GetGroupKey,
    GetGroupKeyResponse,
    Post,
    PostResponse,
    PutData,
    PutDataResponse,
    UnauthorisedPut,
    PutKey,
    AccountTransfer,
    PutPublicId,
    Unknown,
}

impl Encodable for MessageTypeTag {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        let mut type_tag = "";
        match *self {
            MessageTypeTag::BootstrapIdRequest => type_tag = "BootstrapIdRequest",
            MessageTypeTag::BootstrapIdResponse => type_tag = "BootstrapIdResponse",
            MessageTypeTag::ConnectRequest => type_tag = "ConnectRequest",
            MessageTypeTag::ConnectResponse => type_tag = "ConnectResponse",
            MessageTypeTag::FindGroup => type_tag = "FindGroup",
            MessageTypeTag::FindGroupResponse => type_tag = "FindGroupResponse",
            MessageTypeTag::GetData => type_tag = "GetData",
            MessageTypeTag::GetDataResponse => type_tag = "GetDataResponse",
            MessageTypeTag::GetKey => type_tag = "GetKey",
            MessageTypeTag::GetKeyResponse => type_tag = "GetKeyResponse",
            MessageTypeTag::GetGroupKey => type_tag = "GetGroupKey",
            MessageTypeTag::GetGroupKeyResponse => type_tag = "GetGroupKeyResponse",
            MessageTypeTag::Post => type_tag = "Post",
            MessageTypeTag::PostResponse => type_tag = "PostResponse",
            MessageTypeTag::PutData => type_tag = "PutData",
            MessageTypeTag::PutDataResponse => type_tag = "PutDataResponse",
            MessageTypeTag::UnauthorisedPut => type_tag = "UnauthorisedPut",
            MessageTypeTag::PutKey => type_tag = "PutKey",
            MessageTypeTag::AccountTransfer => type_tag = "AccountTransfer",
            MessageTypeTag::PutPublicId => type_tag = "PutPublicId",
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
            "BootstrapIdRequest" => Ok(MessageTypeTag::BootstrapIdRequest),
            "BootstrapIdResponse" => Ok(MessageTypeTag::BootstrapIdResponse),
            "ConnectRequest" => Ok(MessageTypeTag::ConnectRequest),
            "ConnectResponse" => Ok(MessageTypeTag::ConnectResponse),
            "FindGroup" => Ok(MessageTypeTag::FindGroup),
            "FindGroupResponse" => Ok(MessageTypeTag::FindGroupResponse),
            "GetData" => Ok(MessageTypeTag::GetData),
            "GetDataResponse" => Ok(MessageTypeTag::GetDataResponse),
            "GetKey" => Ok(MessageTypeTag::GetKey),
            "GetKeyResponse" => Ok(MessageTypeTag::GetKeyResponse),
            "GetGroupKey" => Ok(MessageTypeTag::GetGroupKey),
            "GetGroupKeyResponse" => Ok(MessageTypeTag::GetGroupKeyResponse),
            "Post" => Ok(MessageTypeTag::Post),
            "PostResponse" => Ok(MessageTypeTag::PostResponse),
            "PutData" => Ok(MessageTypeTag::PutData),
            "PutDataResponse" => Ok(MessageTypeTag::PutDataResponse),
            "UnauthorisedPut" => Ok(MessageTypeTag::UnauthorisedPut),
            "PutKey" => Ok(MessageTypeTag::PutKey),
            "PutPublicId" => Ok(MessageTypeTag::PutPublicId),
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
    pub signature : types::Signature
}

impl Encodable for RoutingMessage {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        CborTagEncode::new(5483_001, &(&self.message_type, &self.message_header,
            &self.serialised_body, &self.signature)).encode(e)
    }
}

impl Decodable for RoutingMessage {
    fn decode<D: Decoder>(d: &mut D)->Result<RoutingMessage, D::Error> {
        try!(d.read_u64());
        let (message_type, message_header, serialised_body, signature) = try!(Decodable::decode(d));
        Ok(RoutingMessage { message_type: message_type, message_header: message_header,
            serialised_body: serialised_body, signature : signature })
    }
}

impl RoutingMessage {
    // pub fn dummy_new(message_type: MessageTypeTag,
    //                  message_header: message_header::MessageHeader) -> RoutingMessage {
    //     RoutingMessage { message_type: message_type, message_header: message_header, serialised_body: Vec::<u8>::new() }
    // }

    pub fn new<T>(message_type: MessageTypeTag, message_header: message_header::MessageHeader,
                  message : T, private_sign_key : &crypto::sign::SecretKey) -> RoutingMessage where T: for<'a> Encodable + Decodable {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&message]).unwrap();
        let signature = types::Signature::new(crypto::sign::sign_detached(&e.as_bytes(),
                                              &private_sign_key));
        RoutingMessage {
            message_type: message_type,
            message_header: message_header,
            serialised_body: types::array_as_vector(e.as_bytes()),
            signature: signature }
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

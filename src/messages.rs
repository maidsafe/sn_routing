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

use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use sodiumoxide::crypto::sign::Signature;
use sodiumoxide::crypto::sign;
use crust::Endpoint;
use authority::Authority;
use data::{Data, DataRequest};
use types;
use public_id::PublicId;
use types::{DestinationAddress, SourceAddress};
use error::{ResponseError};
use NameType;
use utils;
use cbor::{CborError};

#[derive(PartialEq, Eq, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct ConnectRequest {
    pub local_endpoints: Vec<Endpoint>,
    pub external_endpoints: Vec<Endpoint>,
    // TODO: redundant, already in fob
    pub requester_id: NameType,
    // TODO: make optional, for now simply ignore if requester_fob is not relocated
    pub receiver_id: NameType,
    pub requester_fob: PublicId
}

#[derive(PartialEq, Eq, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct ConnectResponse {
    pub requester_local_endpoints: Vec<Endpoint>,
    pub requester_external_endpoints: Vec<Endpoint>,
    pub receiver_local_endpoints: Vec<Endpoint>,
    pub receiver_external_endpoints: Vec<Endpoint>,
    pub requester_id: NameType,
    pub receiver_id: NameType,
    pub receiver_fob: PublicId,
    pub serialised_connect_request: Vec<u8>,
    pub connect_request_signature: Signature
}

// Unfortunately the Result type is not (yet?) encodable/decodable
// so we need to create this wrapper.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetDataResponse {
    pub result       : Result<Data, ResponseError>,
    pub orig_request : SignedMessage,
}

impl GetDataResponse {
    pub fn verify_request_came_from(&self, requester_pub_key: &sign::PublicKey) -> bool {
        self.orig_request.verify_signature(requester_pub_key)
    }
}

impl Encodable for GetDataResponse {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_enum("GetDataResponse", |s| {
            match self.result {
                // Not sure what the third argument to the `emit_enum_variant`
                // function is meant to be, currently it is ignored.
                Ok(ref data) => s.emit_enum_variant("Ok",  0, 1, |s| data.encode(s)),
                Err(ref err) => s.emit_enum_variant("Err", 1, 1, |s| err.encode(s))
            }
        })
    }
}

impl Decodable for GetDataResponse {
    fn decode<D: Decoder>(d: &mut D) -> Result<GetDataResponse, D::Error> {
        d.read_enum("GetDataResponse", move |d| {
            d.read_enum_variant(&["Ok", "Err"], move |d, idx| {
                match idx {
                    0 => Ok(GetDataResponse { result: Ok(try!(Decodable::decode(d))),
                                              orig_request: try!(Decodable::decode(d)) }),
                    1 => Ok(GetDataResponse { result: Err(try!(Decodable::decode(d))),
                                              orig_request: try!(Decodable::decode(d)) }),
                    _ => {
                        Err(d.error("Expected Ok or Err"))
                    }
                }
            })
        })
    }
}

/// Response error which can be verified that originated from our request.
#[derive(PartialEq, Eq, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct ErrorReturn {
    pub error: ResponseError,
    pub orig_request: SignedMessage
}

impl ErrorReturn {
    #[allow(dead_code)]
    pub fn new(error: ResponseError, orig_request: SignedMessage) -> ErrorReturn {
        ErrorReturn {
            error        : error,
            orig_request : orig_request,
        }
    }

    pub fn verify_request_came_from(&self, requester_pub_key: &sign::PublicKey) -> bool {
        self.orig_request.verify_signature(requester_pub_key)
    }
}

/// These are the messageTypes routing provides
/// many are internal to routing and woudl not be useful
/// to users.
#[derive(PartialEq, Eq, Clone, Debug, RustcEncodable, RustcDecodable)]
pub enum MessageType {
    ConnectRequest(ConnectRequest),
    ConnectResponse(ConnectResponse),
    FindGroup(NameType /* Redundant, it's already in the destination */),
    FindGroupResponse(Vec<PublicId>),
    GetData(DataRequest),
    GetDataResponse(GetDataResponse),
    DeleteData(DataRequest),
    DeleteDataResponse(ErrorReturn),
    GetKey,
    GetKeyResponse(NameType, sign::PublicKey),
    GetGroupKey,
    GetGroupKeyResponse(Vec<(NameType, sign::PublicKey)>),
    Post(Data),
    PostResponse(ErrorReturn),
    PutData(Data),
    PutDataResponse(ErrorReturn),
    PutKey,
    PutPublicId(PublicId),
    PutPublicIdResponse(PublicId),
    Refresh(u64, Vec<u8>),
    Unknown,
}

/// the bare (unsigned) routing message
#[derive(PartialEq, Eq, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct RoutingMessage {
    pub destination     : DestinationAddress,
    pub source          : SourceAddress,
    // orig_message represents original message when this is forwarded
    // from a client or single node
    pub orig_message    : Option<SignedMessage>,
    pub message_type    : MessageType,
    pub message_id      : types::MessageId,
    pub authority       : Authority
}

impl RoutingMessage {

    #[allow(dead_code)]
    pub fn message_id(&self) -> types::MessageId {
        self.message_id.clone()
    }

    pub fn source_address(&self) -> SourceAddress {
        self.source.clone()
    }

    pub fn destination_address(&self) -> DestinationAddress {
        self.destination.clone()
    }

    pub fn non_relayed_source(&self) -> NameType {
        self.source.non_relayed_source()
    }

    #[allow(dead_code)]
    pub fn actual_source(&self) -> types::Address {
       self.source.actual_source()
    }

    pub fn non_relayed_destination(&self) -> NameType {
        self.destination.non_relayed_destination()
    }

    // FIXME: add from_authority to filter value
    pub fn get_filter(&self) -> types::FilterType {
        (self.source.clone(), self.message_id, self.destination.clone())
    }

    pub fn from_authority(&self) -> Authority {
        self.authority.clone()
    }

    pub fn client_key(&self) -> Option<sign::PublicKey> {
        match self.source {
            SourceAddress::RelayedForClient(_, client_key) => Some(client_key),
            SourceAddress::RelayedForNode(_, _)            => None,
            SourceAddress::Direct(_)                       => None,
        }
    }

    pub fn client_key_as_name(&self) -> Option<NameType> {
        self.client_key().map(|n|utils::public_key_to_client_name(&n))
    }

    pub fn from_group(&self) -> Option<NameType /* Group name */> {
        match self.source {
            SourceAddress::RelayedForClient(_, _) => None,
            SourceAddress::RelayedForNode(_, _)   => None,
            SourceAddress::Direct(_) => match self.authority {
                Authority::ClientManager(n) => Some(n),
                Authority::NaeManager(n)    => Some(n),
                Authority::NodeManager(n)   => Some(n),
                Authority::ManagedNode      => None,
                Authority::ManagedClient(_) => None,
                Authority::Client(_)        => None,
                Authority::Unknown          => None,
            },
        }
    }

    /// This creates a new message for Action::Forward. It clones all the fields,
    /// and then mutates the destination and source accordingly.
    /// Authority is changed at this point as this method is called after
    /// the interface has processed the message.
    /// Note: this is not for XOR-forwarding; then the header is preserved!
    pub fn create_forward(&self,
                          our_name      : NameType,
                          our_authority : Authority,
                          destination   : NameType,
                          orig_signed_message  : SignedMessage) -> RoutingMessage {

        // implicitly preserve all non-mutated fields.
        let mut forward_message = self.clone();
        // if we are sending on and the original message is not stored
        // then store it and preserve along the route
        // it will contain the address to reply to as well as proof the request was made
        // FIXME(dirvine) We need the original encoded signed message here  :13/07/2015
        // FIXME(ben) only attach when from client or node 15/07/2015
        if self.orig_message.is_none() {
            forward_message.orig_message = Some(orig_signed_message);
        }

        forward_message.source      = SourceAddress::Direct(our_name);
        forward_message.destination = DestinationAddress::Direct(destination);
        forward_message.authority   = our_authority;
        forward_message
    }

    /// This creates a new message for Action::Reply. It clones all the fields,
    /// and then mutates the destination and source accordingly.
    /// Authority is changed at this point as this method is called after
    /// the interface has processed the message.
    /// Note: this is not for XOR-forwarding; then the header is preserved!
    pub fn create_reply(&self, _our_name : &NameType, _our_authority : &Authority)
        -> RoutingMessage {
        // Commented the below code as it doesn't compile.
        unimplemented!()
        //// implicitly preserve all non-mutated fields.
        //// TODO(dirvine) Again why copy here instead of change in place?  :08/07/2015
        //let mut reply_message     = self.clone();
        //if self.orig_message.is_some() {
        //   reply_message.destination = try!(self.orig_message.get_routing_message()).reply_destination();
        //} else {
        //   reply_message.destination = self.reply_destination();
        //}
        //reply_message.source      = SourceAddress::Direct(our_name.clone());
        //reply_message.authority   = our_authority.clone();
        //reply_message
    }

    pub fn reply_destination(&self) -> DestinationAddress {
        match self.source {
            SourceAddress::RelayedForClient(a, b) => DestinationAddress::RelayToClient(a, b),
            SourceAddress::RelayedForNode(a, b)   => DestinationAddress::RelayToNode(a, b),
            SourceAddress::Direct(a)              => DestinationAddress::Direct(a),
        }
    }

}

/// All messages sent / received are constructed from this type
#[derive(PartialEq, Eq, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct SignedMessage {
    encoded_body: Vec<u8>,
    signature:    Signature,
}

impl SignedMessage {
    pub fn new(message: &RoutingMessage, private_sign_key: &sign::SecretKey)
        -> Result<SignedMessage, CborError> {

        let encoded_body = try!(utils::encode(&message));
        let signature    = sign::sign_detached(&encoded_body, private_sign_key);

        Ok(SignedMessage {
            encoded_body: encoded_body,
            signature:    signature
        })
    }

    pub fn verify_signature(&self, public_sign_key: &sign::PublicKey) -> bool {
        sign::verify_detached(&self.signature,
                              &self.encoded_body,
                              &public_sign_key)
    }

    pub fn get_routing_message(&self) -> Result<RoutingMessage, CborError> {
        utils::decode::<RoutingMessage>(&self.encoded_body)
    }

    pub fn encoded_body(&self) -> &Vec<u8> {
        &self.encoded_body
    }

    pub fn signature(&self) -> &Signature { &self.signature }
}

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

use sodiumoxide::crypto::sign::Signature;
use sodiumoxide::crypto::sign;
use std::fmt::{Debug, Formatter, Error};
use cbor::CborError;
use std::collections::BTreeMap;
use ::rand::Rng;

use crust::Endpoint;

use authority::Authority;
use data::{Data, DataRequest};
use types;
use public_id::PublicId;
use error::ResponseError;
use NameType;
use utils;

pub static VERSION_NUMBER : u8 = 0;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct ConnectRequest {
    pub local_endpoints: Vec<Endpoint>,
    pub external_endpoints: Vec<Endpoint>,
    pub requester_fob: PublicId,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct ConnectResponse {
    pub local_endpoints: Vec<Endpoint>,
    pub external_endpoints: Vec<Endpoint>,
    pub receiver_fob: PublicId,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, RustcEncodable, RustcDecodable)]
pub struct SignedToken {
    pub serialised_request: Vec<u8>,
    pub signature: Signature,
}

impl SignedToken {
    pub fn verify_signature(&self, public_sign_key: &sign::PublicKey) -> bool {
        sign::verify_detached(&self.signature, &self.serialised_request, &public_sign_key)
    }
}

impl Debug for SignedToken {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), Error> {
        formatter.write_str(&format!("SignedToken"))
    }
}
/// These are the messageTypes routing provides
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub enum ExternalRequest {
    Get(DataRequest, u8),
    Put(Data),
    Post(Data),
    Delete(Data),
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub enum ExternalResponse {
    // TODO: Technical depth: if the third param here is Some(...) then
    // the it shares most of the data with the second argument, which
    // needlessly increases bandwidth.
    Get(Data, DataRequest, Option<SignedToken>),
    Put(ResponseError, Option<SignedToken>),
    Post(ResponseError, Option<SignedToken>),
    Delete(ResponseError, Option<SignedToken>),
}

impl ExternalResponse {
    // If the *request* was from a group entity, then there is
    // no signed token.
    pub fn get_signed_token(&self) -> &Option<SignedToken> {
        match *self {
            ExternalResponse::Get(_, _, ref r) => r,
            ExternalResponse::Put(_, ref r) => r,
            ExternalResponse::Post(_, ref r) => r,
            ExternalResponse::Delete(_, ref r) => r,
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub enum InternalRequest {
    Connect(ConnectRequest),
    RequestNetworkName(PublicId),
    // a client can send RequestNetworkName
    CacheNetworkName(PublicId, SignedToken),
    //               ~~|~~~~~  ~~|~~~~~~~~
    //                 |         | SignedToken contains Request::RequestNetworkName and needs to
    //                 |         | be forwarded in the Request::CacheNetworkName;
    //                 |         | from it the original reply to authority can be read.
    //                 | contains the PublicId from RequestNetworkName, but mutated with
    //                 | the network assigned name
    Refresh(u64, Vec<u8>),
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub enum InternalResponse {
    Connect(ConnectResponse, SignedToken),
    // FindGroup(Vec<PublicId>, SignedToken),
    // GetGroupKey(BTreeMap<NameType, sign::PublicKey>, SignedToken),
    CacheNetworkName(PublicId, Vec<PublicId>, SignedToken),
    //               ~~|~~~~~  ~~|~~~~~~~~~~  ~~|~~~~~~~~
    //                 |         |              | the original Request::RequestNetworkName
    //                 |         | the group public keys to combine FindGroup in this response
    //                 | the cached PublicId in the group
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub enum Content {
    ExternalRequest(ExternalRequest),
    InternalRequest(InternalRequest),
    ExternalResponse(ExternalResponse),
    InternalResponse(InternalResponse),
}

/// the bare (unsigned) routing message
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct RoutingMessage {
    // version_number     : u8
    pub from_authority: Authority,
    pub to_authority: Authority,
    pub content: Content,
}

impl RoutingMessage {

    #[allow(dead_code)]
    pub fn source(&self) -> Authority {
        self.from_authority.clone()
    }

    pub fn destination(&self) -> Authority {
        self.to_authority.clone()
    }

    pub fn client_key(&self) -> Option<sign::PublicKey> {
        match self.from_authority {
            Authority::ClientManager(_) => None,
            Authority::NaeManager(_) => None,
            Authority::NodeManager(_) => None,
            Authority::ManagedNode(_) => None,
            Authority::Client(_, key) => Some(key),
        }
    }

    pub fn client_key_as_name(&self) -> Option<NameType> {
        self.client_key().map(|n|utils::public_key_to_client_name(&n))
    }

    pub fn from_group(&self) -> Option<NameType> {
        match self.from_authority {
            Authority::ClientManager(name) => Some(name),
            Authority::NaeManager(name) => Some(name),
            Authority::NodeManager(name) => Some(name),
            Authority::ManagedNode(_) => None,
            Authority::Client(_, _) => None,
        }
    }
}

/// All messages sent / received are constructed as signed message.
#[derive(PartialEq, Eq, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct SignedMessage {
    body: RoutingMessage,
    claimant: types::Address,
    //          when signed by Client(sign::PublicKey) the data needs to contain it as
    // an owner
    //          when signed by a Node(NameType), Sentinel needs to validate the
    // signature
    random_bits: u8,
    signature: Signature,
}

impl SignedMessage {
    pub fn new(claimant: types::Address,
               message: RoutingMessage,
               private_sign_key: &sign::SecretKey)
               -> Result<SignedMessage, CborError> {

        let mut rng = ::rand::thread_rng();
        let random_bits = rng.gen::<u8>();
        let encoded_body = try!(utils::encode(&(&message, &claimant, &random_bits)));
        let signature    = sign::sign_detached(&encoded_body, private_sign_key);

        Ok(SignedMessage { body: message, claimant: claimant,
            random_bits: random_bits, signature: signature })
    }

    pub fn with_signature(claimant: types::Address,
                          message: RoutingMessage,
                          random_bits: u8,
                          signature: Signature)
                          -> Result<SignedMessage, CborError> {

        Ok(SignedMessage { body: message, claimant: claimant,
              random_bits: random_bits, signature: signature })
    }

    pub fn new_from_token(signed_token: SignedToken) -> Result<SignedMessage, CborError> {
        let (message, claimant, random_bits) =
            try!(utils::decode(&signed_token.serialised_request));

        Ok(SignedMessage { body: message, claimant: claimant,
            random_bits: random_bits, signature: signed_token.signature })
    }

    pub fn verify_signature(&self, public_sign_key: &sign::PublicKey) -> bool {
        let encoded_body = match utils::encode(&(&self.body, &self.claimant,
            &self.random_bits)) {
            Ok(x) => x,
            Err(_) => return false,
        };

        sign::verify_detached(&self.signature, &encoded_body, public_sign_key)
    }

    pub fn get_routing_message(&self) -> &RoutingMessage {
        &self.body
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn encoded_body(&self) -> Result<Vec<u8>, CborError> {
        utils::encode(&(&self.body, &self.claimant, &self.random_bits))
    }

    pub fn as_token(&self) -> Result<SignedToken, CborError> {
        Ok(SignedToken {
                serialised_request: try!(self.encoded_body()),
                signature: self.signature().clone(),
            })
    }

    pub fn claimant(&self) -> &types::Address {
        &self.claimant
    }
}


#[cfg(test)]
mod test{

    // TODO Brian: Find a unique access point for the following fn's, repeated in filter.rs.
    fn generate_random_u8() -> u8 {
        use rand::Rng;

        let mut rng = ::rand::thread_rng();
        rng.gen::<u8>()
    }

    fn generate_random_vec() -> ::std::vec::Vec<u8> {
        use rand::Rng;

        let size = 1025;
        let mut data = ::std::vec::Vec::with_capacity(size);
        let mut rng = ::rand::thread_rng();
        for _ in 0..size {
            data.push(rng.gen::<u8>());
        }
        data
    }

    fn generate_random_authority(name: ::NameType, key: &::sodiumoxide::crypto::sign::PublicKey)
            -> ::authority::Authority {
        use rand::distributions::IndependentSample;
        use rand::Rng;

        let mut rng = ::rand::thread_rng();
        let range = ::rand::distributions::Range::new(0, 5);
        let index = range.ind_sample(&mut rng);

        match index {
            0 => return ::authority::Authority::ClientManager(name),
            1 => return ::authority::Authority::NaeManager(name),
            2 => return ::authority::Authority::NodeManager(name),
            3 => return ::authority::Authority::ManagedNode(name),
            4 => return ::authority::Authority::Client(name, key.clone()),
            _ => panic!("Unexpected index.")
        }
    }

    fn generate_random_data(public_sign_key: &::sodiumoxide::crypto::sign::PublicKey,
                            secret_sign_key: &::sodiumoxide::crypto::sign::SecretKey)
            -> ::data::Data {
        use rand::distributions::IndependentSample;
        use rand::Rng;

        let mut rng = ::rand::thread_rng();
        let range = ::rand::distributions::Range::new(0, 3);
        let index = range.ind_sample(&mut rng);

        match index {
            0 => {
                let structured_data =
                    match ::structured_data::StructuredData::new(0,
                                ::test_utils::Random::generate_random(), 0, vec![],
                                vec![public_sign_key.clone()], vec![], Some(&secret_sign_key)) {
                        Ok(structured_data) => structured_data,
                        Err(error) => panic!("StructuredData error: {:?}", error),
                };
                return ::data::Data::StructuredData(structured_data)
            },
            1 => {
                let type_tag = ::immutable_data::ImmutableDataType::Normal;
                let immutable_data =
                        ::immutable_data::ImmutableData::new(type_tag, generate_random_vec());
                return ::data::Data::ImmutableData(immutable_data)
            },
            2 => {
                let plain_data = ::plain_data::PlainData::new(
                        ::test_utils::Random::generate_random(), generate_random_vec());
                return ::data::Data::PlainData(plain_data)
            },
            _ => panic!("Unexpected index.")
        }
    }

    // TODO Brian: Randomize Content and rename to random_routing_message.
    fn arbtrary_routing_message(public_key: &::sodiumoxide::crypto::sign::PublicKey,
                              secret_key: &::sodiumoxide::crypto::sign::SecretKey)
            -> super::RoutingMessage {
        let from_authority =
                generate_random_authority(::test_utils::Random::generate_random(), public_key);
        let to_authority =
                generate_random_authority(::test_utils::Random::generate_random(), public_key);
        let data = generate_random_data(public_key, secret_key);
        let content = super::Content::ExternalRequest(super::ExternalRequest::Put(data));

        super::RoutingMessage {
            from_authority: from_authority,
            to_authority: to_authority,
            content: content,
        }
    }

    #[test]
    fn signed_message_new() {
        let claimant = ::types::Address::Node(::test_utils::Random::generate_random());
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message = arbtrary_routing_message(&keys.0, &keys.1);
        let signed_message =
            super::SignedMessage::new(claimant.clone(), routing_message.clone(), &keys.1);

        assert!(signed_message.is_ok());

        let signed_message = signed_message.unwrap();

        assert_eq!(signed_message.get_routing_message(), &routing_message);
        assert_eq!(signed_message.claimant(), &claimant);

        let encoded_body = signed_message.encoded_body();

        assert!(encoded_body.is_ok());

        let encoded_body = encoded_body.unwrap();
        let signature = ::sodiumoxide::crypto::sign::sign_detached(&encoded_body, &keys.1);

        assert_eq!(signed_message.signature(), &signature);
        assert!(signed_message.verify_signature(&keys.0));
    }

    #[test]
    fn invalid_signed_message_new() {
        let claimant = ::types::Address::Node(::test_utils::Random::generate_random());
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message = arbtrary_routing_message(&keys.0, &keys.1);
        let invalid_keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let signed_message =
            super::SignedMessage::new(claimant.clone(), routing_message.clone(), &invalid_keys.1);

        assert!(signed_message.is_ok());

        let signed_message = signed_message.unwrap();

        assert_eq!(signed_message.get_routing_message(), &routing_message);
        assert_eq!(signed_message.claimant(), &claimant);

        let encoded_body = signed_message.encoded_body();

        assert!(encoded_body.is_ok());

        let encoded_body = encoded_body.unwrap();
        let signature = ::sodiumoxide::crypto::sign::sign_detached(&encoded_body, &keys.1);

        assert!(signed_message.signature() != &signature);
        assert!(!signed_message.verify_signature(&keys.0));
    }

    #[test]
    fn signed_message_with_signature() {
        let claimant = ::types::Address::Node(::test_utils::Random::generate_random());
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message = arbtrary_routing_message(&keys.0, &keys.1);
        let random_bits = generate_random_u8();
        let encoded_body = ::utils::encode(&(&routing_message, &claimant, &random_bits));

        assert!(encoded_body.is_ok());

        let encoded_body = encoded_body.unwrap();
        let signature = ::sodiumoxide::crypto::sign::sign_detached(&encoded_body, &keys.1);
        let signed_message = super::SignedMessage::with_signature(
                claimant.clone(), routing_message.clone(), random_bits, signature);

        assert!(signed_message.is_ok());

        let signed_message = signed_message.unwrap();

        assert_eq!(signed_message.get_routing_message(), &routing_message);
        assert_eq!(signed_message.claimant(), &claimant);

        let signed_message_encoded_body = signed_message.encoded_body();

        assert!(signed_message_encoded_body.is_ok());

        let signed_message_encoded_body = signed_message_encoded_body.unwrap();

        assert_eq!(signed_message_encoded_body, encoded_body);

        let signature =
                ::sodiumoxide::crypto::sign::sign_detached(&signed_message_encoded_body, &keys.1);

        assert_eq!(signed_message.signature(), &signature);
        assert!(signed_message.verify_signature(&keys.0));
    }

    #[test]
    fn invalid_signed_message_with_signature() {
        let claimant = ::types::Address::Node(::test_utils::Random::generate_random());
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message = arbtrary_routing_message(&keys.0, &keys.1);
        let random_bits = generate_random_u8();
        let encoded_body = ::utils::encode(&(&routing_message, &claimant, &random_bits));

        assert!(encoded_body.is_ok());

        let encoded_body = encoded_body.unwrap();
        let invalid_keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let signature = ::sodiumoxide::crypto::sign::sign_detached(&encoded_body, &invalid_keys.1);
        let signed_message = super::SignedMessage::with_signature(
                claimant.clone(), routing_message.clone(), random_bits, signature);

        assert!(signed_message.is_ok());

        let signed_message = signed_message.unwrap();

        assert_eq!(signed_message.get_routing_message(), &routing_message);
        assert_eq!(signed_message.claimant(), &claimant);

        let signed_message_encoded_body = signed_message.encoded_body();

        assert!(signed_message_encoded_body.is_ok());

        let signed_message_encoded_body = signed_message_encoded_body.unwrap();

        assert_eq!(signed_message_encoded_body, encoded_body);

        let signature =
                ::sodiumoxide::crypto::sign::sign_detached(&signed_message_encoded_body, &keys.1);

        assert!(signed_message.signature() != &signature);
        assert!(!signed_message.verify_signature(&keys.0));
    }

    #[test]
    fn signed_message_new_from_token() {
        let claimant = ::types::Address::Node(::test_utils::Random::generate_random());
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message = arbtrary_routing_message(&keys.0, &keys.1);
        let random_bits = generate_random_u8();
        let encoded_body = ::utils::encode(&(&routing_message, &claimant, &random_bits));

        assert!(encoded_body.is_ok());

        let encoded_body = encoded_body.unwrap();
        let signature = ::sodiumoxide::crypto::sign::sign_detached(&encoded_body, &keys.1);
        let signed_token = super::SignedToken {
            serialised_request: encoded_body.clone(), signature:  signature
        };
        let signed_message = super::SignedMessage::new_from_token(signed_token.clone());

        assert!(signed_message.is_ok());

        let signed_message = signed_message.unwrap();

        assert_eq!(signed_message.get_routing_message(), &routing_message);
        assert_eq!(signed_message.claimant(), &claimant);

        let signed_message_encoded_body = signed_message.encoded_body();

        assert!(signed_message_encoded_body.is_ok());

        let signed_message_encoded_body = signed_message_encoded_body.unwrap();

        assert_eq!(signed_message_encoded_body, encoded_body);

        let signature =
                ::sodiumoxide::crypto::sign::sign_detached(&signed_message_encoded_body, &keys.1);

        assert_eq!(signed_message.signature(), &signature);
        assert!(signed_message.verify_signature(&keys.0));

        let signed_message_as_token = signed_message.as_token();

        assert!(signed_message_as_token.is_ok());
        assert_eq!(signed_message_as_token.unwrap(), signed_token);
    }

    #[test]
    fn invalid_signed_message_new_from_token() {
        let claimant = ::types::Address::Node(::test_utils::Random::generate_random());
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message = arbtrary_routing_message(&keys.0, &keys.1);
        let random_bits = generate_random_u8();
        let encoded_body = ::utils::encode(&(&routing_message, &claimant, &random_bits));

        assert!(encoded_body.is_ok());

        let encoded_body = encoded_body.unwrap();
        let invalid_keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let signature =
                ::sodiumoxide::crypto::sign::sign_detached(&encoded_body.clone(), &invalid_keys.1);
        let signed_token = super::SignedToken {
            serialised_request: encoded_body.clone(), signature:  signature
        };
        let signed_message = super::SignedMessage::new_from_token(signed_token.clone());

        assert!(signed_message.is_ok());

        let signed_message = signed_message.unwrap();

        assert_eq!(signed_message.get_routing_message(), &routing_message);
        assert_eq!(signed_message.claimant(), &claimant);

        let signed_message_encoded_body = signed_message.encoded_body();

        assert!(signed_message_encoded_body.is_ok());

        let signed_message_encoded_body = signed_message_encoded_body.unwrap();

        assert_eq!(signed_message_encoded_body, encoded_body);

        let signature =
                ::sodiumoxide::crypto::sign::sign_detached(&signed_message_encoded_body, &keys.1);

        assert!(signed_message.signature() != &signature);
        assert!(!signed_message.verify_signature(&keys.0));

        let signed_message_as_token = signed_message.as_token();

        assert!(signed_message_as_token.is_ok());
        assert_eq!(signed_message_as_token.unwrap(), signed_token);
    }
}

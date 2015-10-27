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

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct ConnectRequest {
    pub local_endpoints: Vec<::crust::Endpoint>,
    pub external_endpoints: Vec<::crust::Endpoint>,
    pub requester_fob: ::public_id::PublicId,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct ConnectResponse {
    pub local_endpoints: Vec<::crust::Endpoint>,
    pub external_endpoints: Vec<::crust::Endpoint>,
    pub receiver_fob: ::public_id::PublicId,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, RustcEncodable, RustcDecodable)]
/// SignedToken.
pub struct SignedToken {
    /// Encoded request to be signed.
    pub serialised_request: Vec<u8>,
    /// Signature of the serialised_request signed by secret sign key.
    pub signature: ::sodiumoxide::crypto::sign::Signature,
}

impl SignedToken {

    /// Verify the request was signed by the secret key corresponding to the passed in public key. 
    pub fn verify_signature(&self, public_sign_key: &::sodiumoxide::crypto::sign::PublicKey)
            -> bool {
        ::sodiumoxide::crypto::sign::verify_detached(
            &self.signature, &self.serialised_request, &public_sign_key)
    }
}

impl ::std::fmt::Debug for SignedToken {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
        formatter.write_str(&format!("SignedToken"))
    }
}

/// These are the message types routing provides.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
/// ExternalRequest.
pub enum ExternalRequest {
    /// Request to get data from the network.
    Get(::data::DataRequest, u8),
    /// Request to put data onto the network.
    Put(::data::Data),
    /// Request to mutate data on the network.
    Post(::data::Data),
    /// Request to delete data from the network.
    Delete(::data::Data),
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
/// ExternalResponse.
pub enum ExternalResponse {
    // TODO: Applies to Get: Technical depth: if the third param here is Some(...) then
    // the it shares most of the data with the second argument, which
    // needlessly increases bandwidth.

    /// Response to get data request.
    Get(::data::Data, ::data::DataRequest, Option<SignedToken>),
    /// Response to put data request on error.
    Put(::error::ResponseError, Option<SignedToken>),
    /// Response to post data request on error.
    Post(::error::ResponseError, Option<SignedToken>),
    /// Response to delete data request on error.
    Delete(::error::ResponseError, Option<SignedToken>),
}

impl ExternalResponse {

    /// If the *request* was from a group entity, then there is no signed token.
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
    RequestNetworkName(::public_id::PublicId),
    // a client can send RequestNetworkName
    CacheNetworkName(::public_id::PublicId, SignedToken),
    //               ~~|~~~~~  ~~|~~~~~~~~
    //                 |         | SignedToken contains Request::RequestNetworkName and needs to
    //                 |         | be forwarded in the Request::CacheNetworkName;
    //                 |         | from it the original reply to authority can be read.
    //                 | contains the PublicId from RequestNetworkName, but mutated with
    //                 | the network assigned name
    /// Refresh allows a persona to republish account records (identified with type_tag:u64 and
    /// the serialised payload:Vec<u8>).  The cause of the Refresh is the NameType of the node
    /// that caused the churn event.
    Refresh(u64, Vec<u8>, ::NameType),
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub enum InternalResponse {
    Connect(ConnectResponse, SignedToken),
    // FindGroup(Vec<::public_id::PublicId>, SignedToken),
    // GetGroupKey(::std::collections::BTreeMap<
    //      ::NameType, ::sodiumoxide::crypto::sign::PublicKey>, SignedToken),
    CacheNetworkName(::public_id::PublicId, Vec<::public_id::PublicId>, SignedToken),
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
    pub from_authority: ::authority::Authority,
    pub to_authority: ::authority::Authority,
    pub content: Content,
}

impl RoutingMessage {

    #[allow(dead_code)]
    pub fn source(&self) -> ::authority::Authority {
        self.from_authority.clone()
    }

    pub fn destination(&self) -> ::authority::Authority {
        self.to_authority.clone()
    }

    pub fn client_key(&self) -> Option<::sodiumoxide::crypto::sign::PublicKey> {
        match self.from_authority {
            ::authority::Authority::ClientManager(_) => None,
            ::authority::Authority::NaeManager(_) => None,
            ::authority::Authority::NodeManager(_) => None,
            ::authority::Authority::ManagedNode(_) => None,
            ::authority::Authority::Client(_, key) => Some(key),
        }
    }

    pub fn client_key_as_name(&self) -> Option<::NameType> {
        self.client_key().map(|n| ::utils::public_key_to_client_name(&n))
    }

    pub fn from_group(&self) -> Option<::NameType> {
        match self.from_authority {
            ::authority::Authority::ClientManager(name) => Some(name),
            ::authority::Authority::NaeManager(name) => Some(name),
            ::authority::Authority::NodeManager(name) => Some(name),
            ::authority::Authority::ManagedNode(_) => None,
            ::authority::Authority::Client(_, _) => None,
        }
    }
}

/// All messages sent / received are constructed as signed message.
#[derive(PartialEq, Eq, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct SignedMessage {
    body: RoutingMessage,
    claimant: ::types::Address,
    //          when signed by Client(PublicKey) the data needs to contain it as an owner
    //          when signed by a Node(NameType), Sentinel needs to validate the signature
    random_bits: u8,
    signature: ::sodiumoxide::crypto::sign::Signature,
}

#[allow(unused)]
impl SignedMessage {
    pub fn new(claimant: ::types::Address,
               message: RoutingMessage,
               private_sign_key: &::sodiumoxide::crypto::sign::SecretKey)
               -> Result<SignedMessage, ::cbor::CborError> {
        use ::rand::Rng;

        let mut rng = ::rand::thread_rng();
        let random_bits = rng.gen::<u8>();
        let encoded_body = try!(::utils::encode(&(&message, &claimant, &random_bits)));
        let signature = ::sodiumoxide::crypto::sign::sign_detached(&encoded_body, private_sign_key);

        Ok(SignedMessage { body: message, claimant: claimant,
            random_bits: random_bits, signature: signature })
    }

    /// Construct a signed message passing in the signature.
    pub fn with_signature(claimant: ::types::Address,
                          message: RoutingMessage,
                          random_bits: u8,
                          signature: ::sodiumoxide::crypto::sign::Signature)
                          -> Result<SignedMessage, ::cbor::CborError> {

        Ok(SignedMessage { body: message, claimant: claimant,
              random_bits: random_bits, signature: signature })
    }

    /// Construct a signed message from a signed token.
    pub fn new_from_token(signed_token: SignedToken) -> Result<SignedMessage, ::cbor::CborError> {
        let (message, claimant, random_bits) =
            try!(::utils::decode(&signed_token.serialised_request));

        Ok(SignedMessage { body: message, claimant: claimant,
            random_bits: random_bits, signature: signed_token.signature })
    }

    /// Verify the signature using the given public key.
    pub fn verify_signature(&self, public_sign_key: &::sodiumoxide::crypto::sign::PublicKey)
            -> bool {
        let encoded_body = match ::utils::encode(&(&self.body, &self.claimant, &self.random_bits)) {
            Ok(x) => x,
            Err(_) => return false,
        };

        ::sodiumoxide::crypto::sign::verify_detached(
            &self.signature, &encoded_body, public_sign_key)
    }

    /// Return the internal routing message.
    pub fn get_routing_message(&self) -> &RoutingMessage {
        &self.body
    }

    /// Return the signature.
    pub fn signature(&self) -> &::sodiumoxide::crypto::sign::Signature {
        &self.signature
    }

    /// Return the encoded unsigned body of the message.
    pub fn encoded_body(&self) -> Result<Vec<u8>, ::cbor::CborError> {
        ::utils::encode(&(&self.body, &self.claimant, &self.random_bits))
    }

    /// Return the associated signed token.
    pub fn as_token(&self) -> Result<SignedToken, ::cbor::CborError> {
        Ok(SignedToken {
                serialised_request: try!(self.encoded_body()),
                signature: self.signature().clone(),
            })
    }

    /// Return the message claimant.
    pub fn claimant(&self) -> &::types::Address {
        &self.claimant
    }
}


#[cfg(test)]
mod test{
    use rand;

    #[test]
    fn signed_message_new() {
        let claimant = ::types::Address::Node(rand::random());
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message =
            ::test_utils::messages_util::arbitrary_routing_message(&keys.0, &keys.1);
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
        let claimant = ::types::Address::Node(rand::random());
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message =
            ::test_utils::messages_util::arbitrary_routing_message(&keys.0, &keys.1);
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
        let claimant = ::types::Address::Node(rand::random());
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message =
            ::test_utils::messages_util::arbitrary_routing_message(&keys.0, &keys.1);
        let random_bits: u8 = rand::random();
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
        let claimant = ::types::Address::Node(rand::random());
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message =
            ::test_utils::messages_util::arbitrary_routing_message(&keys.0, &keys.1);
        let random_bits: u8 = rand::random();
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
        let claimant = ::types::Address::Node(rand::random());
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message =
            ::test_utils::messages_util::arbitrary_routing_message(&keys.0, &keys.1);
        let random_bits: u8 = rand::random();
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
        let claimant = ::types::Address::Node(rand::random());
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message =
            ::test_utils::messages_util::arbitrary_routing_message(&keys.0, &keys.1);
        let random_bits: u8 = rand::random();
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

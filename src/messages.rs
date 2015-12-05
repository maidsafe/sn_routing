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

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, RustcEncodable, RustcDecodable)]
/// Contains a signed RoutingMessage request returned to originator for validation where applicable.
pub struct SignedRequest {
    /// Signed RoutingMessage.
    pub signed_routing_message: Vec<u8>,
}

impl ::std::fmt::Debug for SignedRequest {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
        formatter.write_str(&format!("SignedRequest"))
    }
}

/// These are the message types routing provides.
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
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

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
/// ExternalResponse.
pub enum ExternalResponse {
    // TODO: Applies to Get: Technical depth: if the third param here is Some(...) then
    // the it shares most of the data with the second argument, which
    // needlessly increases bandwidth.
    /// Response to get data request.
    Get(::data::Data, ::data::DataRequest, Option<SignedRequest>),
    /// Response to put data request on error.
    Put(::error::ResponseError, Option<SignedRequest>),
    /// Response to post data request on error.
    Post(::error::ResponseError, Option<SignedRequest>),
    /// Response to delete data request on error.
    Delete(::error::ResponseError, Option<SignedRequest>),
}

impl ExternalResponse {
    /// If the *request* was from a group entity, then there is no signed token.
    pub fn get_signed_token(&self) -> &Option<SignedRequest> {
        match *self {
            ExternalResponse::Get(_, _, ref r) => r,
            ExternalResponse::Put(_, ref r) => r,
            ExternalResponse::Post(_, ref r) => r,
            ExternalResponse::Delete(_, ref r) => r,
        }
    }
}

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub enum InternalRequest {
    GetNetworkName {
        current_id: ::id::PublicId,
    },
    ExpectCloseNode {
        expect_id: ::id::PublicId,
    },
    GetCloseGroup,
    Connect,
    Endpoints {
        encrypted_endpoints: Vec<u8>,
        nonce_bytes: [u8; ::sodiumoxide::crypto::box_::NONCEBYTES],
    },
    GetPublicId,
    GetPublicIdWithEndpoints {
        encrypted_endpoints: Vec<u8>,
        nonce_bytes: [u8; ::sodiumoxide::crypto::box_::NONCEBYTES],
    },
    Refresh {
        type_tag: u64,
        message: Vec<u8>,
        cause: ::NameType,
    },
}

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub enum InternalResponse {
    GetNetworkName {
        relocated_id: ::id::PublicId,
        signed_request: SignedRequest,
    },
    GetCloseGroup {
        close_group_ids: Vec<::id::PublicId>,
        signed_request: SignedRequest,
    },
    GetPublicId {
        public_id: ::id::PublicId,
        signed_request: SignedRequest,
    },
    GetPublicIdWithEndpoints {
        public_id: ::id::PublicId,
        signed_request: SignedRequest,
    },
}

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub enum Content {
    ExternalRequest(ExternalRequest),
    InternalRequest(InternalRequest),
    ExternalResponse(ExternalResponse),
    InternalResponse(InternalResponse),
}

/// the bare (unsigned) routing message
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct RoutingMessage {
    pub source: ::authority::Authority,
    pub destination: ::authority::Authority,
    pub content: Content,
    pub group_keys: Option<Vec<::sodiumoxide::crypto::sign::PublicKey>>,
}

impl RoutingMessage {
    // pub fn source(&self) -> ::authority::Authority {
    //     self.source.clone()
    // }

    // pub fn destination(&self) -> ::authority::Authority {
    //     self.destination.clone()
    // }

    pub fn client_key(&self) -> Option<::sodiumoxide::crypto::sign::PublicKey> {
        match self.source {
            ::authority::Authority::ClientManager(_) => None,
            ::authority::Authority::NaeManager(_) => None,
            ::authority::Authority::NodeManager(_) => None,
            ::authority::Authority::ManagedNode(_) => None,
            ::authority::Authority::Client(_, key) => Some(key),
        }
    }

    pub fn client_key_as_name(&self) -> Option<::NameType> {
        self.client_key().map(|n| ::NameType(::sodiumoxide::crypto::hash::sha512::hash(&n[..]).0))
    }

    pub fn source_group(&self) -> Option<::NameType> {
        match self.source {
            ::authority::Authority::ClientManager(name) => Some(name),
            ::authority::Authority::NaeManager(name) => Some(name),
            ::authority::Authority::NodeManager(name) => Some(name),
            ::authority::Authority::ManagedNode(_) => None,
            ::authority::Authority::Client(_, _) => None,
        }
    }
}

/// All messages sent / received are constructed as signed message.
#[derive(Hash, PartialOrd, Ord, PartialEq, Eq, Clone, RustcEncodable, RustcDecodable)]
pub struct SignedMessage {
    signed_routing_message: Vec<u8>,
    public_sign_key: ::sodiumoxide::crypto::sign::PublicKey,
}

impl SignedMessage {
    pub fn new(routing_message: &RoutingMessage, full_id: &::id::FullId)
            -> Result<SignedMessage, ::maidsafe_utilities::serialisation::SerialisationError> {
        let encoded_message = try!(::maidsafe_utilities::serialisation::serialise(routing_message));
        let signed_message = ::sodiumoxide::crypto::sign::sign(&encoded_message, full_id.signing_private_key());

        Ok(SignedMessage {
            signed_routing_message: signed_message,
            public_sign_key: full_id.public_id().signing_public_key().clone(),
        })
    }

    /// Construct a signed message from a signed token and public signing key. Note we don't attempt
    /// to verify the signed message on construction.
    pub fn from_signed_request(signed_request: SignedRequest,
                               public_sign_key: ::sodiumoxide::crypto::sign::PublicKey)
            -> SignedMessage {
        SignedMessage {
            signed_routing_message: signed_request.signed_routing_message,
            public_sign_key: public_sign_key,
        }
    }

    /// Verifies the message returning the RoutingMessage, or RoutingError on failure.
    pub fn get_routing_message(&self) -> Result<RoutingMessage, ::error::RoutingError> {
        let verify_result = ::sodiumoxide::crypto::sign::verify(
            &self.signed_routing_message, &self.public_sign_key);

        let encoded_msg = try!(verify_result.map_err(|()| ::error::RoutingError::FailedSignature));

        Ok(try!(::maidsafe_utilities::serialisation::deserialise(&encoded_msg)))
    }

    /// Return public signing key.
    pub fn signing_public_key(&self) -> &::sodiumoxide::crypto::sign::PublicKey {
        &self.public_sign_key
    }

    /// Return the associated signed request.
    pub fn as_signed_request(&self) -> SignedRequest {
        SignedRequest { signed_routing_message: self.signed_routing_message.clone(), }
    }
}

impl ::std::fmt::Debug for SignedMessage {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(formatter, "SignedMessage {{ signed_routing_message: {:?}, public_sign_key: {:?}, }}\
            ", self.signed_routing_message, self.public_sign_key)
    }
}

#[cfg(test)]
mod test{
    #[test]
    fn signed_message_new() {
        let full_id = ::id::FullId::new();
        let routing_message = ::test_utils::messages_util::arbitrary_routing_message(
                full_id.public_id().signing_public_key(),
                full_id.signing_private_key());
        let signed_message = super::SignedMessage::new(&routing_message, &full_id);

        assert!(signed_message.is_ok());

        let signed_message = signed_message.unwrap();
        let verified_routing_message = unwrap_result!(signed_message.get_routing_message());
        assert_eq!(verified_routing_message, routing_message);
    }

    #[test]
    fn signed_message_from_token() {
        let full_id = ::id::FullId::new();
        let routing_message = ::test_utils::messages_util::arbitrary_routing_message(
                full_id.public_id().signing_public_key(),
                full_id.signing_private_key());
        let signed_message = super::SignedMessage::new(&routing_message, &full_id);

        assert!(signed_message.is_ok());

        let signed_message = signed_message.unwrap();
        let signed_request = signed_message.as_signed_request();

        let signed_message_from_token = super::SignedMessage::from_signed_request(
                signed_request, full_id.public_id().signing_public_key().clone());

        assert_eq!(signed_message, signed_message_from_token);

        let verified_routing_message = unwrap_result!(signed_message_from_token.get_routing_message());
        assert_eq!(verified_routing_message, routing_message);
    }
}

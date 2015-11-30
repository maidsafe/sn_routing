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
/// SignedToken.
pub struct SignedToken {
    /// Signed RoutingMessage.
    pub signed_routing_message: Vec<u8>,
}

impl ::std::fmt::Debug for SignedToken {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
        formatter.write_str(&format!("SignedToken"))
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

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub enum InternalRequest {
    Connect {
        endpoints: Vec<::crust::Endpoint>,
        public_id: ::public_id::PublicId,
    },
    RequestNetworkName(::public_id::PublicId),
    // a client can send RequestNetworkName
    RelocatedNetworkName(::public_id::PublicId, SignedToken),
    //               ~~|~~~~~  ~~|~~~~~~~~
    //                 |         | SignedToken contains Request::RequestNetworkName and needs to
    //                 |         | be forwarded in the Request::RelocatedNetworkName;
    //                 |         | from it the original reply to authority can be read.
    //                 | contains the PublicId from RequestNetworkName, but mutated with
    //                 | the network assigned name
    /// Refresh allows a persona to republish account records (identified with type_tag:u64 and
    /// the serialised payload:Vec<u8>).  The cause of the Refresh is the NameType of the node
    /// that caused the churn event.
    Refresh(u64, Vec<u8>, ::NameType),
}

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub enum InternalResponse {
    Connect {
        endpoints: Vec<::crust::Endpoint>,
        public_id: ::public_id::PublicId,
        signed_token: SignedToken,
    },
    // FindGroup(Vec<::public_id::PublicId>, SignedToken),
    // GetGroupKey(::std::collections::BTreeMap<
    //      ::NameType, ::sodiumoxide::crypto::sign::PublicKey>, SignedToken),
    RelocatedNetworkName(::public_id::PublicId, Vec<::public_id::PublicId>, SignedToken), /*               ~~|~~~~~  ~~|~~~~~~~~~~  ~~|~~~~~~~~
                                                                                       *                 |         |              | the original Request::RequestNetworkName
                                                                                       *                 |         | the group public keys to combine FindGroup in this response
                                                                                       *                 | the cached PublicId in the group */
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
    pub from_authority: ::authority::Authority,
    pub to_authority: ::authority::Authority,
    pub content: Content,
    pub group_keys: Option<Vec<::sodiumoxide::crypto::sign::PublicKey>>,
}

impl RoutingMessage {
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

    pub fn source_group(&self) -> Option<::NameType> {
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
#[derive(PartialEq, Eq, Clone, RustcEncodable, RustcDecodable)]
pub struct SignedMessage {
    signed_routing_message: Vec<u8>,
    public_sign_key: ::sodiumoxide::crypto::sign::PublicKey
}

impl SignedMessage {
    pub fn new(routing_message: &RoutingMessage,
               public_sign_key: ::sodiumoxide::crypto::sign::PublicKey,
               private_sign_key: &::sodiumoxide::crypto::sign::SecretKey)
                    -> Result<SignedMessage, ::cbor::CborError> {
        let encoded_message = try!(::utils::encode(routing_message));
        let signed_message = ::sodiumoxide::crypto::sign::sign(&encoded_message, private_sign_key);

        Ok(SignedMessage {
            signed_routing_message: signed_message,
            public_sign_key: public_sign_key
        })
    }

    /// Construct a signed message from a signed token and public signing key. Note we don't attempt
    /// to verify the signed message on construction.
    pub fn from_token(signed_token: SignedToken,
                      public_sign_key: ::sodiumoxide::crypto::sign::PublicKey) -> SignedMessage {
        SignedMessage {
            signed_routing_message: signed_token.signed_routing_message,
            public_sign_key: public_sign_key,
        }
    }

    /// Verifies the message returning the RoutingMessage, or None on failure.
    pub fn verify(&self) -> Option<RoutingMessage> {
        match ::sodiumoxide::crypto::sign::verify(
                &self.signed_routing_message[..], &self.public_sign_key) {
            Ok(encoded_message) => {
                match ::utils::decode(&encoded_message[..]) {
                    Ok(routing_message) => Some(routing_message),
                    Err(_) => None,
                }
            },
            Err(_) => None
        }
    }

    /// Return public signing key.
    pub fn signing_public_key(&self) -> &::sodiumoxide::crypto::sign::PublicKey {
        &self.public_sign_key
    }

    /// Return the associated signed token.
    pub fn as_token(&self) -> SignedToken {
        SignedToken { signed_routing_message: self.signed_routing_message.clone(), }
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
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message = ::test_utils::messages_util::arbitrary_routing_message(&keys.0,
                                                                                     &keys.1);
        let signed_message = super::SignedMessage::new(&routing_message, keys.0, &keys.1);

        assert!(signed_message.is_ok());

        let signed_message = signed_message.unwrap();
        let verified_message = signed_message.verify();

        assert!(verified_message.is_some());

        let verified_routing_message = verified_message.unwrap();
        assert_eq!(verified_routing_message, routing_message);
    }

    #[test]
    fn signed_message_from_token() {
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message = ::test_utils::messages_util::arbitrary_routing_message(&keys.0,
                                                                                     &keys.1);
        let signed_message = super::SignedMessage::new(&routing_message, keys.0, &keys.1);

        assert!(signed_message.is_ok());

        let signed_message = signed_message.unwrap();
        let signed_token = signed_message.as_token();

        let signed_message_from_token = super::SignedMessage::from_token(signed_token, keys.0);

        assert_eq!(signed_message, signed_message_from_token);

        let verified_message = signed_message_from_token.verify();

        assert!(verified_message.is_some());

        let verified_routing_message = verified_message.unwrap();
        assert_eq!(verified_routing_message, routing_message);
    }
}

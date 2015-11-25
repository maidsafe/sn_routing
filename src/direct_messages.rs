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

//! Direct messages are different from SignedMessages as they have no header information and
//! are restricted to transfer on a single connection.  They cannot be transferred
//! as SignedMessages (wrapping RoutingMessages) over the routing network.

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct Churn {
    pub close_group: Vec<::NameType>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
#[allow(variant_size_differences)]
pub enum Content {
    Identify { public_id: ::public_id::PublicId, },
    Churn(Churn),
}

/// All messages sent / received are constructed as signed message.
#[derive(PartialEq, Eq, Clone, RustcEncodable, RustcDecodable)]
pub struct DirectMessage {
    content: Content,
    signature: ::sodiumoxide::crypto::sign::Signature,
}

impl DirectMessage {
    pub fn new(content: Content,
               private_sign_key: &::sodiumoxide::crypto::sign::SecretKey)
               -> Result<DirectMessage, ::cbor::CborError> {
        let encoded_content = try!(::utils::encode(&content));
        let signature = ::sodiumoxide::crypto::sign::sign_detached(&encoded_content,
                                                                   private_sign_key);
        Ok(DirectMessage {
            content: content,
            signature: signature,
        })
    }

    pub fn new_identify(public_id: ::public_id::PublicId,
                        private_sign_key: &::sodiumoxide::crypto::sign::SecretKey)
                        -> Result<DirectMessage, ::cbor::CborError> {
        let content = Content::Identify{ public_id: public_id, };
        Self::new(content, private_sign_key)
    }

    pub fn verify_signature(&self,
                            public_sign_key: &::sodiumoxide::crypto::sign::PublicKey)
                            -> bool {
        let encoded_content = match self.encoded_content() {
            Ok(x) => x,
            Err(_) => return false,
        };

        ::sodiumoxide::crypto::sign::verify_detached(&self.signature,
                                                     &encoded_content,
                                                     public_sign_key)
    }

    pub fn content(&self) -> &Content {
        &self.content
    }

    #[allow(unused)]
    pub fn signature(&self) -> &::sodiumoxide::crypto::sign::Signature {
        &self.signature
    }

    pub fn encoded_content(&self) -> Result<Vec<u8>, ::cbor::CborError> {
        ::utils::encode(&self.content)
    }
}

impl ::std::fmt::Debug for DirectMessage {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(formatter, "DirectMessage {{ content: {:?}, signature: <binary data> }}",
               self.content)
    }
}

#[cfg(test)]
mod test {
    use rand;

    #[test]
    fn verify_signature() {
        let public_id: ::public_id::PublicId = rand::random();
        let content = ::direct_messages::Content::Identify {
            public_id: public_id,
        };
        let key = ::sodiumoxide::crypto::sign::gen_keypair();
        let other_key = ::sodiumoxide::crypto::sign::gen_keypair();

        match ::direct_messages::DirectMessage::new(content, &key.1) {
            Ok(message) => {
                // verify_signature returns true for correct public key
                assert!(message.verify_signature(&key.0));

                // verify_signature returns false for other public key
                assert!(!message.verify_signature(&other_key.0));
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }
}

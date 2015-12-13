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

use data::{Data, DataRequest};
use id::{PublicId, FullId};
use xor_name::XorName;
use error::{RoutingError, ResponseError};
use sodiumoxide::crypto::{box_, sign, hash};
use authority::Authority;
use maidsafe_utilities::serialisation::{serialise, deserialise};
use rustc_serialize::{Decoder, Encoder};
#[derive(Debug, RustcEncodable, RustcDecodable)]
pub enum Message {
    DirectMessage(DirectMessage),
    HopMessage(HopMessage),
}

#[derive(Debug, RustcEncodable, RustcDecodable)]
pub enum DirectMessage {
    BootstrapIdentify {
        public_id: ::id::PublicId,
        current_quorum_size: usize,
    },
    ClientIdentify {
        serialised_public_id: Vec<u8>,
        signature: sign::Signature,
    },
    NodeIdentify {
        serialised_public_id: Vec<u8>,
        signature: sign::Signature,
    },
    Churn {
        // TODO Sign this ???
        close_group: Vec<::XorName>,
    },
}

#[derive(Debug, RustcEncodable, RustcDecodable)]
pub struct HopMessage {
    content: SignedMessage,
    name: XorName,
    signature: sign::Signature,
}

impl HopMessage {
    pub fn new(content: SignedMessage,
               name: XorName,
               sign_key: &sign::SecretKey)
               -> Result<HopMessage, RoutingError> {
        let bytes_to_sign = try!(serialise(&(&content, &name)));
        Ok(HopMessage {
            content: content,
            name: name,
            signature: sign::sign_detached(&bytes_to_sign, sign_key),
        })
    }

    pub fn verify(&self, verification_key: &sign::PublicKey) -> Result<(), RoutingError> {
        let signed_bytes = try!(serialise(&(&self.content, &self.name)));
        if !sign::verify_detached(&self.signature, &signed_bytes, verification_key) {
            Ok(())
        } else {
            Err(RoutingError::FailedSignature)
        }
    }

    pub fn extract(&self) -> (SignedMessage, XorName) {
        (self.content.clone(), self.name.clone())
    }

    pub fn name(&self) -> &XorName {
        &self.name
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Debug, RustcEncodable, RustcDecodable)]
pub struct SignedMessage {
    content: RoutingMessage,
    public_id: PublicId,
    signature: sign::Signature,
}

impl SignedMessage {
    pub fn new(content: RoutingMessage, full_id: &FullId) -> Result<SignedMessage, RoutingError> {
        let bytes_to_sign = try!(serialise(&(&content, full_id.public_id())));
        Ok(SignedMessage {
            content: content,
            public_id: full_id.public_id().clone(),
            signature: sign::sign_detached(&bytes_to_sign, full_id.signing_private_key()),
        })
    }

    pub fn check_integrity(&self) -> Result<(), RoutingError> {
        let signed_bytes = try!(serialise(&(&self.content, &self.public_id)));
        if !sign::verify_detached(&self.signature,
                                  &signed_bytes,
                                  self.public_id().signing_public_key()) {
            Ok(())
        } else {
            Err(RoutingError::FailedSignature)
        }
    }

    // TODO Maybe verify signature also
    pub fn content(&self) -> &RoutingMessage {
        &self.content
    }

    // TODO Maybe verify signature also
    pub fn public_id(&self) -> &PublicId {
        &self.public_id
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Debug, RustcEncodable, RustcDecodable)]
pub enum RoutingMessage {
    Request(RequestMessage),
    Response(ResponseMessage),
}

impl RoutingMessage {
    pub fn src(&self) -> &Authority {
        match *self {
            RoutingMessage::Request(ref msg) => &msg.src,
            RoutingMessage::Response(ref msg) => &msg.src,
        }
    }

    pub fn dst(&self) -> &Authority {
        match *self {
            RoutingMessage::Request(ref msg) => &msg.dst,
            RoutingMessage::Response(ref msg) => &msg.dst,
        }
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Debug, RustcEncodable, RustcDecodable)]
pub struct RequestMessage {
    pub src: Authority,
    pub dst: Authority,
    pub content: RequestContent,
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Debug, RustcEncodable, RustcDecodable)]
pub struct ResponseMessage {
    pub src: Authority,
    pub dst: Authority,
    pub content: ResponseContent,
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Debug, RustcEncodable, RustcDecodable)]
pub enum RequestContent {
    // ---------- Internal ------------
    GetNetworkName {
        current_id: PublicId,
    },
    ExpectCloseNode {
        expect_id: PublicId,
    },
    GetCloseGroup,
    Connect,
    Endpoints {
        encrypted_endpoints: Vec<u8>,
        nonce_bytes: [u8; box_::NONCEBYTES],
    },
    GetPublicId,
    GetPublicIdWithEndpoints {
        encrypted_endpoints: Vec<u8>,
        nonce_bytes: [u8; box_::NONCEBYTES],
    },
    Refresh {
        type_tag: u64,
        message: Vec<u8>,
        cause: ::XorName,
    },
    // ---------- External ------------
    Get(DataRequest),
    Put(Data),
    Post(Data),
    Delete(Data),
}


#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Debug, RustcEncodable, RustcDecodable)]
pub enum GetResultType {
    Success(Data),
    Failure(RequestMessage, ResponseError),
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Debug, RustcEncodable, RustcDecodable)]
pub enum APIResultType {
    Success(hash::sha512::Digest),
    Failure(RequestMessage, ResponseError),
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Debug, RustcEncodable, RustcDecodable)]
pub enum ResponseContent {
    // ---------- Internal ------------
    GetNetworkName {
        relocated_id: PublicId,
    },
    GetPublicId {
        public_id: PublicId,
    },
    GetPublicIdWithEndpoints {
        public_id: PublicId,
        encrypted_endpoints: Vec<u8>,
        nonce_bytes: [u8; box_::NONCEBYTES],
    },
    GetCloseGroup {
        close_group_ids: Vec<PublicId>,
    },
    // ---------- External ------------
    Get {
        result: GetResultType,
    },
    Put {
        result: APIResultType,
    },
    Post {
        result: APIResultType,
    },
    Delete {
        result: APIResultType,
    },
}

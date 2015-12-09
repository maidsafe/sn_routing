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

use data::{Data};
use id::{PublicId};
use xor_name::XorName;
use sodiumoxide::crypto::{box_, sign, hash};
use authority::{SourceAuthority, DestinationAuthority};

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

#[derive(Ord, PartialOrd, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct SignedMessage {
	content: RoutingMessage,
	public_id: PublicId,
    signature: sign::Signature,
}

#[derive(Ord, PartialOrd, Clone, Debug, RustcEncodable, RustcDecodable)]
pub enum RoutingMessage {
    Request(RequestMessage),
    Response(ResponseMessage),
}

#[derive(Ord, PartialOrd, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct RequestMessage {
    pub src: Authority,
    pub dst: Authority,
    pub content: RequestContent,
}

#[derive(Ord, PartialOrd, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct ResponseMessage {
    pub src: Authority,
    pub dst: Authority,
    pub content: ResponseContent,
    pub request: SignedMessage,
}

#[derive(Ord, PartialOrd, Clone, Debug, RustcEncodable, RustcDecodable)]
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

#[derive(Ord, PartialOrd, Clone, Debug, RustcEncodable, RustcDecodable)]
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
    },
    GetCloseGroup {
        close_group_ids: Vec<PublicId>,
    },
    // ---------- External ------------
    Get {
        result: Result<Data, (RequestMessage, ResponseError)>,
    },
    Put {
        result: Result<sha512::hash::Digest, (RequestMessage, ResponseError)>,
    },
    Post {
        result: Result<sha512::hash::Digest, (RequestMessage, ResponseError)>,
    },
    Delete {
        result: Result<sha512::hash::Digest, (RequestMessage, ResponseError)>,
    },
}

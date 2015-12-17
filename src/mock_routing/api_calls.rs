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

#[derive(Clone)]
pub struct GetRequest {
    pub our_authority: ::routing::Authority,
    pub location: ::routing::Authority,
    pub request_for: ::routing::data::DataRequest,
}

impl GetRequest {
    pub fn new(our_authority: ::routing::Authority,
               location: ::routing::Authority,
               request_for: ::routing::data::DataRequest)
               -> GetRequest {
        GetRequest { our_authority: our_authority, location: location, request_for: request_for }
    }
}

#[derive(Clone)]
pub struct PutRequest {
    pub our_authority: ::routing::Authority,
    pub location: ::routing::Authority,
    pub data: ::routing::data::Data,
}

impl PutRequest {
    pub fn new(our_authority: ::routing::Authority,
               location: ::routing::Authority,
               data: ::routing::data::Data)
               -> PutRequest {
        PutRequest { our_authority: our_authority, location: location, data: data }
    }
}

#[derive(Clone)]
pub struct PostRequest {
    pub our_authority: ::routing::Authority,
    pub location: ::routing::Authority,
    pub data: ::routing::data::Data,
}

impl PostRequest {
    #[allow(dead_code)]
    pub fn new(our_authority: ::routing::Authority,
               location: ::routing::Authority,
               data: ::routing::data::Data)
               -> PostRequest {
        PostRequest { our_authority: our_authority, location: location, data: data }
    }
}

#[derive(Clone)]
pub struct DeleteRequest {
    pub our_authority: ::routing::Authority,
    pub location: ::routing::Authority,
    pub data: ::routing::data::Data,
}

impl DeleteRequest {
    #[allow(dead_code)]
    pub fn new(our_authority: ::routing::Authority,
               location: ::routing::Authority,
               data: ::routing::data::Data)
               -> DeleteRequest {
        DeleteRequest { our_authority: our_authority, location: location, data: data }
    }
}

#[derive(Clone)]
pub struct GetResponse {
    pub our_authority: ::routing::Authority,
    pub location: ::routing::Authority,
    pub data: ::routing::data::Data,
    pub data_request: ::routing::data::DataRequest,
    pub response_token: Option<::routing::SignedToken>,
}

impl GetResponse {
    pub fn new(our_authority: ::routing::Authority,
               location: ::routing::Authority,
               data: ::routing::data::Data,
               data_request: ::routing::data::DataRequest,
               response_token: Option<::routing::SignedToken>)
               -> GetResponse {
        GetResponse {
            our_authority: our_authority,
            location: location,
            data: data,
            data_request: data_request,
            response_token: response_token,
        }
    }
}

#[derive(Clone)]
pub struct PutResponse {
    pub our_authority: ::routing::Authority,
    pub location: ::routing::Authority,
    pub response_error: ::routing::error::ResponseError,
    pub signed_token: Option<::routing::SignedToken>,
}

impl PutResponse {
    pub fn new(our_authority: ::routing::Authority,
               location: ::routing::Authority,
               response_error: ::routing::error::ResponseError,
               signed_token: Option<::routing::SignedToken>)
               -> PutResponse {
        PutResponse {
            our_authority: our_authority,
            location: location,
            response_error: response_error,
            signed_token: signed_token,
        }
    }
}

#[derive(Clone)]
pub struct PostResponse {
    pub our_authority: ::routing::Authority,
    pub location: ::routing::Authority,
    pub response_error: ::routing::error::ResponseError,
    pub signed_token: Option<::routing::SignedToken>,
}

impl PostResponse {
    #[allow(dead_code)]
    pub fn new(our_authority: ::routing::Authority,
               location: ::routing::Authority,
               response_error: ::routing::error::ResponseError,
               signed_token: Option<::routing::SignedToken>)
               -> PostResponse {
        PostResponse {
            our_authority: our_authority,
            location: location,
            response_error: response_error,
            signed_token: signed_token,
        }
    }
}

#[derive(Clone)]
pub struct DeleteResponse {
    pub our_authority: ::routing::Authority,
    pub location: ::routing::Authority,
    pub response_error: ::routing::error::ResponseError,
    pub signed_token: Option<::routing::SignedToken>,
}

impl DeleteResponse {
    #[allow(dead_code)]
    pub fn new(our_authority: ::routing::Authority,
               location: ::routing::Authority,
               response_error: ::routing::error::ResponseError,
               signed_token: Option<::routing::SignedToken>)
               -> DeleteResponse {
        DeleteResponse {
            our_authority: our_authority,
            location: location,
            response_error: response_error,
            signed_token: signed_token,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshRequest {
    pub type_tag: u64,
    pub our_authority: ::routing::Authority,
    pub content: Vec<u8>,
    pub churn_node: XorName,
}

impl RefreshRequest {
    pub fn new(type_tag: u64,
               our_authority: ::routing::Authority,
               content: Vec<u8>,
               churn_node: XorName) -> RefreshRequest {
        RefreshRequest { type_tag: type_tag, our_authority: our_authority,
                         content: content, churn_node: churn_node }
    }
}

// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use messages::{Request, Response};

/// A cache that stores `Response`s keyed by `Requests`. Should be implemented
/// by layers above routing.
pub trait Cache: Send {
    /// Retrieve cached response for the given request.
    fn get(&self, request: &Request) -> Option<Response>;

    /// Cache the given response.
    fn put(&self, response: Response);
}

/// A no-op implementation of the `Cache` trait. Throws everything away on put
/// and always returns `None` on get.
pub struct NullCache;

impl Cache for NullCache {
    fn get(&self, _: &Request) -> Option<Response> {
        None
    }
    fn put(&self, _: Response) {}
}

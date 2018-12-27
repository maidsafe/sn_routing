// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::messages::{Request, Response};

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

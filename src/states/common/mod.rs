// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod base;
mod bootstrapped;
pub mod client;

pub use self::base::Base;
pub use self::bootstrapped::Bootstrapped;

pub const USER_MSG_CACHE_EXPIRY_DURATION_SECS: u64 = 120;

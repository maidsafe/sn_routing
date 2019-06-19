// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod approved;
mod base;
mod bootstrapped;
mod bootstrapped_not_established;
pub mod proxied;
mod relocated;
mod relocated_not_established;

pub use self::{
    approved::Approved,
    base::{from_network_bytes, Base},
    bootstrapped::Bootstrapped,
    bootstrapped_not_established::BootstrappedNotEstablished,
    relocated::Relocated,
    relocated_not_established::RelocatedNotEstablished,
};
use crate::time::Duration;

pub const USER_MSG_CACHE_EXPIRY_DURATION: Duration = Duration::from_secs(120);

// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod approved;
mod base;

pub use self::{
    approved::Approved,
    base::{from_network_bytes, Base},
};
use crate::time::Duration;

#[cfg(feature = "mock_base")]
use crate::{utils::XorTargetInterval, xor_name::XorName};

pub(super) const GOSSIP_TIMEOUT: Duration = Duration::from_secs(2);

/// Development-only node data (used mainly for the mock-network tests).
#[cfg(feature = "mock_base")]
#[derive(Default)]
pub struct DevParams {
    // Value which can be set in mock-network tests to be used as the next relocation
    // destination.
    pub next_relocation_dst: Option<XorName>,
    // Interval used for relocation in mock network tests.
    // Note: this is currently unused.
    pub next_relocation_interval: Option<XorTargetInterval>,
}

#[cfg(not(feature = "mock_base"))]
#[derive(Default)]
pub struct DevParams;

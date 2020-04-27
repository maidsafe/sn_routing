// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{consensus::GenesisPfxInfo, section::SharedState};

/// Data chain.
pub struct Chain {
    /// The shared state of the section.
    pub state: SharedState,
}

#[allow(clippy::len_without_is_empty)]
impl Chain {
    /// Create a new chain given genesis information
    pub fn new(gen_info: GenesisPfxInfo) -> Self {
        Self {
            state: SharedState::new(gen_info.elders_info, gen_info.public_keys, gen_info.ages),
        }
    }
}

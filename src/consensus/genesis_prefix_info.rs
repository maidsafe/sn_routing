// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::section::EldersInfo;
use std::fmt::{self, Debug, Formatter};

/// Info sent to nodes to update them about the state of the section.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct GenesisPrefixInfo {
    pub elders_info: EldersInfo,
    pub public_keys: bls::PublicKeySet,
    pub parsec_version: u64,
}

impl Debug for GenesisPrefixInfo {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "GenesisPrefixInfo({:?}, elders_version: {}, parsec_version: {})",
            self.elders_info.prefix, self.elders_info.version, self.parsec_version,
        )
    }
}

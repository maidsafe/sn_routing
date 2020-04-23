// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    id::PublicId,
    section::{AgeCounter, EldersInfo},
};
use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Formatter},
};

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct GenesisPfxInfo {
    pub elders_info: EldersInfo,
    pub public_keys: bls::PublicKeySet,
    pub state_serialized: Vec<u8>,
    pub ages: BTreeMap<PublicId, AgeCounter>,
    pub parsec_version: u64,
}

impl GenesisPfxInfo {
    pub fn trimmed(&self) -> Self {
        Self {
            elders_info: self.elders_info.clone(),
            public_keys: self.public_keys.clone(),
            state_serialized: Vec::new(),
            ages: self.ages.clone(),
            parsec_version: self.parsec_version,
        }
    }
}

impl Debug for GenesisPfxInfo {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "GenesisPfxInfo({:?}, elders_version: {}, parsec_version: {})",
            self.elders_info.prefix(),
            self.elders_info.version(),
            self.parsec_version,
        )
    }
}

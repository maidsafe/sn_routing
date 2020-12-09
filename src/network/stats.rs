// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub struct NetworkStats {
    pub(super) known_elders: u64,
    pub(super) total_elders: u64,
    pub(super) total_elders_exact: bool,
}

impl NetworkStats {
    pub fn print(&self) {
        if self.total_elders_exact {
            info!("*** Exact total network elders: {} ***", self.known_elders)
        } else {
            info!(
                "*** Known network elders: {}, Estimated total network elders: {} ***",
                self.known_elders, self.total_elders
            )
        }
    }
}

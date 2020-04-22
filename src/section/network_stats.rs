// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::{cmp, iter};

pub struct NetworkStats {
    pub(super) known_elders: u64,
    pub(super) total_elders: u64,
    pub(super) total_elders_exact: bool,
}

impl NetworkStats {
    pub fn print(&self) {
        const LEVEL: log::Level = log::Level::Info;

        if log::log_enabled!(LEVEL) {
            let status_str = format!("Known elders: {:3}", self.known_elders);
            let network_estimate = if self.total_elders_exact {
                format!("Exact total network elders: {}", self.total_elders)
            } else {
                format!("Estimated total network elders: {}", self.total_elders)
            };
            let sep_len = cmp::max(status_str.len(), network_estimate.len());
            let sep_str = iter::repeat('-').take(sep_len).collect::<String>();
            log!(target: "stats", LEVEL, " -{}- ", sep_str);
            log!(target: "stats", LEVEL, "| {:<1$} |", status_str, sep_len);
            log!(target: "stats", LEVEL, "| {:<1$} |", network_estimate, sep_len);
            log!(target: "stats", LEVEL, " -{}- ", sep_str);
        }
    }
}

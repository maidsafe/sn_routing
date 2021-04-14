// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{supermajority, ELDER_SIZE};
use lru_time_cache::{Entry, LruCache};
use std::{collections::BTreeSet, iter, time::Duration};
use xor_name::XorName;

const COMPLAINT_EXPIRY_DURATION: Duration = Duration::from_secs(60);

// Structure to retain connectivity complaints from adults against an elder.
// The flag indicates whehter an accumulation has been reported.
pub(crate) struct ConnectivityComplaints {
    complaints: LruCache<XorName, (BTreeSet<XorName>, bool)>,
}

impl ConnectivityComplaints {
    pub fn new() -> Self {
        Self {
            complaints: LruCache::with_expiry_duration_and_capacity(
                COMPLAINT_EXPIRY_DURATION,
                ELDER_SIZE,
            ),
        }
    }

    // Received a complaint from an adult against an elder.
    pub fn add_complaint(&mut self, adult_name: XorName, elder_name: XorName) {
        match self.complaints.entry(elder_name) {
            Entry::Vacant(entry) => {
                let _ = entry.insert((iter::once(adult_name).collect(), false));
            }
            Entry::Occupied(entry) => {
                let _ = entry.into_mut().0.insert(adult_name);
            }
        }
    }

    // Check whether an elder got too many complaints among weighing adults.
    pub fn is_complained(
        &mut self,
        elder_name: XorName,
        weighing_adults: &BTreeSet<XorName>,
    ) -> bool {
        let threshold = supermajority(weighing_adults.len());
        match self.complaints.entry(elder_name) {
            Entry::Vacant(_) => false,
            Entry::Occupied(entry) => {
                let mut records = entry.into_mut();
                if records.1 {
                    // Already complained, return with false to avoid duplication.
                    false
                } else {
                    let complained_adults = records
                        .0
                        .iter()
                        .filter(|name| weighing_adults.contains(name))
                        .count();
                    if complained_adults >= threshold {
                        records.1 = true;
                        true
                    } else {
                        false
                    }
                }
            }
        }
    }
}

impl Default for ConnectivityComplaints {
    fn default() -> Self {
        Self::new()
    }
}

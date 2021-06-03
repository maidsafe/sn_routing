// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{cache::Cache, supermajority, ELDER_SIZE};
use dashmap::DashSet;
use std::iter;
use std::sync::Arc;
use std::{collections::BTreeSet, time::Duration};
use xor_name::XorName;

const COMPLAINT_EXPIRY_DURATION: Duration = Duration::from_secs(60);

// Structure to retain connectivity complaints from adults against an elder.
// The flag indicates whehter an accumulation has been reported.
pub(crate) struct ConnectivityComplaints {
    complaints: Cache<XorName, (Arc<DashSet<XorName>>, bool)>,
}

impl ConnectivityComplaints {
    pub fn new() -> Self {
        Self {
            complaints: Cache::with_expiry_duration_and_capacity(
                COMPLAINT_EXPIRY_DURATION,
                ELDER_SIZE,
            ),
        }
    }

    // Received a complaint from an adult against an elder.
    pub async fn add_complaint(&self, adult_name: XorName, elder_name: XorName) {
        if let Some((set, _)) = self.complaints.get(&elder_name).await {
            let _ = set.insert(adult_name);
        }
        match self.complaints.get(&elder_name).await {
            Some((set, _)) => {
                let _ = set.insert(adult_name);
            }
            None => {
                let set = Arc::new(iter::once(adult_name).collect());
                let _ = self.complaints.set(elder_name, (set, false), None).await;
            }
        };
    }

    // Check whether an elder got too many complaints among weighing adults.
    pub async fn is_complained(
        &self,
        elder_name: XorName,
        weighing_adults: &BTreeSet<XorName>,
    ) -> bool {
        let threshold = supermajority(weighing_adults.len());
        match self.complaints.get(&elder_name).await {
            None => false,
            Some((records, complained)) => {
                if complained {
                    // Already complained, return with false to avoid duplication.
                    false
                } else {
                    let complained_adults = records
                        .iter()
                        .filter(|name| weighing_adults.contains(name))
                        .count();
                    if complained_adults >= threshold {
                        let _ = self.complaints.set(elder_name, (records, true), None);
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

// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{observation::Observation, DkgResult, DkgResultWrapper, NetworkEvent, Proof, PublicId};
use std::collections::BTreeSet;
use std::rc::Rc;

#[serde(bound = "")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub struct Block<T: NetworkEvent, P: PublicId> {
    payload: Rc<Observation<T, P>>,
    proofs: BTreeSet<Proof<P>>,
}

impl<T: NetworkEvent, P: PublicId> Block<T, P> {
    pub(super) fn new<'a, I>(observation: Rc<Observation<T, P>>, proofs: I) -> Self
    where
        I: IntoIterator<Item = &'a Proof<P>>,
        P: 'a,
    {
        Self {
            payload: observation,
            proofs: proofs.into_iter().cloned().collect(),
        }
    }

    /// Create a `Block` with no signatures for a single DkgResult
    pub(super) fn new_dkg(participants: BTreeSet<P>, dkg_result: DkgResult) -> Self {
        Self {
            payload: Rc::new(Observation::DkgResult {
                participants,
                dkg_result: DkgResultWrapper(dkg_result),
            }),
            proofs: BTreeSet::new(),
        }
    }

    pub fn payload(&self) -> &Observation<T, P> {
        &*self.payload
    }

    pub fn proofs(&self) -> &BTreeSet<Proof<P>> {
        &self.proofs
    }
}

// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    observation::{Observation, ObservationInfo},
    NetworkEvent, Proof, PublicId,
};
use std::collections::BTreeSet;

#[serde(bound = "")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub struct Block<T: NetworkEvent, P: PublicId> {
    payload: Observation<T, P>,
    proofs: BTreeSet<Proof<P>>,
}

impl<T: NetworkEvent, P: PublicId> Block<T, P> {
    pub fn payload(&self) -> &Observation<T, P> {
        &self.payload
    }

    pub fn proofs(&self) -> &BTreeSet<Proof<P>> {
        &self.proofs
    }
}

pub(super) fn create<T: NetworkEvent, P: PublicId>(
    observation: Observation<T, P>,
    observation_info: &ObservationInfo<P>,
) -> Block<T, P> {
    let proofs = observation_info
        .votes()
        .map(|(_, proof)| proof.clone())
        .collect();

    Block {
        payload: observation,
        proofs,
    }
}

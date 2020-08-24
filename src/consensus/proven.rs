// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{consensus::Proof, section::SectionProofChain};
use serde::Serialize;
use std::{borrow::Borrow, fmt::Debug};
use xor_name::Prefix;

/// A value together with the proof that it was agreed on by the quorum of the section elders.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct Proven<T: Serialize> {
    pub value: T,
    pub proof: Proof,
}

impl<T: Serialize> Proven<T> {
    pub fn new(value: T, proof: Proof) -> Self {
        Self { value, proof }
    }

    pub fn verify(&self, history: &SectionProofChain) -> bool {
        history.has_key(&self.proof.public_key) && self.self_verify()
    }

    pub fn self_verify(&self) -> bool {
        bincode::serialize(&self.value)
            .map(|bytes| self.proof.verify(&bytes))
            .unwrap_or(false)
    }
}

impl<T> Borrow<Prefix> for Proven<T>
where
    T: Borrow<Prefix> + Serialize,
{
    fn borrow(&self) -> &Prefix {
        self.value.borrow()
    }
}

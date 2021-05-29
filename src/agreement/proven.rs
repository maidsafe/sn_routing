// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{verify_proof, Proof};
use secured_linked_list::SecuredLinkedList;
use serde::Serialize;
use sn_messaging::node::Proven;

pub trait ProvenUtils<T: Serialize> {
    fn new(value: T, proof: Proof) -> Self;

    fn verify(&self, section_chain: &SecuredLinkedList) -> bool;

    fn self_verify(&self) -> bool;
}

impl<T: Serialize> ProvenUtils<T> for Proven<T> {
    fn new(value: T, proof: Proof) -> Self {
        Self { value, proof }
    }

    fn verify(&self, section_chain: &SecuredLinkedList) -> bool {
        section_chain.has_key(&self.proof.public_key) && self.self_verify()
    }

    fn self_verify(&self) -> bool {
        verify_proof(&self.proof, &self.value)
    }
}

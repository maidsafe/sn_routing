// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::signature_accumulator::SignatureAccumulator;

// The approved stage - node is a full member of a section and is performing its duties according
// to its persona (infant, adult or elder).
pub struct Approved {
    pub sig_accumulator: SignatureAccumulator,
}

impl Approved {
    pub fn new(sig_accumulator: SignatureAccumulator) -> Self {
        Self { sig_accumulator }
    }
}

// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod dkg;
mod event_accumulator;
mod proven;
#[cfg(test)]
pub mod test_utils;
mod vote;

pub use self::{
    dkg::{generate_secret_key_set, threshold_count, DkgKey, DkgResult, DkgVoter},
    proven::Proven,
    vote::{Vote, VoteAccumulator},
};
pub use bls_signature_aggregator::{AccumulationError, Proof, ProofShare, SignatureAggregator};

#[cfg(feature = "mock")]
pub use self::event_accumulator::{UNRESPONSIVE_THRESHOLD, UNRESPONSIVE_WINDOW};

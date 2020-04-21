// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod event_accumulator;
mod parsec;

pub use self::{
    event_accumulator::{AccumulatingProof, ChainAccumulator, InsertError},
    parsec::{
        generate_bls_threshold_secret_key, generate_first_dkg_result, DkgResult, DkgResultWrapper,
        NetworkEvent as ParsecNetworkEvent, Observation, ParsecMap, Request as ParsecRequest,
        Response as ParsecResponse, GOSSIP_PERIOD,
    },
};

#[cfg(feature = "mock_base")]
pub use self::event_accumulator::{UNRESPONSIVE_THRESHOLD, UNRESPONSIVE_WINDOW};

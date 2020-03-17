// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod approved_peer;
mod bootstrapping_peer;
pub mod common;
mod joining_peer;

pub use self::{
    approved_peer::ApprovedPeer,
    bootstrapping_peer::{BootstrappingPeer, BootstrappingPeerDetails},
    joining_peer::JoiningPeer,
};

#[cfg(feature = "mock_base")]
pub use self::{bootstrapping_peer::BOOTSTRAP_TIMEOUT, joining_peer::JOIN_TIMEOUT};

// # The state machine
//
//            START
//              │
//              ▼
//      ┌───────────────┐
//      │ Bootstrapping │──────────┐
//      └───────────────┘          │
//        ▲           ▲            │
//        │           │            │
//        │           │            ▼
//        │           │          ┌─────────────┐
//        │           └──────────│ JoiningNode │
//        │                      └─────────────┘
//        │                        │
//        │                        │
//        │                        │
//        │                        ▼
//        │                      ┌──────────────┐
//        └──────────────────────│ ApprovedPeer │
//                               └──────────────┘
//
//
// # Common traits
//                              BootstrappingPeer
//                              │   JoininigPeer
//                              │   │   ApprovedPeer
//                              │   │   │
// Base                         *   *   *
//

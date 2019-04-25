// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod bootstrapping;
mod client;
pub mod common;
mod establishing_node;
mod node;
mod proving_node;
mod relocating_node;

pub use self::{
    bootstrapping::{Bootstrapping, TargetState as BootstrappingTargetState},
    client::{Client, RATE_EXCEED_RETRY},
    establishing_node::EstablishingNode,
    node::Node,
    proving_node::ProvingNode,
    relocating_node::RelocatingNode,
};

//
// # The state machine
//
//            START
//              │
//              ▼
//      ┌───────────────┐
//      │ Bootstrapping │──────────┐
//      └───────────────┘          │
//        │     │     ▲            │
//        │     │     │            │
//        │     ▼     │            ▼
//        │   ┌────────────────┐ ┌─────────────┐
//        │   │ RelocatingNode │ │ ProvingNode │
//        │   └────────────────┘ └─────────────┘
//        │                        │
//        │                        │
//        │                        ▼
//        │                      ┌──────────────────┐
//        │                      │ EstablishingNode │
//        │                      └──────────────────┘
//        │                        │
//        │                        │
//        ▼                        ▼
// ┌────────┐                    ┌──────┐
// │ Client │                    │ Node │
// └────────┘                    └──────┘
//
//
// # Common traits
//                           Bootstrapping
//                           │   Client
//                           │   │   RelocatingNode
//                           │   │   │   ProvingNode
//                           │   │   │   │   EstablishingNode
//                           │   │   │   │   │   Node
//                           │   │   │   │   │   │
// Base                      *   *   *   *   *   *
// Bootstrapped                  *   *   *   *   *
// NotEstablished                *   *   *   *
// Relocated                             *   *   *
// RelocatedNotEstablished               *   *
// Approved                                  *   *
//

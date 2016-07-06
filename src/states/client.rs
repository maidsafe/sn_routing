// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use crust::Event as CrustEvent;

use action::Action;
#[cfg(feature = "use-mock-crust")]
use routing_table::RoutingTable;
use state_machine::Transition;
use super::Node;

pub struct Client {
}

impl Client {
    // pub fn new() -> Self {
    //     Client {
    //     }
    // }

    pub fn handle_action(&mut self, _action: Action) -> Transition {
        Transition::Client
    }

    pub fn handle_crust_event(&mut self, _crust_event: CrustEvent) -> Transition {
        Transition::Client
    }

    pub fn into_node(self) -> Node {
        unimplemented!()
    }

    /// Routing table of this node.
    #[cfg(feature = "use-mock-crust")]
    pub fn routing_table(&self) -> &RoutingTable {
        unimplemented!()
    }

    /// resends all unacknowledged messages.
    #[cfg(feature = "use-mock-crust")]
    pub fn resend_unacknowledged(&mut self) -> bool {
        unimplemented!()
    }

    /// Are there any unacknowledged messages?
    #[cfg(feature = "use-mock-crust")]
    pub fn has_unacknowledged(&self) -> bool {
        unimplemented!()
    }

    /// Clears all state containers except `bootstrap_blacklist`.
    #[cfg(feature = "use-mock-crust")]
    pub fn clear_state(&mut self) {
        unimplemented!()
    }
}

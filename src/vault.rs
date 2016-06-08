// Copyright 2015 MaidSafe.net limited.
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

use std::rc::Rc;
use std::sync::mpsc::{self, Receiver};

#[cfg(feature = "use-mock-crust")]
use config_handler::Config;
use error::InternalError;
use kademlia_routing_table::RoutingTable;
use personas::maid_manager::MaidManager;
use personas::data_manager::DataManager;
#[cfg(feature = "use-mock-crust")]
use personas::data_manager::IdAndVersion;

use routing::{Authority, Data, Request, Response, XorName};
use sodiumoxide;

pub const CHUNK_STORE_PREFIX: &'static str = "safe-vault";
const DEFAULT_MAX_CAPACITY: u64 = 500 * 1024 * 1024;

pub use routing::Event;
pub use routing::Node as RoutingNode;

/// Main struct to hold all personas and Routing instance
pub struct Vault {
    maid_manager: MaidManager,
    data_manager: DataManager,
    routing_node: Rc<RoutingNode>,
    routing_receiver: Receiver<Event>,
}

impl Vault {
    /// Creates a network Vault instance.
    pub fn new(first_vault: bool) -> Result<Self, InternalError> {
        sodiumoxide::init();
        let (routing_sender, routing_receiver) = mpsc::channel();
        let routing_node = Rc::new(try!(RoutingNode::new(routing_sender, true, first_vault)));

        Ok(Vault {
            maid_manager: MaidManager::new(routing_node.clone()),
            data_manager: try!(DataManager::new(routing_node.clone(), DEFAULT_MAX_CAPACITY)),
            routing_node: routing_node.clone(),
            routing_receiver: routing_receiver,
        })
    }

    /// Allow replacing the default config values for use with the mock-crust tests.  This should
    /// only be called immediately after constructing a new Vault.
    #[cfg(feature = "use-mock-crust")]
    pub fn apply_config(&mut self, config: Config) -> Result<(), InternalError> {
        let max_capacity = config.max_capacity.unwrap_or(DEFAULT_MAX_CAPACITY);
        self.data_manager = try!(DataManager::new(self.routing_node.clone(), max_capacity));
        Ok(())
    }

    /// Run the event loop, processing events received from Routing.
    pub fn run(&mut self) -> Result<bool, InternalError> {
        while let Ok(event) = self.routing_receiver.recv() {
            if let Some(terminate) = self.process_event(event) {
                return Ok(terminate);
            }
        }
        // FIXME: decide if we want to restart here (in which case return `Ok(false)`).
        Ok(true)
    }

    /// Non-blocking call to process any events in the event queue, returning true if
    /// any received, otherwise returns false.
    #[cfg(feature = "use-mock-crust")]
    pub fn poll(&mut self) -> bool {
        let mut result = self.routing_node.poll();

        while let Ok(event) = self.routing_receiver.try_recv() {
            let _ignored_for_mock = self.process_event(event);
            result = true
        }

        result
    }

    /// Get the names of all the data chunks stored in a personas' chunk store.
    #[cfg(feature = "use-mock-crust")]
    pub fn get_stored_names(&self) -> Vec<IdAndVersion> {
        self.data_manager.get_stored_names()
    }

    /// Get the number of put requests the network processed for the given client.
    #[cfg(feature = "use-mock-crust")]
    pub fn get_maid_manager_put_count(&self, client_name: &XorName) -> Option<u64> {
        self.maid_manager.get_put_count(client_name)
    }

    /// Resend all unacknowledged messages.
    #[cfg(feature = "use-mock-crust")]
    pub fn resend_unacknowledged(&self) -> bool {
        self.routing_node.resend_unacknowledged()
    }

    /// Clear routing node state.
    #[cfg(feature = "use-mock-crust")]
    pub fn clear_state(&self) {
        self.routing_node.clear_state()
    }

    /// Vault node name
    #[cfg(feature = "use-mock-crust")]
    pub fn name(&self) -> XorName {
        unwrap_result!(self.routing_node.name())
    }

    fn process_event(&mut self, event: Event) -> Option<bool> {
        let name = self.routing_node
            .name()
            .expect("Failed to get name from routing node.");
        trace!("Vault {} received an event from routing: {:?}", name, event);

        let mut ret = None;

        if let Err(error) = match event {
            Event::Request { request, src, dst } => self.on_request(request, src, dst),
            Event::Response { response, src, dst } => self.on_response(response, src, dst),
            Event::NodeAdded(node_added, routing_table) => {
                self.on_node_added(node_added, routing_table)
            }
            Event::NodeLost(node_lost, routing_table) => {
                self.on_node_lost(node_lost, routing_table)
            }
            Event::Connected => self.on_connected(),
            Event::GetNodeNameFailed => {
                warn!("Received {:?}. Restarting Vault", event);
                ret = Some(false);
                Ok(())
            }
            Event::Disconnected |
            Event::NetworkStartupFailed => {
                ret = Some(true);
                Ok(())
            }
            Event::Tick => Ok(()),
        } {
            debug!("Failed to handle event: {:?}", error);
        }

        self.data_manager.check_timeouts();
        ret
    }

    fn on_request(&mut self,
                  request: Request,
                  src: Authority,
                  dst: Authority)
                  -> Result<(), InternalError> {
        match (src, dst, request) {
            // ================== Get ==================
            (src @ Authority::Client { .. },
             dst @ Authority::NaeManager(_),
             Request::Get(data_id, msg_id)) |
            (src @ Authority::ManagedNode(_),
             dst @ Authority::ManagedNode(_),
             Request::Get(data_id, msg_id)) => {
                self.data_manager.handle_get(src, dst, data_id, msg_id)
            }
            // ================== Put ==================
            (src @ Authority::Client { .. },
             dst @ Authority::ClientManager(_),
             Request::Put(data, msg_id)) => self.maid_manager.handle_put(src, dst, data, msg_id),
            (src @ Authority::ClientManager(_),
             dst @ Authority::NaeManager(_),
             Request::Put(data, msg_id)) => self.data_manager.handle_put(src, dst, data, msg_id),
            // ================== Post ==================
            (src @ Authority::Client { .. },
             dst @ Authority::NaeManager(_),
             Request::Post(Data::Structured(data), msg_id)) => {
                self.data_manager.handle_post(src, dst, data, msg_id)
            }
            // ================== Delete ==================
            (src @ Authority::Client { .. },
             dst @ Authority::NaeManager(_),
             Request::Delete(Data::Structured(data), msg_id)) => {
                self.data_manager.handle_delete(src, dst, data, msg_id)
            }
            // ================== Refresh ==================
            (Authority::ClientManager(_),
             Authority::ClientManager(_),
             Request::Refresh(serialised_msg, _)) => {
                self.maid_manager.handle_refresh(&serialised_msg)
            }
            (Authority::ManagedNode(src_name),
             Authority::ManagedNode(_),
             Request::Refresh(serialised_msg, _)) |
            (Authority::ManagedNode(src_name),
             Authority::NaeManager(_),
             Request::Refresh(serialised_msg, _)) => {
                self.data_manager.handle_refresh(src_name, &serialised_msg)
            }
            // ================== Invalid Request ==================
            (_, _, request) => Err(InternalError::UnknownRequestType(request)),
        }
    }

    fn on_response(&mut self,
                   response: Response,
                   src: Authority,
                   dst: Authority)
                   -> Result<(), InternalError> {
        match (src, dst, response) {
            // ================== GetSuccess ==================
            (Authority::ManagedNode(src_name),
             Authority::ManagedNode(_),
             Response::GetSuccess(data, _)) => self.data_manager.handle_get_success(src_name, data),
            // ================== GetFailure ==================
            (Authority::ManagedNode(src_name),
             Authority::ManagedNode(_),
             Response::GetFailure { data_id, .. }) => {
                self.data_manager.handle_get_failure(src_name, data_id)
            }
            // ================== PutSuccess ==================
            (Authority::NaeManager(_),
             Authority::ClientManager(_),
             Response::PutSuccess(data_id, msg_id)) => {
                self.maid_manager.handle_put_success(data_id, msg_id)
            }
            // ================== PutFailure ==================
            (Authority::NaeManager(_),
             Authority::ClientManager(_),
             Response::PutFailure { id, external_error_indicator, data_id }) => {
                self.maid_manager.handle_put_failure(id, data_id, &external_error_indicator)
            }
            // ================== Invalid Response ==================
            (_, _, response) => Err(InternalError::UnknownResponseType(response)),
        }
    }

    fn on_node_added(&mut self,
                     node_added: XorName,
                     routing_table: RoutingTable<XorName>)
                     -> Result<(), InternalError> {
        self.maid_manager.handle_node_added(&node_added, &routing_table);
        self.data_manager.handle_node_added(&node_added, &routing_table);
        Ok(())
    }

    fn on_node_lost(&mut self,
                    node_lost: XorName,
                    routing_table: RoutingTable<XorName>)
                    -> Result<(), InternalError> {
        self.maid_manager.handle_node_lost(&node_lost);
        self.data_manager.handle_node_lost(&node_lost, &routing_table);
        Ok(())
    }

    fn on_connected(&self) -> Result<(), InternalError> {
        // TODO: what is expected to be done here?
        debug!("Vault connected");
        Ok(())
    }
}

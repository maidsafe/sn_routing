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

#[cfg(any(test, feature = "use-mock-crust"))]
use config_handler::Config;
use error::InternalError;
use kademlia_routing_table::RoutingTable;
use personas::maid_manager::MaidManager;
use personas::data_manager::DataManager;
#[cfg(any(test, feature = "use-mock-crust"))]
use routing::DataIdentifier;
use routing::{Authority, Data, RequestContent, RequestMessage, ResponseContent, ResponseMessage,
              RoutingMessage};
use sodiumoxide;
use xor_name::XorName;

pub const CHUNK_STORE_PREFIX: &'static str = "safe-vault";
const DEFAULT_MAX_CAPACITY: u64 = 500 * 1024 * 1024;

pub use routing::Event;

pub use routing::NodeInfo;


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
    pub fn new() -> Result<Self, InternalError> {
        sodiumoxide::init();
        let (routing_sender, routing_receiver) = mpsc::channel();
        let routing_node = Rc::new(try!(RoutingNode::new(routing_sender, true)));

        Ok(Vault {
            maid_manager: MaidManager::new(routing_node.clone()),
            data_manager: try!(DataManager::new(routing_node.clone(), DEFAULT_MAX_CAPACITY)),
            routing_node: routing_node.clone(),
            routing_receiver: routing_receiver,
        })
    }

    /// Allow replacing the default config values for use with the mock-crust tests.  This should
    /// only be called immediately after constructing a new Vault.
    #[cfg(any(test, feature = "use-mock-crust"))]
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
    #[cfg(any(test, feature = "use-mock-crust"))]
    pub fn get_stored_names(&self) -> Vec<DataIdentifier> {
        self.data_manager.get_stored_names()
    }

    /// Get the number of put requests the network processed for the given client.
    #[cfg(any(test, feature = "use-mock-crust"))]
    pub fn get_maid_manager_put_count(&self, client_name: &XorName) -> Option<u64> {
        self.maid_manager.get_put_count(client_name)
    }

    fn process_event(&mut self, event: Event) -> Option<bool> {
        let name = self.routing_node
                       .name()
                       .expect("Failed to get name from routing node.");
        trace!("Vault {} received an event from routing: {:?}", name, event);

        let mut ret = None;

        if let Err(error) = match event {
            Event::Request(request) => self.on_request(request),
            Event::Response(response) => self.on_response(response),
            Event::NodeAdded(node_added, routing_table) => {
                self.on_node_added(node_added, routing_table)
            }
            Event::NodeLost(node_lost, routing_table) => {
                self.on_node_lost(node_lost, routing_table)
            }
            Event::Connected => self.on_connected(),
            Event::Disconnected |
            Event::GetNetworkNameFailed => {
                ret = Some(false);
                Ok(())
            }
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

    fn on_request(&mut self, request: RequestMessage) -> Result<(), InternalError> {
        match (&request.src, &request.dst, &request.content) {
            // ================== Get ==================
            (&Authority::Client { .. },
             &Authority::NaeManager(_),
             &RequestContent::Get(ref data_id, ref msg_id)) |
            (&Authority::ManagedNode(_),
             &Authority::ManagedNode(_),
             &RequestContent::Get(ref data_id, ref msg_id)) => {
                self.data_manager.handle_get(&request, data_id, msg_id)
            }
            // ================== Put ==================
            (&Authority::Client { .. },
             &Authority::ClientManager(_),
             &RequestContent::Put(ref data, ref msg_id)) => {
                self.maid_manager.handle_put(&request, data, msg_id)
            }
            (&Authority::ClientManager(_),
             &Authority::NaeManager(_),
             &RequestContent::Put(ref data, ref msg_id)) => {
                self.data_manager
                    .handle_put(&request, data, msg_id)
            }
            // ================== Post ==================
            (&Authority::Client { .. },
             &Authority::NaeManager(_),
             &RequestContent::Post(Data::Structured(ref data), ref msg_id)) => {
                self.data_manager.handle_post(&request, data, msg_id)
            }
            // ================== Delete ==================
            (&Authority::Client { .. },
             &Authority::NaeManager(_),
             &RequestContent::Delete(Data::Structured(ref data), ref msg_id)) => {
                self.data_manager.handle_delete(&request, data, msg_id)
            }
            // ================== Refresh ==================
            (&Authority::ClientManager(_),
             &Authority::ClientManager(_),
             &RequestContent::Refresh(ref serialised_msg, _)) => {
                self.maid_manager.handle_refresh(serialised_msg)
            }
            (&Authority::ManagedNode(ref src),
             &Authority::ManagedNode(_),
             &RequestContent::Refresh(ref serialised_msg, _)) |
            (&Authority::ManagedNode(ref src),
             &Authority::NaeManager(_),
             &RequestContent::Refresh(ref serialised_msg, _)) => {
                self.data_manager.handle_refresh(src, serialised_msg)
            }
            // ================== Invalid Request ==================
            _ => Err(InternalError::UnknownMessageType(RoutingMessage::Request(request.clone()))),
        }
    }

    fn on_response(&mut self, response: ResponseMessage) -> Result<(), InternalError> {
        match (&response.src, &response.dst, &response.content) {
            // ================== GetSuccess ==================
            (&Authority::ManagedNode(ref src),
             &Authority::ManagedNode(_),
             &ResponseContent::GetSuccess(ref data, _)) => {
                self.data_manager.handle_get_success(src, data)
            }
            // ================== GetFailure ==================
            (&Authority::ManagedNode(ref src),
             &Authority::ManagedNode(_),
             &ResponseContent::GetFailure {
                    request: RequestMessage {
                        content: RequestContent::Get(ref identifier, _), ..
                    },
                    .. }) => self.data_manager.handle_get_failure(src, identifier),
            // ================== PutSuccess ==================
            (&Authority::NaeManager(_),
             &Authority::ClientManager(_),
             &ResponseContent::PutSuccess(ref data_id, ref msg_id)) => {
                self.maid_manager.handle_put_success(data_id, msg_id)
            }
            // ================== PutFailure ==================
            (&Authority::NaeManager(_),
             &Authority::ClientManager(_),
             &ResponseContent::PutFailure{
                    ref id,
                    request: RequestMessage {
                        content: RequestContent::Put(_, _), .. },
                    ref external_error_indicator }) => {
                self.maid_manager.handle_put_failure(id, external_error_indicator)
            }
            // ================== Invalid Response ==================
            _ => Err(InternalError::UnknownMessageType(RoutingMessage::Response(response.clone()))),
        }
    }

    fn on_node_added(&mut self,
                     node_added: XorName,
                     routing_table: RoutingTable<NodeInfo>)
                     -> Result<(), InternalError> {
        self.maid_manager.handle_node_added(&node_added);
        self.data_manager.handle_node_added(&node_added, &routing_table);
        Ok(())
    }

    fn on_node_lost(&mut self,
                    node_lost: XorName,
                    routing_table: RoutingTable<NodeInfo>)
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

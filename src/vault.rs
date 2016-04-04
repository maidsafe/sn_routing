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

use ctrlc::CtrlC;
use maidsafe_utilities::serialisation;
use routing::{Authority, Data, DataRequest, Event, RequestContent, RequestMessage,
              ResponseContent, ResponseMessage, RoutingMessage};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use xor_name::XorName;

use config_handler;
use error::InternalError;
use personas::immutable_data_manager::ImmutableDataManager;
use personas::maid_manager::MaidManager;
use personas::mpid_manager::MpidManager;
use personas::pmid_manager::PmidManager;
use personas::pmid_node::PmidNode;
use personas::structured_data_manager::StructuredDataManager;
use types::{Refresh, RefreshValue};

pub const CHUNK_STORE_PREFIX: &'static str = "safe-vault";
const DEFAULT_MAX_CAPACITY: u64 = 1_073_741_824;
const PMID_NODE_ALLOWANCE: f64 = 0.6;
const STUCTURED_DATA_MANAGER_ALLOWANCE: f64 = 0.3;
const MPID_MANAGER_ALLOWANCE: f64 = 0.1;

#[cfg(not(all(test, feature = "use-mock-routing")))]
pub type RoutingNode = ::routing::Node;

#[cfg(all(test, feature = "use-mock-routing"))]
pub type RoutingNode = ::mock_routing::MockRoutingNode;

/// Main struct to hold all personas and Routing instance
pub struct Vault {
    immutable_data_manager: ImmutableDataManager,
    maid_manager: MaidManager,
    mpid_manager: MpidManager,
    pmid_manager: PmidManager,
    pmid_node: PmidNode,
    structured_data_manager: StructuredDataManager,
    stop_receiver: Option<Receiver<()>>,
    app_event_sender: Option<Sender<Event>>,
}

impl Vault {
    pub fn run() {
        let (stop_sender, stop_receiver) = mpsc::channel();

        // Handle Ctrl+C to properly stop the vault instance.
        // TODO: this should probably be moved over to main.
        CtrlC::set_handler(move || {
            let _ = stop_sender.send(());
        });

        // TODO - Keep retrying to construct new Vault until returns Ok() rather than using unwrap?
        unwrap_result!(unwrap_result!(Vault::new(None, stop_receiver)).do_run());
    }

    fn new(app_event_sender: Option<Sender<Event>>,
           stop_receiver: Receiver<()>)
           -> Result<Vault, InternalError> {
        ::sodiumoxide::init();
        let config = try!(config_handler::read_config_file());
        let max_capacity = config.max_capacity.unwrap_or(DEFAULT_MAX_CAPACITY) as f64;
        let pn_capacity = (max_capacity * PMID_NODE_ALLOWANCE) as u64;
        let sdm_capacity = (max_capacity * STUCTURED_DATA_MANAGER_ALLOWANCE) as u64;
        let mpid_capacity = (max_capacity * MPID_MANAGER_ALLOWANCE) as u64;
        Ok(Vault {
            immutable_data_manager: ImmutableDataManager::new(),
            maid_manager: MaidManager::new(),
            mpid_manager: try!(MpidManager::new(mpid_capacity)),
            pmid_manager: PmidManager::new(),
            pmid_node: try!(PmidNode::new(pn_capacity)),
            structured_data_manager: try!(StructuredDataManager::new(sdm_capacity)),
            stop_receiver: Some(stop_receiver),
            app_event_sender: app_event_sender,
        })
    }

    fn do_run(&mut self) -> Result<(), InternalError> {
        let (routing_sender, routing_receiver) = mpsc::channel();

        let routing_node = try!(RoutingNode::new(routing_sender));
        let routing_node1 = Arc::new(Mutex::new(Some(routing_node)));
        let routing_node2 = routing_node1.clone();

        // Take the stop_receiver from self, so we can move it into the stop thread.
        let stop_receiver = unwrap_option!(self.stop_receiver.take(), "");

        // Listen for stop event and destroy the routing node if one is received.  Destroying it
        // will close the routing event channel, stopping the main event loop.
        let stop_thread_handle = thread::spawn(move || {
            let _ = stop_receiver.recv();
            let _ = unwrap_result!(routing_node1.lock()).take();

            stop_receiver
        });

        for event in routing_receiver.iter() {
            let routing_node = unwrap_result!(routing_node2.lock());

            if routing_node.is_none() {
                break;
            }

            let routing_node = unwrap_option!(routing_node.as_ref(), "");

            trace!("Vault {} received an event from routing: {:?}",
                   unwrap_result!(routing_node.name()),
                   event);

            let _ = self.app_event_sender
                        .clone()
                        .and_then(|sender| Some(sender.send(event.clone())));

            if let Err(error) = match event {
                Event::Request(request) => self.on_request(routing_node, request),
                Event::Response(response) => self.on_response(routing_node, response),
                Event::NodeAdded(node_added) => self.on_node_added(routing_node, node_added),
                Event::NodeLost(node_lost) => self.on_node_lost(routing_node, node_lost),
                Event::Connected => self.on_connected(),
                Event::Disconnected => self.on_disconnected(),
            } {
                warn!("Failed to handle event: {:?}", error);
            }

            self.immutable_data_manager.check_timeout(routing_node);
            self.pmid_manager.check_timeout(routing_node);
        }

        // Return the stop_receiver back to self, in case we want to call do_run again.
        self.stop_receiver = Some(unwrap_result!(stop_thread_handle.join()));

        Ok(())
    }

    fn on_request(&mut self,
                  routing_node: &RoutingNode,
                  request: RequestMessage)
                  -> Result<(), InternalError> {
        match (&request.src, &request.dst, &request.content) {
            // ================== Get ==================
            (&Authority::Client { .. },
             &Authority::NaeManager(_),
             &RequestContent::Get(DataRequest::Immutable(_, _), _)) |
            (&Authority::NaeManager(_),
             &Authority::NaeManager(_),
             &RequestContent::Get(DataRequest::Immutable(_, _), _)) => {
                self.immutable_data_manager.handle_get(routing_node, &request)
            }
            (&Authority::Client { .. },
             &Authority::NaeManager(_),
             &RequestContent::Get(DataRequest::Structured(_, _), _)) => {
                self.structured_data_manager.handle_get(routing_node, &request)
            }
            (&Authority::NaeManager(_),
             &Authority::ManagedNode(_),
             &RequestContent::Get(DataRequest::Immutable(_, _), _)) => {
                self.pmid_node.handle_get(routing_node, &request)
            }
            // ================== Put ==================
            (&Authority::Client { .. },
             &Authority::ClientManager(_),
             &RequestContent::Put(Data::Immutable(_), _)) |
            (&Authority::Client { .. },
             &Authority::ClientManager(_),
             &RequestContent::Put(Data::Structured(_), _)) => {
                self.maid_manager.handle_put(routing_node, &request)
            }
            (&Authority::Client { .. },
             &Authority::ClientManager(_),
             &RequestContent::Put(Data::Plain(_), _)) |
            (&Authority::ClientManager(_),
             &Authority::ClientManager(_),
             &RequestContent::Put(Data::Plain(_), _)) => {
                self.mpid_manager.handle_put(routing_node, &request)
            }
            (&Authority::ClientManager(_),
             &Authority::NaeManager(_),
             &RequestContent::Put(Data::Immutable(_), _)) |
            (&Authority::NaeManager(_),
             &Authority::NaeManager(_),
             &RequestContent::Put(Data::Immutable(_), _)) => {
                self.immutable_data_manager.handle_put(routing_node, &request)
            }
            (&Authority::ClientManager(_),
             &Authority::NaeManager(_),
             &RequestContent::Put(Data::Structured(_), _)) => {
                self.structured_data_manager.handle_put(routing_node, &request)
            }
            (&Authority::NaeManager(_),
             &Authority::NodeManager(_),
             &RequestContent::Put(Data::Immutable(_), _)) => {
                self.pmid_manager.handle_put(routing_node, &request)
            }
            (&Authority::NodeManager(_),
             &Authority::ManagedNode(_),
             &RequestContent::Put(Data::Immutable(_), _)) => {
                self.pmid_node.handle_put(routing_node, &request)
            }
            // ================== Post ==================
            (&Authority::NaeManager(_),
             &Authority::NodeManager(_),
             &RequestContent::Post(_, _)) => self.pmid_manager.handle_post(&request),
            (&Authority::Client { .. },
             &Authority::NaeManager(_),
             &RequestContent::Post(Data::Structured(_), _)) => {
                self.structured_data_manager.handle_post(routing_node, &request)
            }
            (&Authority::Client { .. },
             &Authority::ClientManager(_),
             &RequestContent::Post(Data::Plain(_), _)) |
            (&Authority::ClientManager(_),
             &Authority::ClientManager(_),
             &RequestContent::Post(Data::Plain(_), _)) => {
                self.mpid_manager.handle_post(routing_node, &request)
            }
            // ================== Delete ==================
            (&Authority::Client { .. },
             &Authority::ClientManager(_),
             &RequestContent::Delete(Data::Plain(_), _)) => {
                self.mpid_manager.handle_delete(routing_node, &request)
            }
            (&Authority::Client { .. },
             &Authority::NaeManager(_),
             &RequestContent::Delete(Data::Structured(_), _)) => {
                self.structured_data_manager.handle_delete(routing_node, &request)
            }
            // ================== Refresh ==================
            (src, dst, &RequestContent::Refresh(ref serialised_refresh)) => {
                self.on_refresh(src, dst, serialised_refresh)
            }
            // ================== Invalid Request ==================
            _ => Err(InternalError::UnknownMessageType(RoutingMessage::Request(request.clone()))),
        }
    }

    fn on_response(&mut self,
                   routing_node: &RoutingNode,
                   response: ResponseMessage)
                   -> Result<(), InternalError> {
        match (&response.src, &response.dst, &response.content) {
            // ================== GetSuccess ==================
            (&Authority::ManagedNode(_),
             &Authority::NaeManager(_),
             &ResponseContent::GetSuccess(Data::Immutable(_), _)) |
            (&Authority::NaeManager(_),
             &Authority::NaeManager(_),
             &ResponseContent::GetSuccess(Data::Immutable(_), _)) => {
                self.immutable_data_manager.handle_get_success(routing_node, &response)
            }
            // ================== GetFailure ==================
            (&Authority::ManagedNode(ref pmid_node),
             &Authority::NaeManager(_),
             &ResponseContent::GetFailure { ref id, ref request, ref external_error_indicator }) => {
                self.immutable_data_manager
                    .handle_get_failure(routing_node,
                                        pmid_node,
                                        id,
                                        request,
                                        external_error_indicator)
            }
            (&Authority::NaeManager(_),
             &Authority::NaeManager(_),
             &ResponseContent::GetFailure { ref request, .. }) => {
                self.immutable_data_manager
                    .handle_get_from_other_location_failure(routing_node, request)
            }
            // ================== PutSuccess ==================
            (&Authority::NaeManager(_),
             &Authority::ClientManager(_),
             &ResponseContent::PutSuccess(_, ref message_id)) => {
                self.maid_manager.handle_put_success(routing_node, message_id)
            }
            (&Authority::NodeManager(ref pmid_node),
             &Authority::NaeManager(_),
             &ResponseContent::PutSuccess(_, ref message_id)) => {
                self.immutable_data_manager.handle_put_success(pmid_node, message_id)
            }
            (&Authority::ManagedNode(ref pmid_node),
             &Authority::NodeManager(_),
             &ResponseContent::PutSuccess(_, ref message_id)) => {
                self.pmid_manager.handle_put_success(routing_node, pmid_node, message_id)
            }
            // ================== PutFailure ==================
            (&Authority::NaeManager(_),
             &Authority::ClientManager(_),
             &ResponseContent::PutFailure{
                    ref id,
                    request: RequestMessage {
                        content: RequestContent::Put(Data::Structured(_), _), .. },
                    ref external_error_indicator }) => {
                self.maid_manager.handle_put_failure(routing_node, id, external_error_indicator)
            }
            (&Authority::NodeManager(ref pmid_node),
             &Authority::NaeManager(_),
             &ResponseContent::PutFailure { ref id, .. }) => {
                self.immutable_data_manager.handle_put_failure(routing_node, pmid_node, id)
            }
            (&Authority::ManagedNode(_),
             &Authority::NodeManager(_),
             &ResponseContent::PutFailure { ref request, .. }) => {
                self.pmid_manager.handle_put_failure(routing_node, request)
            }
            (&Authority::ClientManager(_),
             &Authority::ClientManager(_),
             &ResponseContent::PutFailure { ref request, .. }) => {
                self.mpid_manager.handle_put_failure(routing_node, request)
            }
            // ================== Invalid Response ==================
            _ => Err(InternalError::UnknownMessageType(RoutingMessage::Response(response.clone()))),
        }
    }

    fn on_node_added(&mut self,
                     routing_node: &RoutingNode,
                     node_added: XorName)
                     -> Result<(), InternalError> {
        self.maid_manager.handle_churn(routing_node);
        self.immutable_data_manager.handle_node_added(routing_node, node_added);
        self.structured_data_manager.handle_churn(routing_node);
        self.pmid_manager.handle_churn(routing_node);
        self.pmid_node.handle_churn(routing_node);
        self.mpid_manager.handle_churn(routing_node);
        Ok(())
    }

    fn on_node_lost(&mut self,
                    routing_node: &RoutingNode,
                    node_lost: XorName)
                    -> Result<(), InternalError> {
        self.maid_manager.handle_churn(routing_node);
        self.immutable_data_manager.handle_node_lost(routing_node, node_lost);
        self.structured_data_manager.handle_churn(routing_node);
        self.pmid_manager.handle_churn(routing_node);
        self.pmid_node.handle_churn(routing_node);
        self.mpid_manager.handle_churn(routing_node);
        Ok(())
    }

    fn on_connected(&self) -> Result<(), InternalError> {
        // TODO: what is expected to be done here?
        debug!("Vault connected");
        Ok(())
    }

    fn on_disconnected(&self) -> Result<(), InternalError> {
        // TODO: restart event loop with new routing object, discarding all current data
        debug!("Vault disconnected");
        Ok(())
    }

    fn on_refresh(&mut self,
                  src: &Authority,
                  dst: &Authority,
                  serialised_refresh: &[u8])
                  -> Result<(), InternalError> {
        let refresh = try!(serialisation::deserialise::<Refresh>(serialised_refresh));
        match (src, dst, &refresh.value) {
            (&Authority::ClientManager(_),
             &Authority::ClientManager(_),
             &RefreshValue::MaidManagerAccount(ref account)) => {
                Ok(self.maid_manager.handle_refresh(refresh.name, account.clone()))
            }
            (&Authority::ClientManager(_),
             &Authority::ClientManager(_),
             &RefreshValue::MpidManagerAccount(ref account,
                                               ref stored_messages,
                                               ref received_headers)) => {
                Ok(self.mpid_manager
                       .handle_refresh(refresh.name, account, stored_messages, received_headers))
            }
            (&Authority::NaeManager(_),
             &Authority::NaeManager(_),
             &RefreshValue::ImmutableDataManagerAccount(ref account)) => {
                Ok(self.immutable_data_manager.handle_refresh(refresh.name, account.clone()))
            }
            (&Authority::NaeManager(_),
             &Authority::NaeManager(_),
             &RefreshValue::StructuredDataManager(ref structured_data)) => {
                self.structured_data_manager.handle_refresh(structured_data.clone())
            }
            (&Authority::NodeManager(_),
             &Authority::NodeManager(_),
             &RefreshValue::PmidManagerAccount(ref account)) => {
                Ok(self.pmid_manager.handle_refresh(refresh.name, account.clone()))
            }
            _ => Err(InternalError::UnknownRefreshType(src.clone(), dst.clone(), refresh.clone())),
        }
    }
}

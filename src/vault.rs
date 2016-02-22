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

use error::InternalError;
use personas::immutable_data_manager::ImmutableDataManager;
use personas::maid_manager::MaidManager;
use personas::mpid_manager::MpidManager;
use personas::pmid_manager::PmidManager;
use personas::pmid_node::PmidNode;
use personas::structured_data_manager::StructuredDataManager;
use types::{Refresh, RefreshValue};

#[cfg(not(all(test, feature = "use-mock-routing")))]
pub type RoutingNode = ::routing::Node;

#[cfg(all(test, feature = "use-mock-routing"))]
pub type RoutingNode = ::mock_routing::MockRoutingNode;

#[allow(unused)]
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
        let _ = unwrap_result!(unwrap_result!(Vault::new(None, stop_receiver)).do_run());
    }

    fn new(app_event_sender: Option<Sender<Event>>,
           stop_receiver: Receiver<()>)
           -> Result<Vault, InternalError> {
        ::sodiumoxide::init();

        Ok(Vault {
            immutable_data_manager: ImmutableDataManager::new(),
            maid_manager: MaidManager::new(),
            mpid_manager: MpidManager::new(),
            pmid_manager: PmidManager::new(),
            pmid_node: try!(PmidNode::new()),
            structured_data_manager: StructuredDataManager::new(),
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
        let stop_receiver = self.stop_receiver.take().unwrap();

        // Listen for stop event and destroy the routing node if one is received.  Destroying it
        // will close the routing event channel, stopping the main event loop.
        let stop_thread_handle = thread::spawn(move || {
            let _ = stop_receiver.recv();
            let _ = routing_node1.lock().unwrap().take();

            stop_receiver
        });

        for event in routing_receiver.iter() {
            let routing_node = routing_node2.lock().unwrap();

            if routing_node.is_none() {
                break;
            }

            let routing_node = routing_node.as_ref().unwrap();

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
            } {
                warn!("Failed to handle event: {:?}", error);
            }
        }

        // Return the stop_receiver back to self, in case we want to call do_run again.
        self.stop_receiver = Some(stop_thread_handle.join().unwrap());

        Ok(())
    }

    fn on_request(&mut self,
                  routing_node: &RoutingNode,
                  request: RequestMessage)
                  -> Result<(), InternalError> {
        match (&request.src, &request.dst, &request.content) {
            // ================== Get ==================
            (&Authority::Client{ .. },
             &Authority::NaeManager(_),
             &RequestContent::Get(DataRequest::ImmutableData(_, _), _)) => {
                self.immutable_data_manager.handle_get(routing_node, &request)
            }
            (&Authority::Client{ .. },
             &Authority::NaeManager(_),
             &RequestContent::Get(DataRequest::StructuredData(_, _), _)) => {
                self.structured_data_manager.handle_get(routing_node, &request)
            }
            (&Authority::NaeManager(_),
             &Authority::ManagedNode(_),
             &RequestContent::Get(DataRequest::ImmutableData(_, _), _)) => {
                self.pmid_node.handle_get(routing_node, &request)
            }
            // ================== Put ==================
            (&Authority::Client{ .. },
             &Authority::ClientManager(_),
             &RequestContent::Put(Data::ImmutableData(_), _)) |
            (&Authority::Client{ .. },
             &Authority::ClientManager(_),
             &RequestContent::Put(Data::StructuredData(_), _)) => {
                self.maid_manager.handle_put(routing_node, &request)
            }
            (&Authority::Client{ .. },
             &Authority::ClientManager(_),
             &RequestContent::Put(Data::PlainData(_), _)) |
            (&Authority::ClientManager(_),
             &Authority::ClientManager(_),
             &RequestContent::Put(Data::PlainData(_), _)) => {
                self.mpid_manager.handle_put(routing_node, &request)
            }
            (&Authority::ClientManager(_),
             &Authority::NaeManager(_),
             &RequestContent::Put(Data::ImmutableData(ref data), ref message_id)) => {
                self.immutable_data_manager.handle_put(routing_node, data, message_id)
            }
            (&Authority::ClientManager(_),
             &Authority::NaeManager(_),
             &RequestContent::Put(Data::StructuredData(_), _)) => {
                self.structured_data_manager.handle_put(routing_node, &request)
            }
            (&Authority::NaeManager(_),
             &Authority::NodeManager(pmid_node_name),
             &RequestContent::Put(Data::ImmutableData(ref data), ref message_id)) => {
                self.pmid_manager.handle_put(routing_node, data, message_id, pmid_node_name)
            }
            (&Authority::NodeManager(_),
             &Authority::ManagedNode(_),
             &RequestContent::Put(Data::ImmutableData(_), _)) => {
                self.pmid_node.handle_put(&request)
            }
            // ================== Post ==================
            (&Authority::Client{ .. },
             &Authority::NaeManager(_),
             &RequestContent::Post(Data::StructuredData(_), _)) => {
                self.structured_data_manager.handle_post(routing_node, &request)
            }
            (&Authority::Client{ .. },
             &Authority::ClientManager(_),
             &RequestContent::Post(Data::PlainData(_), _)) |
            (&Authority::ClientManager(_),
             &Authority::ClientManager(_),
             &RequestContent::Post(Data::PlainData(_), _)) => {
                self.mpid_manager.handle_post(routing_node, &request)
            }
            // ================== Delete ==================
            (&Authority::Client{ .. },
             &Authority::ClientManager(_),
             &RequestContent::Delete(Data::PlainData(_), _)) => {
                self.mpid_manager.handle_delete(routing_node, &request)
            }
            (&Authority::Client{ .. },
             &Authority::NaeManager(_),
             &RequestContent::Delete(Data::StructuredData(_), _)) => {
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
             &ResponseContent::GetSuccess(Data::ImmutableData(_), _)) => {
                self.immutable_data_manager.handle_get_success(routing_node, &response)
            }
            // ================== GetFailure ==================
            (&Authority::ManagedNode(ref pmid_node),
             &Authority::NaeManager(_),
             &ResponseContent::GetFailure{ ref id, ref request, ref external_error_indicator }) => {
                self.immutable_data_manager
                    .handle_get_failure(routing_node,
                                        pmid_node,
                                        id,
                                        request,
                                        external_error_indicator)
            }
            // ================== PutSuccess ==================
            (&Authority::NaeManager(_),
             &Authority::ClientManager(_),
             &ResponseContent::PutSuccess(_, ref message_id)) => {
                self.maid_manager.handle_put_success(routing_node, message_id)
            }
            // ================== PutFailure ==================
            (&Authority::NaeManager(_),
             &Authority::ClientManager(_),
             &ResponseContent::PutFailure{ ref id, ref external_error_indicator, .. }) => {
                self.maid_manager.handle_put_failure(routing_node, id, external_error_indicator)
            }
            (&Authority::ClientManager(_),
             &Authority::ClientManager(_),
             &ResponseContent::PutFailure{ ref request, .. }) => {
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
        self.mpid_manager.handle_churn(routing_node);
        Ok(())
    }

    fn on_connected(&self) -> Result<(), InternalError> {
        // TODO: what is expected to be done here?
        debug!("Vault connected");
        // assert_eq!(kademlia_routing_table::GROUP_SIZE, self.immutable_data_manager.nodes_in_table_len());
        Ok(())
    }

    fn on_refresh(&mut self,
                  src: &Authority,
                  dst: &Authority,
                  serialised_refresh: &Vec<u8>)
                  -> Result<(), InternalError> {
        let refresh = try!(serialisation::deserialise::<Refresh>(serialised_refresh));
        match (src, dst, &refresh.value) {
            (&Authority::ClientManager(_),
             &Authority::ClientManager(_),
             &RefreshValue::MaidManager(ref account)) => {
                Ok(self.maid_manager.handle_refresh(refresh.name, account.clone()))
            }
            (&Authority::ClientManager(_),
             &Authority::ClientManager(_),
             &RefreshValue::MpidManager(ref account, ref stored_messages, ref received_headers)) => {
                Ok(self.mpid_manager
                       .handle_refresh(refresh.name, account, stored_messages, received_headers))
            }
            (&Authority::NaeManager(_),
             &Authority::NaeManager(_),
             &RefreshValue::ImmutableDataManager(ref account)) => {
                Ok(self.immutable_data_manager.handle_refresh(refresh.name, account.clone()))
            }
            (&Authority::NaeManager(_),
             &Authority::NaeManager(_),
             &RefreshValue::StructuredDataManager(ref structured_data)) => {
                self.structured_data_manager.handle_refresh(structured_data.clone())
            }
            (&Authority::NodeManager(_),
             &Authority::NodeManager(_),
             &RefreshValue::PmidManager(ref account)) => {
                Ok(self.pmid_manager.handle_refresh(refresh.name, account.clone()))
            }
            _ => Err(InternalError::UnknownRefreshType(src.clone(), dst.clone(), refresh.clone())),
        }
    }
}



// #[cfg(all(test, not(feature = "use-mock-routing")))]
// mod test {
//     use super::*;
//     use kademlia_routing_table::GROUP_SIZE;
//     use maidsafe_utilities::log;
//     use maidsafe_utilities::thread::RaiiThreadJoiner;
//     use personas::immutable_data_manager;
//     use rand::random;
//     use routing::{Authority, Data, DataRequest, Event, FullId, ImmutableData, ImmutableDataType, RequestContent,
//                   RequestMessage, ResponseContent, ResponseMessage, StructuredData};
//     use routing::Client as RoutingClient;
//     use std::io::Write;
//     use std::sync::mpsc::{self, Receiver, Sender};
//     use std::thread;
//     use time::{Duration, SteadyTime};
//     use utils::generate_random_vec_u8;
//     use xor_name::XorName;

//     struct VaultComms {
//         notifier: Receiver<(Event)>,
//         killer: Sender<()>,
//         _raii_thread_joiner: Option<RaiiThreadJoiner>,
//     }

//     impl VaultComms {
//         fn new(index: usize) -> VaultComms {
//             println!("Starting vault {}", index);
//             let (event_sender, event_receiver) = mpsc::channel();
//             let (stop_sender, stop_receiver) = mpsc::channel();

//             let mut vault = unwrap_result!(Vault::new(Some(event_sender), stop_receiver));
//             let join_handle = Some(RaiiThreadJoiner::new(thread!(format!("Vault {} worker", index),
//                                                                  move || unwrap_result!(vault.do_run()))));
//             let vault_comms = VaultComms {
//                 notifier: event_receiver,
//                 killer: stop_sender,
//                 _raii_thread_joiner: join_handle,
//             };
//             // let mut temp_comms = vec![vault_comms];
//             thread::sleep(::std::time::Duration::from_secs(3 + index as u64));
//             // let _ = unwrap_result!(wait_for_hits(&temp_comms,
//             //                                      10,
//             //                                      index,
//             //                                      Duration::seconds(10 * (index + 1) as i64)));
//             // temp_comms.remove(0)
//             vault_comms
//         }

//         fn stop(&mut self) {
//             let _ = self.killer.send(());
//         }
//     }

//     struct Client {
//         routing: RoutingClient,
//         receiver: ::std::sync::mpsc::Receiver<Data>,
//         name: XorName,
//     }

//     impl Client {
//         fn new() -> Client {
//             let client_receiving = |routing_receiver: Receiver<Event>,
//                                     network_event_sender: Sender<Event>,
//                                     client_sender: Sender<Data>| {
//                 let _ = thread::spawn(move || {
//                     while let Ok(event) = routing_receiver.recv() {
//                         match event {
//                             Event::Request(request) => panic!("Received {:?}", request),
//                             Event::Response(response) => {
//                                 info!("Received {:?}", response);
//                                 match response {
//                                     ResponseMessage{ content: ResponseContent::GetSuccess(data, _), .. } => {
//                                         let _ = client_sender.send(data);
//                                     }
//                                     _ => unreachable!("Unexpected {:?}", response),
//                                 }
//                             }
//                             Event::Churn{ .. } => info!("client received a churn"),
//                             Event::Connected => unwrap_result!(network_event_sender.send(Event::Connected)),
//                         };
//                     }
//                 });
//             };
//             let (routing_sender, routing_receiver) = mpsc::channel();
//             let (network_event_sender, network_event_receiver) = mpsc::channel();
//             let (data_sender, data_receiver) = mpsc::channel();
//             let _ = client_receiving(routing_receiver, network_event_sender, data_sender);

//             let id = FullId::new();
//             let client_name = id.public_id().name().clone();
//             let client_routing = unwrap_result!(RoutingClient::new(routing_sender, Some(id)));
//             let starting_time = SteadyTime::now();
//             let time_limit = Duration::minutes(1);
//             loop {
//                 match network_event_receiver.try_recv() {
//                     Ok(Event::Connected) => break,
//                     Err(_) => (),
//                     _ => panic!("Failed to connect"),
//                 }
//                 ::std::thread::sleep(::std::time::Duration::from_millis(100));
//                 if starting_time + time_limit < ::time::SteadyTime::now() {
//                     panic!("new client can't get bootstrapped in expected duration");
//                 }
//             }
//             Client {
//                 routing: client_routing,
//                 receiver: data_receiver,
//                 name: client_name,
//             }
//         }
//     }

//     struct Environment {
//         vaults_comms: Vec<VaultComms>,
//         client: Client,
//     }

//     impl Environment {
//         fn new() -> Environment {
//             log::init(true);
//             Self::show_warning();

//             remove_files();
//             create_empty_files();

//             let mut vaults_comms = Vec::new();
//             for i in 0..Self::network_size() {
//                 vaults_comms.push(VaultComms::new(i));
//             }

//             Environment {
//                 vaults_comms: vaults_comms,
//                 client: Client::new(),
//             }
//         }

//         #[cfg(windows)]
//         fn show_warning() {
//             println!("\nIf this test hangs, stopping the process with ctrl+C will not suffice.");
//             println!("You should kill the process via the Task Manager, or by running:");
//             println!("  taskkill /f /fi \"imagename eq safe_vault-*\" /im *\n");
//         }

//         #[cfg(not(windows))]
//         fn show_warning() {
//             println!("");
//         }

//         fn network_size() -> usize {
//             GROUP_SIZE as usize
//         }

//         fn consume_vaults_events(&self, time_limit: ::time::Duration) {
//             let starting_time = ::time::SteadyTime::now();
//             loop {
//                 for i in 0..self.vaults_comms.len() {
//                     match self.vaults_comms[i].notifier.try_recv() {
//                         Err(_) => {}
//                         Ok(event) => debug!("vault {} received event {:?}", i, event),
//                     }
//                 }
//                 let duration = ::std::time::Duration::from_millis(1);
//                 ::std::thread::sleep(duration);
//                 if starting_time + time_limit < ::time::SteadyTime::now() {
//                     break;
//                 }
//             }
//         }

//         fn stop_all_vaults(&mut self) {
//             for ref mut vault_comms in &mut self.vaults_comms {
//                 vault_comms.stop();
//             }
//         }
//     }

//     impl Drop for Environment {
//         fn drop(&mut self) {
//             // self.client.routing.stop();
//             self.stop_all_vaults();
//             remove_files();
//         }
//     }

//     // expected_tag: 1 -- Authority::NaeManager
//     //               3 -- Authority::ManagedNode for put request
//     //              10 -- Event::Churn
//     //              20 -- Event::Refresh(type_tag -- 2) for immutable_data test
//     //              21 -- Event::Refresh(type_tag -- 5) for structured_data test
//     //              30 -- Event::Response -- PutResponseError from DM to PM
//     fn wait_for_hits(vaults_comms: &Vec<VaultComms>,
//                      expected_tag: u32,
//                      expected_hits: usize,
//                      time_limit: ::time::Duration)
//                      -> Result<Vec<usize>, String> {
//         let starting_time = ::time::SteadyTime::now();
//         let mut hit_vaults = vec![];
//         while hit_vaults.len() < expected_hits {
//             for i in 0..vaults_comms.len() {
//                 match vaults_comms[i].notifier.try_recv() {
//                     Err(_) => {}
//                     Ok(Event::Request(RequestMessage{ src, dst, content })) => {
//                         debug!("as {:?} received request: {:?} from {:?}",
//                                dst,
//                                content,
//                                src);
//                         match (expected_tag, dst, content) {
//                             (1, Authority::NaeManager(_), _) => hit_vaults.push(i),
//                             (3, Authority::ManagedNode(_), RequestContent::Put(_, _)) => hit_vaults.push(i),
//                             _ => {}
//                         }
//                     }
//                     Ok(Event::Response(ResponseMessage{ src, dst, content })) => {
//                         debug!("as {:?} received response: {:?} from {:?}",
//                                dst,
//                                content,
//                                src);
//                         match (expected_tag, content, dst, src) {
//                             (30,
//                              ResponseContent::PutFailure{ .. },
//                              Authority::NodeManager(_),
//                              Authority::NaeManager(_)) => hit_vaults.push(i),
//                             _ => {}
//                         }
//                     }
//                     Ok(Event::Churn{ .. }) => {
//                         if expected_tag == 10 {
//                             hit_vaults.push(i);
//                         }
//                     }
//                     Ok(_) => {}
//                 }
//             }
//             let duration = ::std::time::Duration::from_millis(1);
//             ::std::thread::sleep(duration);
//             if starting_time + time_limit < ::time::SteadyTime::now() {
//                 // As this function is only to be used in testing code, and a partially
//                 // established environment / testing result having a high chance indicates a failure
//                 // in code.  So here use panic to terminate the testing directly.
//                 return Err(format!("Failed to get {} hits within the expected duration.  Only hit vaults {:?}",
//                                    expected_hits,
//                                    hit_vaults));
//             }
//         }
//         Ok(hit_vaults)
//     }

//     fn wait_for_client_get(client_receiver: &::std::sync::mpsc::Receiver<Data>,
//                            expected_data: Data,
//                            time_limit: ::time::Duration) {
//         let starting_time = ::time::SteadyTime::now();
//         loop {
//             match client_receiver.try_recv() {
//                 Err(_) => {}
//                 Ok(data) => {
//                     assert_eq!(data, expected_data);
//                     break;
//                 }
//             }
//             let duration = ::std::time::Duration::from_millis(1);
//             ::std::thread::sleep(duration);
//             if starting_time + time_limit < ::time::SteadyTime::now() {
//                 panic!("wait_for_client_get can't resolve within the expected duration");
//             }
//         }
//     }

//     fn get_file_name(extension: &'static str) -> ::std::path::PathBuf {
//         let mut name = ::crust::exe_file_stem().unwrap_or(::std::path::Path::new("unknown").to_path_buf());
//         name.set_extension(extension);
//         name
//     }

//     fn remove_file(extension: &'static str) {
//         let _ = ::crust::current_bin_dir().and_then(|mut cur_bin_dir| {
//             cur_bin_dir.push(get_file_name(extension));
//             ::std::fs::remove_file(cur_bin_dir).map_err(|error| ::crust::error::Error::IoError(error))
//         });
//     }

//     fn remove_files() {
//         remove_file("bootstrap.cache");
//         remove_file("crust.config");
//     }

//     fn create_empty_file(extension: &'static str, default_content: &'static str) {
//         let _ = ::crust::current_bin_dir().and_then(|mut cur_bin_dir| {
//             cur_bin_dir.push(get_file_name(extension));
//             let mut file = try!(::std::fs::File::create(cur_bin_dir));
//             let _ = try!(write!(&mut file, "{}", default_content));
//             file.sync_all().map_err(|error| ::crust::error::Error::IoError(error))
//         });
//     }

//     fn create_empty_files() {
//         create_empty_file("bootstrap.cache", "[]");
//         create_empty_file("crust.config",
//                           "{\n\t\"tcp_listening_port\": 5483,\n\t\"utp_listening_port\": \
//                            null,\n\t\"override_default_bootstrap\": false,\n\t\"hard_coded_contacts\": \
//                            [],\n\t\"beacon_port\": 5484\n}\n");
//     }

//     #[test]
//     fn network_test() {
//         let mut env = Environment::new();

//         // ======================= Put/Get test ====================================================
//         println!("\n======================= Put/Get test ====================================================");
//         let value = generate_random_vec_u8(1024);
//         let im_data = ImmutableData::new(ImmutableDataType::Normal, value);
//         println!("Putting data");
//         unwrap_result!(env.client.routing.send_put_request(Authority::ClientManager(env.client.name),
//                                                            Data::ImmutableData(im_data.clone())));
//         let _ = unwrap_result!(wait_for_hits(&env.vaults_comms,
//                                              3,
//                                              immutable_data_manager::REPLICANTS,
//                                              ::time::Duration::minutes(3)));
//         println!("Getting data");
//         unwrap_result!(env.client.routing.send_get_request(Authority::NaeManager(im_data.name()),
//                                                            DataRequest::ImmutableData(im_data.name(),
//                                                                                       ImmutableDataType::Normal)));
//         wait_for_client_get(&env.client.receiver,
//                             Data::ImmutableData(im_data),
//                             Duration::minutes(1));
//         env.consume_vaults_events(Duration::seconds(10));

//         // ======================= Post test =======================================================
//         println!("\n======================= Post test =======================================================");
//         let name = random();
//         let value = generate_random_vec_u8(1024);
//         let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
//         let sd = unwrap_result!(StructuredData::new(0,
//                                                     name,
//                                                     0,
//                                                     value.clone(),
//                                                     vec![sign_keys.0],
//                                                     vec![],
//                                                     Some(&sign_keys.1)));
//         println!("Putting data");
//         unwrap_result!(env.client.routing.send_put_request(Authority::ClientManager(env.client.name),
//                                                            Data::StructuredData(sd.clone())));
//         let _ = unwrap_result!(wait_for_hits(&env.vaults_comms,
//                                              1,
//                                              GROUP_SIZE as usize,
//                                              Duration::minutes(3)));

//         let keys = ::sodiumoxide::crypto::sign::gen_keypair();
//         let sd_new = unwrap_result!(StructuredData::new(0,
//                                                         name,
//                                                         1,
//                                                         value.clone(),
//                                                         vec![keys.0],
//                                                         vec![sign_keys.0],
//                                                         Some(&sign_keys.1)));
//         println!("Posting data");
//         unwrap_result!(env.client.routing.send_post_request(Authority::NaeManager(sd.name()),
//                                                             Data::StructuredData(sd_new.clone())));
//         let _ = unwrap_result!(wait_for_hits(&env.vaults_comms,
//                                              1,
//                                              GROUP_SIZE as usize,
//                                              Duration::minutes(3)));

//         println!("Getting data");
//         unwrap_result!(env.client.routing.send_get_request(Authority::NaeManager(sd.name()),
//                                                            DataRequest::StructuredData(name, 0)));
//         wait_for_client_get(&env.client.receiver,
//                             Data::StructuredData(sd_new),
//                             Duration::minutes(1));

//         // ======================= Churn (node down) ImmutableData test ============================
//         println!("\n======================= Churn (node down) ImmutableData test ============================");
//         let value = generate_random_vec_u8(1024);
//         let im_data = ImmutableData::new(ImmutableDataType::Normal, value);
//         println!("Putting data");
//         unwrap_result!(env.client.routing.send_put_request(Authority::ClientManager(env.client.name),
//                                                            Data::ImmutableData(im_data.clone())));
//         let pmid_nodes = unwrap_result!(wait_for_hits(&env.vaults_comms,
//                                                       3,
//                                                       immutable_data_manager::REPLICANTS,
//                                                       Duration::minutes(3)));

//         println!("Stopping vault {}", pmid_nodes[0]);
//         env.vaults_comms[pmid_nodes[0]].stop();
//         // Waiting for the notifications happen
//         let _ = unwrap_result!(wait_for_hits(&env.vaults_comms,
//                                              30,
//                                              GROUP_SIZE as usize / 2 + 1,
//                                              Duration::minutes(3)));
//         env.consume_vaults_events(::time::Duration::seconds(10));

//         // ======================= Churn (node up) ImmutableData test ==============================
//         println!("\n======================= Churn (node up) ImmutableData test ==============================");
//         let value = generate_random_vec_u8(1024);
//         let im_data = ImmutableData::new(ImmutableDataType::Normal, value);
//         println!("Putting data");
//         unwrap_result!(env.client.routing.send_put_request(Authority::ClientManager(env.client.name),
//                                                            Data::ImmutableData(im_data.clone())));
//         let _ = unwrap_result!(wait_for_hits(&env.vaults_comms,
//                                              3,
//                                              immutable_data_manager::REPLICANTS,
//                                              Duration::minutes(3)));

//         println!("Starting new vault");
//         let mut index = Environment::network_size() - 1;
//         env.vaults_comms.push(VaultComms::new(index));

//         println!("Getting data");
//         unwrap_result!(env.client.routing.send_get_request(Authority::NaeManager(im_data.name()),
//                                                            DataRequest::ImmutableData(im_data.name(),
//                                                                                       ImmutableDataType::Normal)));
//         wait_for_client_get(&env.client.receiver,
//                             Data::ImmutableData(im_data),
//                             Duration::minutes(1));
//         env.consume_vaults_events(Duration::seconds(10));

//         // ======================= Churn (two nodes down) ImmutableData test =======================
//         println!("\n======================= Churn (two nodes down) ImmutableData test =======================");
//         let value = generate_random_vec_u8(1024);
//         let im_data = ImmutableData::new(ImmutableDataType::Normal, value);
//         println!("Putting data");
//         unwrap_result!(env.client.routing.send_put_request(Authority::ClientManager(env.client.name),
//                                                            Data::ImmutableData(im_data.clone())));
//         let pmid_nodes = unwrap_result!(wait_for_hits(&env.vaults_comms,
//                                                       3,
//                                                       immutable_data_manager::REPLICANTS,
//                                                       Duration::minutes(3)));

//         println!("Stopping vault {}", pmid_nodes[0]);
//         env.vaults_comms[pmid_nodes[0]].stop();
//         println!("Stopping vault {}", pmid_nodes[1]);
//         env.vaults_comms[pmid_nodes[1]].stop();
//         // Waiting for the replications happen
//         let _ = unwrap_result!(wait_for_hits(&env.vaults_comms, 3, 1, ::time::Duration::minutes(3)));

//         // ======================= Churn (node up) StructuredData test =============================
//         println!("\n======================= Churn (node up) StructuredData test =============================");
//         let name = random();
//         let value = generate_random_vec_u8(1024);
//         let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
//         let sd = unwrap_result!(StructuredData::new(0,
//                                                     name,
//                                                     0,
//                                                     value.clone(),
//                                                     vec![sign_keys.0],
//                                                     vec![],
//                                                     Some(&sign_keys.1)));
//         println!("Putting data");
//         unwrap_result!(env.client.routing.send_put_request(Authority::ClientManager(env.client.name),
//                                                            Data::StructuredData(sd.clone())));
//         let _ = unwrap_result!(wait_for_hits(&env.vaults_comms,
//                                              1,
//                                              GROUP_SIZE as usize - 2,
//                                              Duration::minutes(3)));

//         println!("Starting new vault");
//         index = Environment::network_size() - 2;
//         env.vaults_comms.push(VaultComms::new(index));

//         println!("Getting data");
//         unwrap_result!(env.client.routing.send_get_request(Authority::NaeManager(sd.name()),
//                                                            DataRequest::StructuredData(name, 0)));
//         wait_for_client_get(&env.client.receiver,
//                             Data::StructuredData(sd),
//                             Duration::minutes(1));
//     }
// }

// #[cfg(all(test, feature = "use-mock-routing"))]
// mod mock_routing_test {
//     use super::*;

//     struct VaultComms {
//         receiver: ::std::sync::mpsc::Receiver<(::routing::data::Data)>,
//         killer: ::std::sync::Arc<::std::sync::atomic::AtomicBool>,
//         join_handle: Option<::std::thread::JoinHandle<()>>,
//     }

//     impl Drop for VaultComms {
//         fn drop(&mut self) {
//             self.killer.store(true, ::std::sync::atomic::Ordering::Relaxed);
//             if let Some(join_handle) = self.join_handle.take() {
//                 unwrap_result!(join_handle.join());
//             }
//         }
//     }


//     fn mock_env_setup() -> (Routing, VaultComms) {
//         ::utils::initialise_logger();
//         let killer = ::std::sync::Arc::new(::std::sync::atomic::AtomicBool::new(false));
//         let mut vault = Vault::new(None, Some(killer.clone()));
//         let mut routing = vault.pmid_node.routing();
//         let receiver = routing.get_client_receiver();
//         let join_handle = Some(unwrap_result!(::std::thread::Builder::new().spawn(move || vault.do_run())));

//         let mut available_nodes = Vec::with_capacity(30);
//         for _ in 0..30 {
//             available_nodes.push(random());
//         }
//         routing.churn_event(available_nodes, random());
//         (routing,
//          VaultComms {
//             receiver: receiver,
//             killer: killer,
//             join_handle: join_handle,
//         })
//     }

//     #[test]
//     fn put_get_flow() {
//         let (mut routing, vault_comms) = mock_env_setup();

//         let client_name = random();
//         let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
//         let value = generate_random_vec_u8(1024);
//         let im_data = ImmutableData::new(ImmutableDataType::Normal, value);
//         routing.client_put(client_name,
//                            sign_keys.0,
//                            ::routing::data::Data::ImmutableData(im_data.clone()));
//         let duration = ::std::time::Duration::from_millis(2000);
//         ::std::thread::sleep(duration);

//         let data_request = ::routing::data::DataRequest::ImmutableData(im_data.name(), ImmutableDataType::Normal);
//         routing.client_get(client_name, sign_keys.0, data_request);
//         for it in vault_comms.receiver.iter() {
//             assert_eq!(it, ::routing::data::Data::ImmutableData(im_data));
//             break;
//         }
//     }

//     #[test]
//     fn post_flow() {
//         let (mut routing, vault_comms) = mock_env_setup();

//         let name = random();
//         let value = generate_random_vec_u8(1024);
//         let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
//         let sd = unwrap_result!(::routing::structured_data::StructuredData::new(0,
//                                                                                 name,
//                                                                                 0,
//                                                                                 value.clone(),
//                                                                                 vec![sign_keys.0],
//                                                                                 vec![],
//                                                                                 Some(&sign_keys.1)));

//         let client_name = random();
//         routing.client_put(client_name,
//                            sign_keys.0,
//                            ::routing::data::Data::StructuredData(sd.clone()));
//         let duration = ::std::time::Duration::from_millis(2000);
//         ::std::thread::sleep(duration);

//         let keys = ::sodiumoxide::crypto::sign::gen_keypair();
//         let sd_new = unwrap_result!(::routing::structured_data::StructuredData::new(0,
//                                                                                     name,
//                                                                                     1,
//                                                                                     value.clone(),
//                                                                                     vec![keys.0],
//                                                                                     vec![sign_keys.0],
//                                                                                     Some(&sign_keys.1)));
//         routing.client_post(client_name,
//                             sign_keys.0,
//                             ::routing::data::Data::StructuredData(sd_new.clone()));
//         let duration = ::std::time::Duration::from_millis(2000);
//         ::std::thread::sleep(duration);

//         let data_request = ::routing::data::DataRequest::StructuredData(name, 0);
//         routing.client_get(client_name, sign_keys.0, data_request);
//         for it in vault_comms.receiver.iter() {
//             assert_eq!(it, ::routing::data::Data::StructuredData(sd_new));
//             break;
//         }
//     }
// }

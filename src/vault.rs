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

#[cfg(not(all(test, feature = "use-mock-routing")))]
pub type Routing = ::routing::routing::Routing;

#[cfg(all(test, feature = "use-mock-routing"))]
pub type Routing = ::mock_routing::MockRouting;

/// Main struct to hold all personas and Routing instance
pub struct Vault {
    data_manager: ::data_manager::DataManager,
    maid_manager: ::maid_manager::MaidManager,
    pmid_manager: ::pmid_manager::PmidManager,
    pmid_node: ::pmid_node::PmidNode,
    sd_manager: ::sd_manager::StructuredDataManager,
    receiver: ::std::sync::mpsc::Receiver<::routing::event::Event>,
    churn_timestamp: ::time::SteadyTime,
    id: ::routing::NameType,
    app_event_sender: Option<::std::sync::mpsc::Sender<(::routing::event::Event)>>,
    should_stop: Option<::std::sync::Arc<::std::sync::atomic::AtomicBool>>,
}

impl Vault {
    pub fn run() {
        Vault::new(None, None).do_run();
    }

    fn new(app_event_sender: Option<::std::sync::mpsc::Sender<(::routing::event::Event)>>,
           should_stop: Option<::std::sync::Arc<::std::sync::atomic::AtomicBool>>) -> Vault {
        ::sodiumoxide::init();
        let (sender, receiver) = ::std::sync::mpsc::channel();
        let routing = Routing::new(sender);
        Vault {
            data_manager: ::data_manager::DataManager::new(routing.clone()),
            maid_manager: ::maid_manager::MaidManager::new(routing.clone()),
            pmid_manager: ::pmid_manager::PmidManager::new(routing.clone()),
            pmid_node: ::pmid_node::PmidNode::new(routing.clone()),
            sd_manager: ::sd_manager::StructuredDataManager::new(routing.clone()),
            churn_timestamp: ::time::SteadyTime::now(),
            receiver: receiver,
            id: ::routing::NameType::new([0u8; 64]),
            app_event_sender: app_event_sender,
            should_stop: should_stop,
        }
    }

    fn do_run(&mut self) {
        use routing::event::Event;
        loop {
            match self.receiver.try_recv() {
                Err(_) => {}
                Ok(event) => {
                    let _ = self.app_event_sender.clone().and_then(|sender| Some(sender.send(event.clone())));
                    info!("Vault {} received an event from routing : {:?}", self.id, event);
                    match event {
                        Event::Request{ request, our_authority, from_authority, response_token } =>
                            self.on_request(request, our_authority, from_authority, response_token),
                        Event::Response{ response, our_authority, from_authority } =>
                            self.on_response(response, our_authority, from_authority),
                        Event::Refresh(type_tag, our_authority, accounts) => self.on_refresh(type_tag,
                                                                                             our_authority,
                                                                                             accounts),
                        Event::Churn(close_group, churn_node) => self.on_churn(close_group, churn_node),
                        Event::DoRefresh(type_tag, our_authority, churn_node) =>
                            self.on_do_refresh(type_tag, our_authority, churn_node),
                        Event::Bootstrapped => self.on_bootstrapped(),
                        Event::Connected => self.on_connected(),
                        Event::Disconnected => self.on_disconnected(),
                        Event::FailedRequest{ request, our_authority, location, interface_error } =>
                            self.on_failed_request(request, our_authority, location, interface_error),
                        Event::FailedResponse{ response, our_authority, location, interface_error } =>
                            self.on_failed_response(response, our_authority, location, interface_error),
                        Event::Terminated => break,
                    };
                }
            }

            if let &Some(ref arc) = &self.should_stop {
                let ref should_stop = &*arc;
                if should_stop.load(::std::sync::atomic::Ordering::Relaxed) {
                    // Just stop Routing and wait for the `Event::Terminated` message to break out
                    // of this event loop.
                    self.pmid_node.routing().stop();
                }
            }
            ::std::thread::yield_now();
        }
    }

    fn on_request(&mut self,
                  request: ::routing::ExternalRequest,
                  our_authority: ::routing::Authority,
                  from_authority: ::routing::Authority,
                  response_token: Option<::routing::SignedToken>) {
        match request {
            ::routing::ExternalRequest::Get(data_request, _) => {
                self.handle_get(our_authority, from_authority, data_request, response_token);
            }
            ::routing::ExternalRequest::Put(data) => {
                self.handle_put(our_authority, from_authority, data, response_token);
            }
            ::routing::ExternalRequest::Post(data) => {
                self.handle_post(our_authority, from_authority, data, response_token);
            }
            ::routing::ExternalRequest::Delete(/*data*/_) => {
                unimplemented!();
            }
        }
    }

    fn on_response(&mut self,
                   response: ::routing::ExternalResponse,
                   our_authority: ::routing::Authority,
                   from_authority: ::routing::Authority) {
        match response {
            ::routing::ExternalResponse::Get(data, _, response_token) => {
                self.handle_get_response(our_authority, from_authority, data, response_token);
            }
            ::routing::ExternalResponse::Put(response_error, response_token) => {
                self.handle_put_response(our_authority,
                                         from_authority,
                                         response_error,
                                         response_token);
            }
            ::routing::ExternalResponse::Post(/*response_error*/_, /*response_token*/_) => {
                unimplemented!();
            }
            ::routing::ExternalResponse::Delete(/*response_error*/_, /*response_token*/_) => {
                unimplemented!();
            }
        }
    }

    fn on_refresh(&mut self,
                  type_tag: u64,
                  our_authority: ::routing::Authority,
                  accounts: Vec<Vec<u8>>) {
        self.handle_refresh(type_tag, our_authority, accounts);
    }

    fn on_churn(&mut self, close_group: Vec<::routing::NameType>,
                churn_node: ::routing::NameType) {
        self.id = close_group[0].clone();
        let churn_up = close_group.len() > self.data_manager.nodes_in_table_len();
        let time_now = ::time::SteadyTime::now();
        // During the process of joining network, the vault shall not refresh its just received info
        if !(churn_up && (self.churn_timestamp + ::time::Duration::seconds(5) > time_now)) {
            self.handle_churn(close_group, churn_node);
        } else {
            self.data_manager.set_node_table(close_group);
        }
        if churn_up {
            info!("Vault added connected node");
            self.churn_timestamp = time_now;
        }
    }

    fn on_do_refresh(&mut self, type_tag: u64, our_authority: ::routing::Authority,
                     churn_node: ::routing::NameType) {
        let _ = self.maid_manager.do_refresh(&type_tag, &our_authority, &churn_node)
                .or_else(|| self.data_manager.do_refresh(&type_tag, &our_authority, &churn_node))
                .or_else(|| self.sd_manager.do_refresh(&type_tag, &our_authority, &churn_node))
                .or_else(|| self.pmid_manager.do_refresh(&type_tag, &our_authority, &churn_node));
    }

    fn on_bootstrapped(&self) {
        debug!("vault bootstrapped having {:?} connections",
               self.data_manager.nodes_in_table_len());
        // assert_eq!(0, self.data_manager.nodes_in_table_len());
    }

    fn on_connected(&self) {
        // TODO: what is expected to be done here?
        debug!("vault connected having {:?} connections",
               self.data_manager.nodes_in_table_len());
        // assert_eq!(::routing::types::GROUP_SIZE, self.data_manager.nodes_in_table_len());
    }

    fn on_disconnected(&mut self) {
        self.pmid_node.routing().stop();
        if let &Some(ref arc) = &self.should_stop {
            let ref should_stop = &*arc;
            if should_stop.load(::std::sync::atomic::Ordering::Relaxed) {
                return;
            }
        }
        self.churn_timestamp = ::time::SteadyTime::now();
        let (sender, receiver) = ::std::sync::mpsc::channel();
        let routing = Routing::new(sender);
        self.receiver = receiver;

        self.maid_manager.reset(routing.clone());
        self.data_manager.reset(routing.clone());
        self.pmid_manager.reset(routing.clone());
        // TODO: https://github.com/maidsafe/safe_vault/issues/269
        //   pmid_node and sd_manager shall discard the data when routing address changed
        self.pmid_node.reset(routing.clone());
        self.sd_manager.reset(routing.clone());
    }

    fn on_failed_request(&mut self,
                         _request: ::routing::ExternalRequest,
                         _our_authority: Option<::routing::Authority>,
                         _location: ::routing::Authority,
                         _error: ::routing::error::InterfaceError) {
        unimplemented!();
    }

    fn on_failed_response(&mut self,
                          _response: ::routing::ExternalResponse,
                          _our_authority: Option<::routing::Authority>,
                          _location: ::routing::Authority,
                          _error: ::routing::error::InterfaceError) {
        unimplemented!();
    }

    fn handle_get(&mut self,
                  our_authority: ::routing::Authority,
                  from_authority: ::routing::Authority,
                  data_request: ::routing::data::DataRequest,
                  response_token: Option<::routing::SignedToken>) {
        let _ = self.data_manager
                    .handle_get(&our_authority, &from_authority, &data_request, &response_token)
                    .or_else(|| {
                        self.sd_manager.handle_get(&our_authority,
                                                   &from_authority,
                                                   &data_request,
                                                   &response_token)
                    })
                    .or_else(|| {
                        self.pmid_node.handle_get(&our_authority,
                                                  &from_authority,
                                                  &data_request,
                                                  &response_token)
                    });
    }

    fn handle_put(&mut self,
                  our_authority: ::routing::Authority,
                  from_authority: ::routing::Authority,
                  data: ::routing::data::Data,
                  response_token: Option<::routing::SignedToken>) {
        let _ = self.maid_manager
                    .handle_put(&our_authority, &from_authority, &data, &response_token)
                    .or_else(|| {
                        self.data_manager.handle_put(&our_authority, &from_authority, &data)
                    })
                    .or_else(|| self.sd_manager.handle_put(&our_authority, &from_authority, &data))
                    .or_else(|| {
                        self.pmid_manager.handle_put(&our_authority, &from_authority, &data)
                    })
                    .or_else(|| {
                        self.pmid_node
                            .handle_put(&our_authority, &from_authority, &data, &response_token)
                    });
    }

    // Post is only used to update the content or owners of a StructuredData
    fn handle_post(&mut self,
                   our_authority: ::routing::Authority,
                   from_authority: ::routing::Authority,
                   data: ::routing::data::Data,
                   _response_token: Option<::routing::SignedToken>) {
        let _ = self.sd_manager.handle_post(&our_authority, &from_authority, &data);
    }

    fn handle_get_response(&mut self,
                           our_authority: ::routing::Authority,
                           from_authority: ::routing::Authority,
                           response: ::routing::data::Data,
                           response_token: Option<::routing::SignedToken>) {
        let _ = self.data_manager.handle_get_response(&our_authority,
                                                      &from_authority,
                                                      &response,
                                                      &response_token);
    }

    // DataManager doesn't need to carry out replication in case of sacrificial copy
    #[allow(dead_code)]
    fn handle_put_response(&mut self,
                           our_authority: ::routing::Authority,
                           from_authority: ::routing::Authority,
                           response: ::routing::error::ResponseError,
                           response_token: Option<::routing::SignedToken>) {
        let _ = self.data_manager
                    .handle_put_response(&our_authority, &from_authority, &response)
                    .or_else(|| {
                        self.pmid_manager.handle_put_response(&our_authority,
                                                              &from_authority,
                                                              &response,
                                                              &response_token)
                    });
    }

    // https://maidsafe.atlassian.net/browse/MAID-1111 post_response is not required on vault
    #[allow(dead_code)]
    fn handle_post_response(&mut self,
                            _: ::routing::Authority, // from_authority
                            _: ::routing::error::ResponseError,
                            _: Option<::routing::SignedToken>) {
    }

    fn handle_churn(&mut self, close_group: Vec<::routing::NameType>,
                    churn_node: ::routing::NameType) {
        self.maid_manager.handle_churn(&churn_node);
        self.sd_manager.handle_churn(&churn_node);
        self.pmid_manager.handle_churn(&close_group, &churn_node);
        self.data_manager.handle_churn(close_group, &churn_node);
    }

    fn handle_refresh(&mut self,
                      type_tag: u64,
                      our_authority: ::routing::Authority,
                      payloads: Vec<Vec<u8>>) {
        // The incoming payloads is a vector of serialised account entries,
        // collected from the close group nodes regarding `from_group`
        debug!("refresh tag {:?} & authority {:?}", type_tag, our_authority);
        let _ = self.maid_manager
                    .handle_refresh(&type_tag, &our_authority, &payloads)
                    .or_else(|| {
                        self.data_manager.handle_refresh(&type_tag, &our_authority, &payloads)
                    })
                    .or_else(|| {
                        self.pmid_manager.handle_refresh(&type_tag, &our_authority, &payloads)
                    })
                    .or_else(|| {
                        self.sd_manager.handle_refresh(&type_tag, &our_authority, &payloads)
                    });
    }
}



#[cfg(all(test, not(feature = "use-mock-routing")))]
mod test {
    use super::*;

    struct VaultComms {
        notifier: ::std::sync::mpsc::Receiver<(::routing::event::Event)>,
        killer: ::std::sync::Arc<::std::sync::atomic::AtomicBool>,
        join_handle: Option<::std::thread::JoinHandle<()>>,
    }

    impl VaultComms {
        fn new(index: usize) -> VaultComms {
            println!("Starting vault {}", index);
            let (sender, receiver) = ::std::sync::mpsc::channel();
            let killer = ::std::sync::Arc::new(::std::sync::atomic::AtomicBool::new(false));
            let mut vault = Vault::new(Some(sender), Some(killer.clone()));
            let join_handle =
                Some(evaluate_result!(::std::thread::Builder::new()
                                          .name(format!("Vault {} worker", index))
                                          .spawn(move || vault.do_run())));
            let vault_comms =
                VaultComms{ notifier: receiver, killer: killer, join_handle: join_handle, };
            let mut temp_comms = vec![vault_comms];
            let _ = evaluate_result!(wait_for_hits(&temp_comms, 10, index,
                        ::time::Duration::seconds(10 * (index + 1) as i64)));
            temp_comms.remove(0)
        }

        fn stop(&mut self) {
            self.killer.store(true, ::std::sync::atomic::Ordering::Relaxed);
            if let Some(join_handle) = self.join_handle.take() {
                evaluate_result!(join_handle.join());
            }
        }
    }

    struct Client {
        routing: ::routing::routing_client::RoutingClient,
        receiver: ::std::sync::mpsc::Receiver<(::routing::data::Data)>,
        name: ::routing::NameType,
    }

    impl Client {
        fn new() -> Client {
            use routing::event::Event;
            let (sender, receiver) = ::std::sync::mpsc::channel();
            let (client_sender, client_receiver) = ::std::sync::mpsc::channel();
            let client_receiving =
                |receiver: ::std::sync::mpsc::Receiver<(Event)>,
                 client_sender: ::std::sync::mpsc::Sender<(::routing::data::Data)>| {
                    let _ = ::std::thread::spawn(move || {
                    while let Ok(event) = receiver.recv() {
                        match event {
                            Event::Request{ request, our_authority, from_authority, response_token } =>
                                info!("as {:?} received request: {:?} from {:?} having token {:?}",
                                      our_authority, request, from_authority, response_token == None),
                            Event::Response{ response, our_authority, from_authority } => {
                                info!("as {:?} received response: {:?} from {:?}",
                                      our_authority, response, from_authority);
                                match response {
                                    ::routing::ExternalResponse::Get(data, _, _) => {
                                        let _ = client_sender.clone().send(data);
                                    },
                                    _ => panic!("not expected!")
                                }
                            },
                            Event::Refresh(_type_tag, _group_name, _accounts) =>
                                info!("client received a refresh"),
                            Event::Churn(_close_group, _churn_node) => info!("client received a churn"),
                            Event::DoRefresh(_type_tag, _our_authority, _churn_node) =>
                                info!("client received a do-refresh"),
                            Event::Connected => info!("client connected"),
                            Event::Disconnected => info!("client disconnected"),
                            Event::FailedRequest{ request, our_authority, location, interface_error } =>
                                info!("as {:?} received request: {:?} targeting {:?} having error {:?}",
                                      our_authority, request, location, interface_error),
                            Event::FailedResponse{ response, our_authority, location,
                                                   interface_error } =>
                                info!("as {:?} received response: {:?} targeting {:?} having error \
                                      {:?}", our_authority, response, location, interface_error),
                            Event::Bootstrapped => {
                                // Send an empty data to indicate bootstrapped
                                let _ = client_sender.clone().send(::routing::data::Data::PlainData(
                                    ::routing::plain_data::PlainData::new(
                                        ::routing::NameType::new([0u8; 64]), vec![])));
                                info!("client routing Bootstrapped");
                            }
                            Event::Terminated => {
                                info!("client routing listening terminated");
                                break;
                            },
                        };
                    }
                });
            };
            let _ = client_receiving(receiver, client_sender);
            let id = ::routing::id::Id::new();
            let client_name = id.name();
            let client_routing = ::routing::routing_client::RoutingClient::new(sender, Some(id));
            let starting_time = ::time::SteadyTime::now();
            let time_limit = ::time::Duration::minutes(1);
            loop {
                match client_receiver.try_recv() {
                    Err(_) => {}
                    Ok(_) => break,
                }
                ::std::thread::yield_now();
                if starting_time + time_limit < ::time::SteadyTime::now() {
                    panic!("new client can't get bootstrapped in expected duration");
                }
            }
            Client{ routing: client_routing, receiver: client_receiver, name: client_name, }
        }
    }

    struct Environment {
        vaults_comms: Vec<VaultComms>,
        client: Client,
    }

    impl Environment {
        fn new() -> Environment {
            ::utils::initialise_logger();
            println!("");

            remove_bootstrap_file();
            create_empty_bootstrap_file();

            let mut vaults_comms = Vec::new();
            for i in 0..Self::network_size() {
                vaults_comms.push(VaultComms::new(i));
            }

            Environment{ vaults_comms: vaults_comms, client: Client::new(), }
        }

        fn network_size() -> usize {
            ::routing::types::GROUP_SIZE
        }

        fn consume_vaults_events(&self, time_limit: ::time::Duration) {
            let starting_time = ::time::SteadyTime::now();
            loop {
                for i in 0..self.vaults_comms.len() {
                    match self.vaults_comms[i].notifier.try_recv() {
                        Err(_) => {}
                        Ok(event) => debug!("vault {} received event {:?}", i, event),
                    }
                }
                ::std::thread::yield_now();
                if starting_time + time_limit < ::time::SteadyTime::now() {
                    break;
                }
            }
        }

        fn stop_all_vaults(&mut self) {
            for ref mut vault_comms in &mut self.vaults_comms {
                vault_comms.stop();
            }
        }
    }

    impl Drop for Environment {
        fn drop(&mut self) {
            self.client.routing.stop();
            self.stop_all_vaults();
            remove_bootstrap_file();
        }
    }

    // expected_tag: 1 -- Authority::NaeManager
    //               3 -- Authority::ManagedNode for put request
    //              10 -- Event::Churn
    //              20 -- Event::Refresh(type_tag -- 2) for immutable_data test
    //              21 -- Event::Refresh(type_tag -- 5) for structured_data test
    //              30 -- Event::Response -- PutResponseError from DM to PM
    fn wait_for_hits(vaults_comms: &Vec<VaultComms>,
                     expected_tag: u32,
                     expected_hits: usize,
                     time_limit: ::time::Duration) -> Result<Vec<usize>, String> {
        let starting_time = ::time::SteadyTime::now();
        let mut hit_vaults = vec![];
        while hit_vaults.len() < expected_hits {
            for i in 0..vaults_comms.len() {
                match vaults_comms[i].notifier.try_recv() {
                    Err(_) => {}
                    Ok(::routing::event::Event::Request{ request, our_authority,
                                                         from_authority, response_token }) => {
                        debug!("as {:?} received request: {:?} from {:?} having token {:?}",
                               our_authority, request, from_authority, response_token == None);
                        match (expected_tag, our_authority, request) {
                            (1, ::routing::Authority::NaeManager(_), _) => hit_vaults.push(i),
                            (3, ::routing::Authority::ManagedNode(_),
                                ::routing::ExternalRequest::Put(_)) => hit_vaults.push(i),
                            _ => {}
                        }
                    }
                    Ok(::routing::event::Event::Churn(_, _)) => {
                        if expected_tag == 10 {
                            hit_vaults.push(i);
                        }
                    }
                    Ok(::routing::event::Event::Refresh(type_tag, _, _)) => {
                        match (expected_tag, type_tag) {
                            (20, 2) => hit_vaults.push(i),
                            (21, 5) => hit_vaults.push(i),
                            _ => {}
                        }
                    }
                    Ok(::routing::event::Event::Response{ response, our_authority,
                                                          from_authority }) => {
                        debug!("as {:?} received response: {:?} from {:?}",
                               our_authority, response, from_authority);
                        match (expected_tag, response, our_authority, from_authority) {
                            (30, ::routing::ExternalResponse::Put(_, _),
                             ::routing::Authority::NodeManager(_),
                             ::routing::Authority::NaeManager(_)) => hit_vaults.push(i),
                            _ => {}
                        }
                    }
                    Ok(_) => {}
                }
            }
            ::std::thread::yield_now();
            if starting_time + time_limit < ::time::SteadyTime::now() {
                // As this function is only to be used in testing code, and a partially
                // established environment / testing result having a high chance indicates a failure
                // in code.  So here use panic to terminate the testing directly.
                return Err(format!(
                    "Failed to get {} hits within the expected duration.  Only hit vaults {:?}",
                    expected_hits, hit_vaults));
            }
        }
        Ok(hit_vaults)
    }

    fn wait_for_client_get(client_receiver: &::std::sync::mpsc::Receiver<(::routing::data::Data)>,
                           expected_data: ::routing::data::Data, time_limit: ::time::Duration) {
        let starting_time = ::time::SteadyTime::now();
        loop {
            match client_receiver.try_recv() {
                Err(_) => {}
                Ok(data) => {
                    assert_eq!(data, expected_data);
                    break
                }
            }
            ::std::thread::yield_now();
            if starting_time + time_limit < ::time::SteadyTime::now() {
                panic!("wait_for_client_get can't resolve within the expected duration");
            }
        }
    }

    fn get_file_name() -> ::std::path::PathBuf {
        let mut name =
            ::crust::exe_file_stem().unwrap_or(::std::path::Path::new("unknown").to_path_buf());
        name.set_extension("bootstrap.cache");
        name
    }

    fn remove_bootstrap_file() {
        let _ = ::crust::current_bin_dir().and_then(|mut cur_bin_dir| {
            cur_bin_dir.push(get_file_name());
            ::std::fs::remove_file(cur_bin_dir).map_err(
                |error| ::crust::error::Error::IoError(error))
        });
    }

    fn create_empty_bootstrap_file() {
        use std::io::Write;
        let _ = ::crust::current_bin_dir().and_then(|mut cur_bin_dir| {
            cur_bin_dir.push(get_file_name());
            let mut file = try!(::std::fs::File::create(cur_bin_dir));
            let _ = try!(write!(&mut file, "[]"));
            file.sync_all().map_err(|error| ::crust::error::Error::IoError(error))
        });
    }

    #[test]
    fn network_test() {
        let mut env = Environment::new();

        // ======================= Put/Get test ====================================================
        println!("\n======================= Put/Get test \
                 ====================================================");
        let value = ::routing::types::generate_random_vec_u8(1024);
        let im_data = ::routing::immutable_data::ImmutableData::new(
                          ::routing::immutable_data::ImmutableDataType::Normal, value);
        println!("Putting data");
        env.client.routing.put_request(::maid_manager::Authority(env.client.name),
                                       ::routing::data::Data::ImmutableData(im_data.clone()));
        let _ = evaluate_result!(wait_for_hits(&env.vaults_comms,
                                               3,
                                               ::data_manager::REPLICANTS,
                                               ::time::Duration::minutes(3)));
        println!("Getting data");
        env.client.routing.get_request(::data_manager::Authority(im_data.name()),
            ::routing::data::DataRequest::ImmutableData(im_data.name(),
                ::routing::immutable_data::ImmutableDataType::Normal));
        wait_for_client_get(&env.client.receiver,
                            ::routing::data::Data::ImmutableData(im_data),
                            ::time::Duration::minutes(1));
        env.consume_vaults_events(::time::Duration::seconds(10));

        // ======================= Post test =======================================================
        println!("\n======================= Post test \
                 =======================================================");
        let name = ::utils::random_name();
        let value = ::routing::types::generate_random_vec_u8(1024);
        let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let sd = evaluate_result!(
            ::routing::structured_data::StructuredData::new(0,
                                                            name,
                                                            0,
                                                            value.clone(),
                                                            vec![sign_keys.0],
                                                            vec![],
                                                            Some(&sign_keys.1)));
        println!("Putting data");
        env.client.routing.put_request(::maid_manager::Authority(env.client.name),
                                   ::routing::data::Data::StructuredData(sd.clone()));
        let _ = evaluate_result!(wait_for_hits(&env.vaults_comms,
                                               1,
                                               ::routing::types::GROUP_SIZE,
                                               ::time::Duration::minutes(3)));

        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let sd_new = evaluate_result!(
            ::routing::structured_data::StructuredData::new(0,
                                                            name,
                                                            1,
                                                            value.clone(),
                                                            vec![keys.0],
                                                            vec![sign_keys.0],
                                                            Some(&sign_keys.1)));
        println!("Posting data");
        env.client.routing.post_request(::sd_manager::Authority(sd.name()),
                                    ::routing::data::Data::StructuredData(sd_new.clone()));
        let _ = evaluate_result!(wait_for_hits(&env.vaults_comms,
                                               1,
                                               ::routing::types::GROUP_SIZE,
                                               ::time::Duration::minutes(3)));

        println!("Getting data");
        env.client.routing.get_request(::sd_manager::Authority(sd.name()),
                                   ::routing::data::DataRequest::StructuredData(name, 0));
        wait_for_client_get(&env.client.receiver,
                            ::routing::data::Data::StructuredData(sd_new),
                            ::time::Duration::minutes(1));

        // ======================= Churn (node down) ImmutableData test ============================
        println!("\n======================= Churn (node down) ImmutableData test \
                 ============================");
        let value = ::routing::types::generate_random_vec_u8(1024);
        let im_data = ::routing::immutable_data::ImmutableData::new(
                          ::routing::immutable_data::ImmutableDataType::Normal, value);
        println!("Putting data");
        env.client.routing.put_request(::maid_manager::Authority(env.client.name),
                                       ::routing::data::Data::ImmutableData(im_data.clone()));
        let pmid_nodes = evaluate_result!(wait_for_hits(&env.vaults_comms,
                                                        3,
                                                        ::data_manager::REPLICANTS,
                                                        ::time::Duration::minutes(3)));

        println!("Stopping vault {}", pmid_nodes[0]);
        env.vaults_comms[pmid_nodes[0]].stop();
        // Waiting for the notifications happen
        let _ = evaluate_result!(wait_for_hits(&env.vaults_comms,
                                               30,
                                               ::routing::types::GROUP_SIZE / 2 + 1,
                                               ::time::Duration::minutes(3)));
        env.consume_vaults_events(::time::Duration::seconds(10));

        // ======================= Churn (node up) ImmutableData test ==============================
        println!("\n======================= Churn (node up) ImmutableData test \
                 ==============================");
        let value = ::routing::types::generate_random_vec_u8(1024);
        let im_data = ::routing::immutable_data::ImmutableData::new(
                          ::routing::immutable_data::ImmutableDataType::Normal, value);
        println!("Putting data");
        env.client.routing.put_request(::maid_manager::Authority(env.client.name),
                                       ::routing::data::Data::ImmutableData(im_data.clone()));
        let _ = evaluate_result!(wait_for_hits(&env.vaults_comms,
                                               3,
                                               ::data_manager::REPLICANTS,
                                               ::time::Duration::minutes(3)));

        println!("Starting new vault");
        let mut index = Environment::network_size() - 1;
        env.vaults_comms.push(VaultComms::new(index));

        println!("Getting data");
        env.client.routing.get_request(::data_manager::Authority(im_data.name()),
                                       ::routing::data::DataRequest::ImmutableData(im_data.name(),
                ::routing::immutable_data::ImmutableDataType::Normal));
        wait_for_client_get(&env.client.receiver,
                            ::routing::data::Data::ImmutableData(im_data),
                            ::time::Duration::minutes(1));
        env.consume_vaults_events(::time::Duration::seconds(10));

        // ======================= Churn (two nodes down) ImmutableData test =======================
        println!("\n======================= Churn (two nodes down) ImmutableData test \
                 =======================");
        let value = ::routing::types::generate_random_vec_u8(1024);
        let im_data = ::routing::immutable_data::ImmutableData::new(
                          ::routing::immutable_data::ImmutableDataType::Normal, value);
        println!("Putting data");
        env.client.routing.put_request(::maid_manager::Authority(env.client.name),
                                       ::routing::data::Data::ImmutableData(im_data.clone()));
        let pmid_nodes = evaluate_result!(wait_for_hits(&env.vaults_comms,
                                                        3,
                                                        ::data_manager::REPLICANTS,
                                                        ::time::Duration::minutes(3)));

        println!("Stopping vault {}", pmid_nodes[0]);
        env.vaults_comms[pmid_nodes[0]].stop();
        println!("Stopping vault {}", pmid_nodes[1]);
        env.vaults_comms[pmid_nodes[1]].stop();
        // Waiting for the replications happen
        let _ = evaluate_result!(wait_for_hits(&env.vaults_comms,
                                               3,
                                               1,
                                               ::time::Duration::minutes(3)));

        // ======================= Churn (node up) StructuredData test =============================
        println!("\n======================= Churn (node up) StructuredData test \
                 =============================");
        let name = ::utils::random_name();
        let value = ::routing::types::generate_random_vec_u8(1024);
        let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let sd = evaluate_result!(
            ::routing::structured_data::StructuredData::new(0,
                                                            name,
                                                            0,
                                                            value.clone(),
                                                            vec![sign_keys.0],
                                                            vec![],
                                                            Some(&sign_keys.1)));
        println!("Putting data");
        env.client.routing.put_request(::maid_manager::Authority(env.client.name),
                                       ::routing::data::Data::StructuredData(sd.clone()));
        let _ = evaluate_result!(wait_for_hits(&env.vaults_comms,
                                               1,
                                               ::routing::types::GROUP_SIZE - 2,
                                               ::time::Duration::minutes(3)));

        println!("Starting new vault");
        index = Environment::network_size() - 2;
        env.vaults_comms.push(VaultComms::new(index));

        println!("Getting data");
        env.client.routing.get_request(::sd_manager::Authority(sd.name()),
                                       ::routing::data::DataRequest::StructuredData(name, 0));
        wait_for_client_get(&env.client.receiver,
                            ::routing::data::Data::StructuredData(sd),
                            ::time::Duration::minutes(1));
    }
}



#[cfg(all(test, feature = "use-mock-routing"))]
mod mock_routing_test {
    use super::*;

    struct VaultComms {
        receiver: ::std::sync::mpsc::Receiver<(::routing::data::Data)>,
        killer: ::std::sync::Arc<::std::sync::atomic::AtomicBool>,
        join_handle: Option<::std::thread::JoinHandle<()>>,
    }

    impl Drop for VaultComms {
        fn drop(&mut self) {
            self.killer.store(true, ::std::sync::atomic::Ordering::Relaxed);
            if let Some(join_handle) = self.join_handle.take() {
                evaluate_result!(join_handle.join());
            }
        }
    }


    fn mock_env_setup() -> (Routing, VaultComms) {
        ::utils::initialise_logger();
        let killer = ::std::sync::Arc::new(::std::sync::atomic::AtomicBool::new(false));
        let mut vault = Vault::new(None, Some(killer.clone()));
        let mut routing = vault.pmid_node.routing();
        let receiver = routing.get_client_receiver();
        let join_handle =
            Some(evaluate_result!(::std::thread::Builder::new().spawn(move || vault.do_run())));

        let mut available_nodes = Vec::with_capacity(30);
        for _ in 0..30 {
            available_nodes.push(::utils::random_name());
        }
        routing.churn_event(available_nodes, ::utils::random_name());
        (routing, VaultComms{ receiver: receiver, killer: killer, join_handle: join_handle })
    }

    #[test]
    fn put_get_flow() {
        let (mut routing, vault_comms) = mock_env_setup();

        let client_name = ::utils::random_name();
        let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let value = ::routing::types::generate_random_vec_u8(1024);
        let im_data = ::routing::immutable_data::ImmutableData::new(
                          ::routing::immutable_data::ImmutableDataType::Normal, value);
        routing.client_put(client_name,
                           sign_keys.0,
                           ::routing::data::Data::ImmutableData(im_data.clone()));
        ::std::thread::sleep_ms(2000);

        let data_request = ::routing::data::DataRequest::ImmutableData(im_data.name(),
                               ::routing::immutable_data::ImmutableDataType::Normal);
        routing.client_get(client_name, sign_keys.0, data_request);
        for it in vault_comms.receiver.iter() {
            assert_eq!(it, ::routing::data::Data::ImmutableData(im_data));
            break;
        }
    }

    #[test]
    fn post_flow() {
        let (mut routing, vault_comms) = mock_env_setup();

        let name = ::utils::random_name();
        let value = ::routing::types::generate_random_vec_u8(1024);
        let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let sd = evaluate_result!(
            ::routing::structured_data::StructuredData::new(0,
                                                            name,
                                                            0,
                                                            value.clone(),
                                                            vec![sign_keys.0],
                                                            vec![],
                                                            Some(&sign_keys.1)));

        let client_name = ::utils::random_name();
        routing.client_put(client_name,
                           sign_keys.0,
                           ::routing::data::Data::StructuredData(sd.clone()));
        ::std::thread::sleep_ms(2000);

        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let sd_new = evaluate_result!(
            ::routing::structured_data::StructuredData::new(0,
                                                            name,
                                                            1,
                                                            value.clone(),
                                                            vec![keys.0],
                                                            vec![sign_keys.0],
                                                            Some(&sign_keys.1)));
        routing.client_post(client_name,
                            sign_keys.0,
                            ::routing::data::Data::StructuredData(sd_new.clone()));
        ::std::thread::sleep_ms(2000);

        let data_request = ::routing::data::DataRequest::StructuredData(name, 0);
        routing.client_get(client_name, sign_keys.0, data_request);
        for it in vault_comms.receiver.iter() {
            assert_eq!(it, ::routing::data::Data::StructuredData(sd_new));
            break;
        }
    }
}

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
    routing: Routing,
    churn_timestamp: ::time::SteadyTime,
    id: ::routing::NameType,
    event_sender: Option<::std::sync::mpsc::Sender<(::routing::event::Event)>>,
}

impl Vault {
    pub fn run() {
        Vault::new(None).do_run();
    }

    fn new(event_sender: Option<::std::sync::mpsc::Sender<(::routing::event::Event)>>) -> Vault {
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
            routing: routing,
            id: ::routing::NameType::new([0u8; 64]),
            event_sender: event_sender,
        }
    }

    fn do_run(&mut self) {
        use routing::event::Event;
        while let Ok(event) = self.receiver.recv() {
            match self.event_sender.clone() {
                Some(sender) => {
                    let _ = sender.send(event.clone());
                }
                None => {}
            }
            info!("Vault {} received an event from routing : {:?}", self.id, event);
            match event {
                Event::Request{ request, our_authority, from_authority, response_token } =>
                    self.on_request(request, our_authority, from_authority, response_token),
                Event::Response{ response, our_authority, from_authority } =>
                    self.on_response(response, our_authority, from_authority),
                Event::Refresh(type_tag, our_authority, accounts) => self.on_refresh(type_tag,
                                                                                     our_authority,
                                                                                     accounts),
                Event::Churn(close_group) => self.on_churn(close_group),
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

    fn on_churn(&mut self, close_group: Vec<::routing::NameType>) {
        self.id = close_group[0].clone();
        let churn_up = close_group.len() > self.data_manager.nodes_in_table_len();
        let time_now = ::time::SteadyTime::now();
        // During the process of joining network, the vault shall not refresh its just received info
        if !(churn_up && (self.churn_timestamp + ::time::Duration::seconds(5) > time_now)) {
            self.handle_churn(close_group);
        } else {
            // We need to pass the close_group to data_manager to hold.
            self.data_manager.handle_churn(close_group);
        }
        if churn_up {
            info!("Vault added connected node");
            self.churn_timestamp = time_now;
        }
    }

    fn on_bootstrapped(&self) {
        // TODO: what is expected to be done here?
        assert_eq!(0, self.data_manager.nodes_in_table_len());
    }

    fn on_connected(&self) {
        // TODO: what is expected to be done here?
        assert_eq!(::routing::types::GROUP_SIZE, self.data_manager.nodes_in_table_len());
    }

    fn on_disconnected(&mut self) {
        self.routing.stop();
        let (sender, receiver) = ::std::sync::mpsc::channel();
        self.routing = Routing::new(sender);
        self.receiver = receiver;
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

    fn handle_churn(&mut self, close_group: Vec<::routing::NameType>) {
        self.maid_manager.handle_churn();
        self.sd_manager.handle_churn();
        self.pmid_manager.handle_churn(&close_group);
        self.data_manager.handle_churn(close_group);
    }

    fn handle_refresh(&mut self,
                      type_tag: u64,
                      our_authority: ::routing::Authority,
                      payloads: Vec<Vec<u8>>) {
        // TODO: The assumption of the incoming payloads is that it is a vector of serialised
        //       account entries from the close group nodes of `from_group`
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

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(feature = "use-mock-routing")]
    fn mock_env_setup() -> (Routing, ::std::sync::mpsc::Receiver<(::routing::data::Data)>) {
        ::utils::initialise_logger();
        let run_vault = |mut vault: Vault| {
            let _ = ::std::thread::spawn(move || {
                vault.do_run();
            });
        };
        let mut vault = Vault::new(None);
        let receiver = vault.routing.get_client_receiver();
        let mut routing = vault.routing.clone();
        let _ = run_vault(vault);

        let mut available_nodes = Vec::with_capacity(30);
        for _ in 0..30 {
            available_nodes.push(::utils::random_name());
        }
        routing.churn_event(available_nodes);
        (routing, receiver)
    }

    #[cfg(feature = "use-mock-routing")]
    #[test]
    fn put_get_flow() {
        let (mut routing, receiver) = mock_env_setup();

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
        for it in receiver.iter() {
            assert_eq!(it, ::routing::data::Data::ImmutableData(im_data));
            break;
        }
    }

    #[cfg(feature = "use-mock-routing")]
    #[test]
    fn post_flow() {
        let (mut routing, receiver) = mock_env_setup();

        let name = ::utils::random_name();
        let value = ::routing::types::generate_random_vec_u8(1024);
        let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let sd = ::routing::structured_data::StructuredData::new(0,
                                                                 name,
                                                                 0,
                                                                 value.clone(),
                                                                 vec![sign_keys.0],
                                                                 vec![],
                                                                 Some(&sign_keys.1))
                     .ok()
                     .unwrap();

        let client_name = ::utils::random_name();
        routing.client_put(client_name,
                           sign_keys.0,
                           ::routing::data::Data::StructuredData(sd.clone()));
        ::std::thread::sleep_ms(2000);

        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let sd_new = ::routing::structured_data::StructuredData::new(0,
                                                                     name,
                                                                     1,
                                                                     value.clone(),
                                                                     vec![keys.0],
                                                                     vec![sign_keys.0],
                                                                     Some(&sign_keys.1))
                         .ok()
                         .unwrap();
        routing.client_post(client_name,
                            sign_keys.0,
                            ::routing::data::Data::StructuredData(sd_new.clone()));
        ::std::thread::sleep_ms(2000);

        let data_request = ::routing::data::DataRequest::StructuredData(sd.name(), 0);
        routing.client_get(client_name, sign_keys.0, data_request);
        for it in receiver.iter() {
            assert_eq!(it, ::routing::data::Data::StructuredData(sd_new));
            break;
        }
    }

    #[cfg(not(feature = "use-mock-routing"))]
    fn network_env_setup() -> (Vec<::std::sync::mpsc::Receiver<(::routing::event::Event)>>,
            ::routing::routing_client::RoutingClient,
            ::std::sync::mpsc::Receiver<(::routing::data::Data)>,
            ::routing::NameType) {
        use routing::event::Event;
        ::utils::initialise_logger();
        match ::env_logger::init() {
            Ok(()) => {}
            Err(e) => println!("Error initialising logger; continuing without: {:?}", e),
        }
        let run_vault = |mut vault: Vault| {
            let _ = ::std::thread::spawn(move || {
                vault.do_run();
            });
        };
        let mut vault_receivers = Vec::new();
        for i in 0..8 {
            println!("starting node {:?}", i);
            let (sender, receiver) = ::std::sync::mpsc::channel();
            let _ = run_vault(Vault::new(Some(sender)));
            let mut cur_receiver = vec![receiver];
            waiting_for_hits(&cur_receiver, 10, i, ::time::Duration::seconds(10 * (i + 1) as i64));
            vault_receivers.push(cur_receiver.swap_remove(0));
        }
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
                        Event::Churn(_close_group) => info!("client received a churn"),
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
        if let Ok(_) = client_receiver.recv() {}
        (vault_receivers, client_routing, client_receiver, client_name)
    }

    #[cfg(not(feature = "use-mock-routing"))]
    // expected_tag: 0 -- Authority::ClientManager
    //               1 -- Authority::NaeManager
    //               2 -- Authority::NodeManager
    //               3 -- Authority::ManagedNode
    //               4 -- Authority::Client
    //              10 -- Event::Churn
    fn waiting_for_hits(
            vault_receivers: &Vec<::std::sync::mpsc::Receiver<(::routing::event::Event)>>,
            expected_tag: u32,
            expected_hits: usize,
            time_limit: ::time::Duration) {
        let mut hits = 0;
        let starting_time = ::time::SteadyTime::now();
        while hits < expected_hits {
            for receiver in vault_receivers.iter() {
                match receiver.try_recv() {
                    Err(_) => {}
                    Ok(::routing::event::Event::Request{ request, our_authority,
                                                         from_authority, response_token }) => {
                        info!("as {:?} received request: {:?} from {:?} having token {:?}",
                              our_authority, request, from_authority, response_token == None);
                        match (our_authority, expected_tag) {
                            (::routing::Authority::NaeManager(_), 1) => hits += 1,
                            (::routing::Authority::ManagedNode(_), 3) => hits += 1,
                            _ => {}
                        }
                    }
                    Ok(::routing::event::Event::Churn(_)) => {
                        if expected_tag == 10 {
                            hits += 1;
                        }
                    }
                    Ok(_) => {}
                }
            }
            ::std::thread::sleep_ms(1);
            if starting_time + time_limit < ::time::SteadyTime::now() {
                // As this function is only to be used in testing code, and a particially
                // established environment / testing result having a high chance indicates a failure
                // in code.  So here use panic to terminate the testing directly.
                panic!("waiting_for_hits can't resolve within the expected duration");
            }
        }
    }

    #[cfg(not(feature = "use-mock-routing"))]
    #[test]
    fn network_put_get_test() {
        let (vault_receivers, mut client_routing, client_receiver, client_name) =
            network_env_setup();

        let value = ::routing::types::generate_random_vec_u8(1024);
        let im_data = ::routing::immutable_data::ImmutableData::new(
                          ::routing::immutable_data::ImmutableDataType::Normal, value);
        println!("network_put_get_test putting data");
        client_routing.put_request(::maid_manager::Authority(client_name),
                                   ::routing::data::Data::ImmutableData(im_data.clone()));
        waiting_for_hits(&vault_receivers,
                         3,
                         ::data_manager::PARALLELISM,
                         ::time::Duration::minutes(1));
        println!("network_put_get_test getting data");
        client_routing.get_request(::data_manager::Authority(im_data.name()),
                                   ::routing::data::DataRequest::ImmutableData(im_data.name(),
                ::routing::immutable_data::ImmutableDataType::Normal));
        while let Ok(data) = client_receiver.recv() {
            assert_eq!(data, ::routing::data::Data::ImmutableData(im_data.clone()));
            break;
        }
    }

    #[cfg(not(feature = "use-mock-routing"))]
    #[test]
    fn network_post_test() {
        let (vault_receivers, mut client_routing, client_receiver, client_name) =
            network_env_setup();

        let name = ::utils::random_name();
        let value = ::routing::types::generate_random_vec_u8(1024);
        let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let sd = ::routing::structured_data::StructuredData::new(0,
                                                                 name,
                                                                 0,
                                                                 value.clone(),
                                                                 vec![sign_keys.0],
                                                                 vec![],
                                                                 Some(&sign_keys.1))
                     .ok()
                     .unwrap();
        println!("network_post_test putting data");
        client_routing.put_request(::maid_manager::Authority(client_name),
                                   ::routing::data::Data::StructuredData(sd.clone()));
        waiting_for_hits(&vault_receivers,
                         1,
                         ::routing::types::GROUP_SIZE,
                         ::time::Duration::minutes(1));

        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let sd_new = ::routing::structured_data::StructuredData::new(0,
                                                                     name,
                                                                     1,
                                                                     value.clone(),
                                                                     vec![keys.0],
                                                                     vec![sign_keys.0],
                                                                     Some(&sign_keys.1))
                         .ok()
                         .unwrap();
        println!("network_post_test posting data");
        client_routing.post_request(::sd_manager::Authority(sd.name()),
                                    ::routing::data::Data::StructuredData(sd_new.clone()));
        waiting_for_hits(&vault_receivers,
                         1,
                         ::routing::types::GROUP_SIZE,
                         ::time::Duration::minutes(1));
        println!("network_post_test getting data");
        client_routing.get_request(::sd_manager::Authority(sd.name()),
                                   ::routing::data::DataRequest::StructuredData(sd.name(), 0));
        while let Ok(data) = client_receiver.recv() {
            assert_eq!(data, ::routing::data::Data::StructuredData(sd_new.clone()));
            break;
        }
    }

    #[cfg(not(feature = "use-mock-routing"))]
    #[test]
    fn network_churn_immutable_data_test() {
        let (vault_receivers, mut client_routing, client_receiver, client_name) =
            network_env_setup();

        let value = ::routing::types::generate_random_vec_u8(1024);
        let im_data = ::routing::immutable_data::ImmutableData::new(
                          ::routing::immutable_data::ImmutableDataType::Normal, value);
        println!("network_churn_immutable_data_test putting data");
        client_routing.put_request(::maid_manager::Authority(client_name),
                                   ::routing::data::Data::ImmutableData(im_data.clone()));
        waiting_for_hits(&vault_receivers,
                         3,
                         ::data_manager::PARALLELISM,
                         ::time::Duration::minutes(1));

        println!("network_churn_immutable_data_test starting new vault");
        let (sender, receiver) = ::std::sync::mpsc::channel();
        let _ = ::std::thread::spawn(move || {
            ::vault::Vault::new(Some(sender)).do_run();
        });
        let new_vault_receivers = vec![receiver];
        waiting_for_hits(&new_vault_receivers,
                         10,
                         ::routing::types::GROUP_SIZE - 1,
                         ::time::Duration::seconds(30));
        println!("network_churn_immutable_data_test getting data");
        client_routing.get_request(::data_manager::Authority(im_data.name()),
                                   ::routing::data::DataRequest::ImmutableData(im_data.name(),
                ::routing::immutable_data::ImmutableDataType::Normal));
        while let Ok(data) = client_receiver.recv() {
            assert_eq!(data, ::routing::data::Data::ImmutableData(im_data.clone()));
            break;
        }
    }

    #[cfg(not(feature = "use-mock-routing"))]
    #[test]
    fn network_churn_structured_data_test() {
        let (vault_receivers, mut client_routing, client_receiver, client_name) =
            network_env_setup();

        let name = ::utils::random_name();
        let value = ::routing::types::generate_random_vec_u8(1024);
        let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let sd = ::routing::structured_data::StructuredData::new(0,
                                                                 name,
                                                                 0,
                                                                 value.clone(),
                                                                 vec![sign_keys.0],
                                                                 vec![],
                                                                 Some(&sign_keys.1))
                     .ok()
                     .unwrap();
        println!("network_churn_structured_data_test putting data");
        client_routing.put_request(::maid_manager::Authority(client_name),
                                   ::routing::data::Data::StructuredData(sd.clone()));
        waiting_for_hits(&vault_receivers,
                         1,
                         ::routing::types::GROUP_SIZE,
                         ::time::Duration::minutes(1));

        println!("network_churn_structured_data_test starting new vault");
        let (sender, receiver) = ::std::sync::mpsc::channel();
        let _ = ::std::thread::spawn(move || {
            ::vault::Vault::new(Some(sender)).do_run();
        });
        let new_vault_receivers = vec![receiver];
        waiting_for_hits(&new_vault_receivers,
                         10,
                         ::routing::types::GROUP_SIZE - 1,
                         ::time::Duration::minutes(1));
        println!("network_churn_structured_data_test getting data");
        client_routing.get_request(::sd_manager::Authority(sd.name()),
                                   ::routing::data::DataRequest::StructuredData(sd.name(), 0));
        while let Ok(data) = client_receiver.recv() {
            assert_eq!(data, ::routing::data::Data::StructuredData(sd.clone()));
            break;
        }
    }
}

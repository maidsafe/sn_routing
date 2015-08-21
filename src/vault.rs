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

use routing_types::*;

#[cfg(feature = "use-actual-routing")]
type Routing = ::routing::routing::Routing;
#[cfg(feature = "use-actual-routing")]
fn get_new_routing(event_sender: ::std::sync::mpsc::Sender<(::routing::event::Event)>) -> Routing {
    ::routing::routing::Routing::new(event_sender)
}

#[cfg(not(feature = "use-actual-routing"))]
type Routing = ::non_networking_test_framework::MockRouting;
#[cfg(not(feature = "use-actual-routing"))]
fn get_new_routing(event_sender: ::std::sync::mpsc::Sender<(::routing::event::Event)>) -> Routing {
    ::non_networking_test_framework::MockRouting::new(event_sender)
}

#[allow(dead_code)]
fn merge_refreshable<T>(empty_entry: T, payloads: Vec<Vec<u8>>) ->
        T where T: for<'a> Sendable + ::rustc_serialize::Encodable + ::rustc_serialize::Decodable +
        'static {
    let mut transfer_entries = Vec::<Box<Sendable>>::new();
    for it in payloads.iter() {
        let mut decoder = ::cbor::Decoder::from_bytes(&it[..]);
        if let Some(parsed_entry) = decoder.decode().next().and_then(|result| result.ok()) {
            let parsed: T = parsed_entry;
            transfer_entries.push(Box::new(parsed));
        }
    }
    match empty_entry.merge(transfer_entries) {
        Some(result) => {
            let mut decoder = ::cbor::Decoder::from_bytes(&result.serialised_contents()[..]);
            if let Some(parsed_entry) = decoder.decode().next().and_then(|result| result.ok()) {
                let parsed: T = parsed_entry;
                parsed
            } else {
                empty_entry
            }
        }
        None => empty_entry
    }
}

/// Main struct to hold all personas and Routing instance
pub struct Vault {
    data_manager: ::data_manager::DataManager,
    maid_manager: ::maid_manager::MaidManager,
    pmid_manager: ::pmid_manager::PmidManager,
    pmid_node: ::pmid_node::PmidNode,
    sd_manager: ::sd_manager::StructuredDataManager,
    nodes_in_table: Vec<NameType>,
    #[allow(dead_code)]
    data_cache: ::lru_time_cache::LruCache<NameType, Data>,
    request_cache: ::lru_time_cache::LruCache<NameType, Vec<(Authority, DataRequest)>>,
    receiver: ::std::sync::mpsc::Receiver<::routing::event::Event>,
    #[allow(dead_code)]
    routing: Routing,
}

impl Vault {
    pub fn run() {
        Vault::new().do_run()
    }

    fn new() -> Vault {
        ::sodiumoxide::init();
        let (sender, receiver) = ::std::sync::mpsc::channel();
        Vault {
            data_manager: ::data_manager::DataManager::new(),
            maid_manager: ::maid_manager::MaidManager::new(),
            pmid_manager: ::pmid_manager::PmidManager::new(),
            pmid_node: ::pmid_node::PmidNode::new(),
            sd_manager: ::sd_manager::StructuredDataManager::new(),
            nodes_in_table: Vec::new(),
            data_cache: ::lru_time_cache::LruCache::with_expiry_duration_and_capacity(
                ::time::Duration::minutes(10), 100),
            request_cache: ::lru_time_cache::LruCache::with_expiry_duration_and_capacity(
                ::time::Duration::minutes(5), 1000),
            receiver: receiver,
            routing: get_new_routing(sender)
        }
    }

    fn do_run(&mut self) {
        use ::routing::event::Event;
        while let Ok(event) = self.receiver.recv() {
            match event {
                Event::Request{ request, our_authority, from_authority, response_token } => {
                    println!("request :  {:?}  ;  our_authority : {:?}  ;  from_authority : {:?}",
                             request, our_authority, from_authority);
                    self.on_request(request, our_authority, from_authority, response_token)
                },
                Event::Response{ response, our_authority, from_authority } =>
                    self.on_response(response, our_authority, from_authority),
                Event::Refresh(type_tag, group_name, accounts) =>
                    self.on_refresh(type_tag, group_name, accounts),
                Event::Churn(close_group) => self.on_churn(close_group),
                Event::Connected => self.on_connected(),
                Event::Disconnected => self.on_disconnected(),
                Event::FailedRequest(location, request, error) =>
                    self.on_failed_request(location, request, error),
                Event::FailedResponse(location, response, error) =>
                    self.on_failed_response(location, response, error),
                Event::Terminated => break,
            };
        }
    }

    fn on_request(&mut self,
                  request: ::routing::ExternalRequest,
                  our_authority: ::routing::authority::Authority,
                  from_authority: ::routing::authority::Authority,
                  response_token: Option<::routing::SignedToken>) {
        match request {
            ::routing::ExternalRequest::Get(data_request) => {
                self.handle_get(our_authority, from_authority, data_request, response_token);
            },
            ::routing::ExternalRequest::Put(data) => {
                // TODO - remove 'let _ = '
                let _ = self.handle_put(our_authority, from_authority, data, response_token);
            },
            ::routing::ExternalRequest::Post(/*data*/_) => {
                unimplemented!();
            },
            ::routing::ExternalRequest::Delete(/*data*/_) => {
                unimplemented!();
            },
        }
    }

    fn on_response(&mut self,
                   response: ::routing::ExternalResponse,
                   our_authority: ::routing::authority::Authority,
                   from_authority: ::routing::authority::Authority) {
        println!("vault as {:?} received response from {:?}", our_authority, from_authority);
        match response {
            ::routing::ExternalResponse::Get(data, _, response_token) => {
                self.handle_get_response(our_authority, from_authority, data, response_token);
            },
            ::routing::ExternalResponse::Put(/*response_error*/_, /*response_token*/_) => {
                unimplemented!();
            },
            ::routing::ExternalResponse::Post(/*response_error*/_, /*response_token*/_) => {
                unimplemented!();
            },
            ::routing::ExternalResponse::Delete(/*response_error*/_, /*response_token*/_) => {
                unimplemented!();
            },
        }
    }

    fn on_refresh(&mut self,
                  /*type_tag*/_: u64,
                  /*group_name*/_: ::routing::NameType,
                  /*accounts*/_: Vec<Vec<u8>>) {
        println!("vault on refresh");
        unimplemented!();
    }

    fn on_churn(&mut self, close_group: Vec<::routing::NameType>) {
        println!("vault on churn");
        self.nodes_in_table = close_group;
    }

    fn on_connected(&mut self) {
        println!("vault on connected");
        unimplemented!();
    }

    fn on_disconnected(&mut self) {
        println!("vault on disconnected");
        unimplemented!();
    }

    fn on_failed_request(&mut self,
                         /*location*/_: Authority,
                         /*request*/_: ExternalRequest,
                         /*error*/_: InterfaceError) {
        println!("vault on failed request");
        unimplemented!();
    }

    fn on_failed_response(&mut self,
                          /*location*/_: Authority,
                          /*response*/_: ExternalResponse,
                          /*error*/_: InterfaceError) {
        println!("vault on failed response");
        unimplemented!();
    }

    fn handle_get(&mut self,
                  our_authority: Authority,
                  mut from_authority: Authority,
                  data_request: DataRequest,
                  response_token: Option<::routing::SignedToken>) {
        let returned_actions = match our_authority {
            Authority::NaeManager(name) => {
                println!("vault NaeManager received get request for data {:}", name);
                // both DataManager and StructuredDataManager are NaeManagers and Get request to
                // them are both from Node
                match data_request.clone() {
                    // drop the message if we don't have the data
                    DataRequest::ImmutableData(_, _) => {
                        // Only remember the request from client for Immutable Data
                        // as StructuredData will get replied immediately from SDManager
                        if self.request_cache.contains_key(&name) {
                            self.request_cache.get_mut(&name).unwrap().push((from_authority.clone(),
                                                                             data_request.clone()));
                        } else {
                            self.request_cache.add(name, vec![(from_authority.clone(), data_request.clone())]);
                        }
                        self.data_manager.handle_get(&name, data_request.clone())
                    }
                    DataRequest::StructuredData(_, _) => self.sd_manager.handle_get(name),
                    _ => Ok(vec![]),
                }
            },
            Authority::ManagedNode(_) => {
                println!("vault ManagedNode received get request from {:?}", from_authority);
                match data_request.clone() {
                    DataRequest::ImmutableData(name, _) => {
                        from_authority = Authority::NaeManager(name.clone());
                        self.pmid_node.handle_get(name)
                    },
                    _ => Ok(vec![]),
                }
                // match from_authority {
                //     // drop the message if we don't have the data
                //     Authority::NaeManager(name) => self.pmid_node.handle_get(name),
                //     _ => Ok(vec![]),
                // }
            },
            _ => Ok(vec![]),
        };
        if let Ok(actions) = returned_actions {
            self.send(actions, response_token, Some(from_authority), Some(data_request));
        }
    }

    fn handle_put(&mut self,
                  our_authority: Authority,
                  _: Authority,
                  data: Data,
                  response_token: Option<::routing::SignedToken>) {
        let returned_actions = match our_authority {
            Authority::ClientManager(from_address) => self.maid_manager.handle_put(&from_address, data),
            Authority::NaeManager(_) => {
                // both DataManager and StructuredDataManager are NaeManagers
                // client put other data (Immutable, StructuredData) will all goes to MaidManager
                // first, then goes to DataManager (i.e. from_authority is always ClientManager)
                match data {
                    Data::ImmutableData(data) => self.data_manager.handle_put(data, &mut (self.nodes_in_table)),
                    Data::StructuredData(data) => self.sd_manager.handle_put(data),
                    _ => Ok(vec![]),
                }
            },
            Authority::NodeManager(dest_address) => self.pmid_manager.handle_put(dest_address, data),
            Authority::ManagedNode(_) => self.pmid_node.handle_put(data),
            _ => Ok(vec![]),
        };
        if let Ok(actions) = returned_actions {
            self.send(actions, response_token, None, None);
        }
    }

    // Post is only used to update the content or owners of a StructuredData
    #[allow(dead_code)]
    fn handle_post(&mut self,
                   our_authority: Authority,
                   _: Authority, // from_authority
                   data: Data,
                   _: Option<::routing::SignedToken>) ->
            Result<Vec<MethodCall>, ResponseError> {
        match our_authority {
            Authority::NaeManager(_) => {
                match data {
                    Data::StructuredData(data) => { return self.sd_manager.handle_post(data); }
                    _ => {}
                }
            }
            _ => {}
        }
        Err(ResponseError::InvalidRequest(data))
    }

    #[allow(dead_code)]
    fn handle_get_response(&mut self,
                           our_authority: Authority,
                           _from_authority: Authority,
                           response: Data,
                           response_token: Option<::routing::SignedToken>) {
        match our_authority {
            // Lookup in the request_cache and reply to the clients
            Authority::NaeManager(name) => {
                if self.request_cache.contains_key(&name) {
                    let records = self.request_cache.remove(&name).unwrap();
                    for record in records {
                        self.send(vec![MethodCall::Reply{ data: response.clone() }], response_token.clone(),
                                  Some(record.0), Some(record.1));
                    }
                }
            },
            _ => {}
        }
        let returned_actions = match response.clone() {
            // GetResponse used by DataManager to replicate data to new PN
            Data::ImmutableData(_) => self.data_manager.handle_get_response(response),
            _ => vec![]
        };
        self.send(returned_actions, None, None, None);
    }

    // Put response will holding the copy of failed to store data, which will be:
    //     1, the original immutable data if it failed to squeeze in
    //     2, the sacrificial copy if it has been removed to empty the space
    // DataManager doesn't need to carry out replication in case of sacrificial copy
    #[allow(dead_code)]
    fn handle_put_response(&mut self,
                           from_authority: Authority,
                           response: ResponseError,
                           _: Option<::routing::SignedToken>) -> Vec<MethodCall> {
        match from_authority {
            Authority::ManagedNode(pmid_node) =>
                self.pmid_manager.handle_put_response(&pmid_node, response),
            Authority::NodeManager(pmid_node) =>
                self.data_manager.handle_put_response(response, &pmid_node),
            _ => vec![]
        }
    }

    // https://maidsafe.atlassian.net/browse/MAID-1111 post_response is not required on vault
    #[allow(dead_code)]
    fn handle_post_response(&mut self,
                            _: Authority, // from_authority
                            _: ResponseError,
                            _: Option<::routing::SignedToken>) -> Vec<MethodCall> {
        vec![]
    }

    #[allow(dead_code)]
    fn handle_churn(&mut self, mut close_group: Vec<NameType>) -> Vec<MethodCall> {
        let mm = self.maid_manager.retrieve_all_and_reset();
        let vh = self.sd_manager.retrieve_all_and_reset();
        let pm = self.pmid_manager.retrieve_all_and_reset(&close_group);
        let dm = self.data_manager.retrieve_all_and_reset(&mut close_group);
        self.nodes_in_table = close_group;

        mm.into_iter().chain(vh.into_iter().chain(pm.into_iter().chain(dm.into_iter()))).collect()
    }

    #[allow(dead_code)]
    fn handle_refresh(&mut self,
                      type_tag: u64,
                      from_group: NameType,
                      payloads: Vec<Vec<u8>>) {
        // TODO: The assumption of the incoming payloads is that it is a vector of serialised
        //       account entries from the close group nodes of `from_group`
        match type_tag {
            ::transfer_parser::transfer_tags::MAID_MANAGER_ACCOUNT_TAG => {
                let merged_account = merge_refreshable(
                    ::maid_manager::MaidManagerAccountWrapper::new(from_group,
                        ::maid_manager::MaidManagerAccount::new()), payloads);
                self.maid_manager.handle_account_transfer(merged_account);
            },
            ::transfer_parser::transfer_tags::DATA_MANAGER_ACCOUNT_TAG => {
                let merged_account = merge_refreshable(
                    ::data_manager::DataManagerSendable::new(from_group, vec![]), payloads);
                self.data_manager.handle_account_transfer(merged_account);
            },
            ::transfer_parser::transfer_tags::PMID_MANAGER_ACCOUNT_TAG => {
                let merged_account = merge_refreshable(
                    ::pmid_manager::PmidManagerAccountWrapper::new(from_group,
                        ::pmid_manager::PmidManagerAccount::new()), payloads);
                self.pmid_manager.handle_account_transfer(merged_account);
            },
            ::transfer_parser::transfer_tags::SD_MANAGER_ACCOUNT_TAG => {
                for payload in payloads {
                    self.sd_manager.handle_account_transfer(payload);
                }
            },
            ::transfer_parser::transfer_tags::DATA_MANAGER_STATS_TAG => {
                let merged_stats = merge_refreshable(
                    ::data_manager::DataManagerStatsSendable::new(from_group, 0), payloads);
                self.data_manager.handle_stats_transfer(merged_stats);
            },
            _ => {},
        }
    }

    // The cache handling in vault is roleless, i.e. vault will do whatever routing tells it to do
    #[allow(dead_code)]
    fn handle_cache_get(&mut self,
                        _: DataRequest, // data_request
                        data_location: NameType,
                        _: NameType,
                        _: Option<::routing::SignedToken>) ->
            Result<MethodCall, ResponseError> { // from_address
        match self.data_cache.get(&data_location) {
            Some(data) => Ok(MethodCall::Reply { data: data.clone() }),
            // TODO: NoData may still be preferred here
            None => Err(ResponseError::Abort)
        }
    }

    #[allow(dead_code)]
    fn handle_cache_put(&mut self,
                        _: Authority, // from_authority
                        _: NameType, // from_address
                        data: Data,
                        _: Option<::routing::SignedToken>) ->
            Result<MethodCall, ResponseError> {
        self.data_cache.add(data.name(), data);
        Err(ResponseError::Abort)
    }

    #[allow(dead_code)]
    fn send(&mut self, actions: Vec<MethodCall>,
            response_token: Option<::routing::SignedToken>,
            reply_to: Option<Authority>,
            original_data_request: Option<DataRequest>) {
        for action in actions {
            match action {
                MethodCall::Get { location, data_request } => {
                    println!("vault send get request");
                    self.routing.get_request(location, data_request);
                },
                MethodCall::Put { location, content } => {
                    println!("vault send put request");
                    self.routing.put_request(location, content);
                },
                MethodCall::Reply { data } => {
                    if reply_to != None && original_data_request != None {
                        println!("vault send reply to {:?}", reply_to.clone().unwrap());
                        self.routing.get_response(reply_to.clone().unwrap(), data,
                            original_data_request.clone().unwrap(), response_token.clone());
                    }
                },
                _ => {}
            }
        }
    }
}

pub type ResponseNotifier =
    ::std::sync::Arc<(::std::sync::Mutex<Result<Vec<MethodCall>, ::routing::error::ResponseError>>,
                      ::std::sync::Condvar)>;

#[cfg(test)]
 mod test {
    use cbor;
    use sodiumoxide::crypto;

    use super::*;
    // use data_manager;
    use transfer_parser::{Transfer, transfer_tags};
    use routing_types::*;

    #[cfg(not(feature = "use-actual-routing"))]
    #[test]
    fn put_get_flow() {
        let run_vault = |mut vault: Vault| {
            let _ = ::std::thread::spawn(move || {
                vault.do_run();
            });
        };
        let mut vault = Vault::new();
        let receiver = vault.routing.get_client_receiver();
        let mut routing = vault.routing.clone();
        let _ = run_vault(vault);

        let mut available_nodes = Vec::with_capacity(30);
        for _ in 0..30 {
            available_nodes.push(::routing::NameType(::routing::types::vector_as_u8_64_array(
                ::routing::types::generate_random_vec_u8(64))));
        }
        routing.churn_event(available_nodes);

        let client_name = ::routing::NameType(::routing::types::vector_as_u8_64_array(
            ::routing::types::generate_random_vec_u8(64)));
        let sign_keys =  ::sodiumoxide::crypto::sign::gen_keypair();
        let value = ::routing::types::generate_random_vec_u8(1024);
        let im_data = ::routing::immutable_data::ImmutableData::new(
            ::routing::immutable_data::ImmutableDataType::Normal, value);
        routing.client_put(client_name, sign_keys.0,
            ::routing::data::Data::ImmutableData(im_data.clone()));
        ::std::thread::sleep_ms(2000);

        routing.client_get(client_name, sign_keys.0, im_data.name());
        for it in receiver.iter() {
            assert_eq!(it, ::routing::data::Data::ImmutableData(im_data));
            break;
        }
    }

    #[cfg(feature = "use-actual-routing")]
    #[test]
    fn network_put_get_test() {
        let run_vault = |mut vault: Vault| {
            let _ = ::std::thread::spawn(move || {
                vault.do_run();
            });
        };
        for i in 0..4 {
            println!("starting node {:?}", i);
            let _ = run_vault(Vault::new());
            ::std::thread::sleep_ms(1000 + i * 1000);
        }
        let (sender, receiver) = ::std::sync::mpsc::channel();
        let (client_sender, client_receiver) = ::std::sync::mpsc::channel();
        let client_receiving = |receiver: ::std::sync::mpsc::Receiver<(Event)>,
                                client_sender: ::std::sync::mpsc::Sender<(Data)>| {
            let _ = ::std::thread::spawn(move || {
                println!("client routing starts listen");
                while let Ok(event) = receiver.recv() {
                    println!("client routing received an event");
                    match event {
                        Event::Request{ request, our_authority, from_authority, response_token } =>
                            println!("as {:?} received request: {:?} from {:?} having token {:?}",
                                     our_authority, request, from_authority, response_token == None),
                        Event::Response{ response, our_authority, from_authority } => {
                            println!("as {:?} received response: {:?} from {:?}",
                                     our_authority, response, from_authority);
                            match response {
                                ExternalResponse::Get(data, _, _) => {
                                    let _ = client_sender.clone().send(data);
                                },
                                _ => panic!("not expected!")
                            }
                        },
                        Event::Refresh(_type_tag, _group_name, _accounts) =>
                            println!("client received a refresh"),
                        Event::Churn(_close_group) => println!("client received a churn"),
                        Event::Connected => {
                            // client_routing.stop();
                            println!("client connected");
                        },
                        Event::Disconnected => println!("client disconnected"),
                        Event::FailedRequest(_location, _request, _error) =>
                            println!("client received a failed request"),
                        Event::FailedResponse(_location, _response, _error) =>
                            println!("client received a failed response"),
                        Event::Terminated => {
                            println!("client routing listening terminated");
                            break;
                        },
                    };
                }
            });
        };
        let _ = client_receiving(receiver, client_sender);
        // let mut client_routing = ::routing::routing::Routing::new_client(sender, None);
        let client_routing = ::routing::routing::Routing::new_client(sender, Some(::routing::id::Id::new()));
        println!("client routing created");
        // let _ = thread_guard.join();
        ::std::thread::sleep_ms(1000);

        let client_name = ::routing::NameType(::routing::types::vector_as_u8_64_array(
            ::routing::types::generate_random_vec_u8(64)));
        let value = ::routing::types::generate_random_vec_u8(1024);
        let im_data = ::routing::immutable_data::ImmutableData::new(
            ::routing::immutable_data::ImmutableDataType::Normal, value);
        client_routing.put_request(::routing::authority::Authority::ClientManager(client_name),
                                   ::routing::data::Data::ImmutableData(im_data.clone()));
        ::std::thread::sleep_ms(2000);
        client_routing.get_request(::routing::authority::Authority::NaeManager(im_data.name()),
            ::routing::data::DataRequest::ImmutableData(im_data.name(),
                ::routing::immutable_data::ImmutableDataType::Normal));
        while let Ok(data) = client_receiver.recv() {
            assert_eq!(data, ::routing::data::Data::ImmutableData(im_data.clone()));
            break;
        }
    }

    fn maid_manager_put(vault: &mut Vault, client: NameType, im_data: ImmutableData) {
        let keys = crypto::sign::gen_keypair();
        let _put_result = vault.handle_put(Authority::ClientManager(client),
                                          Authority::Client(client, keys.0),
                                          Data::ImmutableData(im_data.clone()), None);
        // assert_eq!(put_result.is_err(), false);
        // let calls = put_result.ok().unwrap();
        // assert_eq!(calls.len(), 1);
        // match calls[0] {
        //     MethodCall::Put { destination, ref content } => {
        //         assert_eq!(destination, im_data.name());
        //         assert_eq!(*content,  Data::ImmutableData(im_data.clone()));
        //     }
        //     _ => panic!("Unexpected"),
        // }
    }

    fn data_manager_put(vault: &mut Vault, im_data: ImmutableData) {
        let _put_result = vault.handle_put(Authority::NaeManager(im_data.name()),
                                          Authority::ClientManager(NameType::new([1u8; 64])),
                                          Data::ImmutableData(im_data), None);
        // assert_eq!(put_result.is_err(), false);
        // let calls = put_result.ok().unwrap();
        // assert_eq!(calls.len(), data_manager::PARALLELISM);
    }

    fn add_nodes_to_table(vault: &mut Vault, nodes: &Vec<NameType>) {
        for node in nodes {
            vault.nodes_in_table.push(node.clone());
        }
    }

    fn pmid_manager_put(vault: &mut Vault, pmid_node: NameType, im_data: ImmutableData) {
          let _put_result = vault.handle_put(Authority::NodeManager(pmid_node),
                                            Authority::NaeManager(im_data.name()),
                                            Data::ImmutableData(im_data), None);
        // assert_eq!(put_result.is_err(), false);
        // let calls = put_result.ok().unwrap();
        // assert_eq!(calls.len(), 1);
        // match calls[0] {
        //     MethodCall::Forward { destination } => {
        //         assert_eq!(destination, pmid_node);
        //     }
        //     _ => panic!("Unexpected"),
        // }
    }

    fn sd_manager_put(vault: &mut Vault, sdv: StructuredData) {
        let _put_result = vault.handle_put(Authority::NaeManager(sdv.name()),
                                          Authority::ManagedNode(NameType::new([7u8; 64])),
                                          Data::StructuredData(sdv.clone()), None);
        // assert_eq!(put_result.is_ok(), true);
        // let mut calls = put_result.ok().unwrap();
        // assert_eq!(calls.len(), 1);
        // match calls.remove(0) {
        //     MethodCall::Reply { data } => {
        //         match data {
        //             Data::StructuredData(sd) => {
        //                 assert_eq!(sd, sdv);
        //             }
        //             _ => panic!("Unexpected"),
        //         }
        //     }
        //     _ => panic!("Unexpected"),
        // }
    }

    fn sd_manager_post(vault: &mut Vault, sdv: StructuredData) {
        let post_result = vault.handle_post(Authority::NaeManager(sdv.name()),
                                            Authority::ManagedNode(NameType::new([7u8; 64])),
                                            Data::StructuredData(sdv.clone()), None);
        assert_eq!(post_result.is_ok(), true);
    }

    fn sd_manager_get(vault: &mut Vault, name: NameType, _sd_expected: StructuredData) {
        let _get_result = vault.handle_get(Authority::NaeManager(name),
                                          Authority::ManagedNode(NameType::new([7u8; 64])),
                                          DataRequest::StructuredData(name, 0), None);
        // assert_eq!(get_result.is_ok(), true);
        // let mut calls = get_result.ok().unwrap();
        // assert_eq!(calls.len(), 1);
        // match calls.remove(0) {
        //     MethodCall::Reply { data } => {
        //         match data {
        //             Data::StructuredData(sd) => {
        //                 assert_eq!(sd, sd_expected);
        //             }
        //             _ => panic!("Unexpected"),
        //         }
        //     }
        //     _ => panic!("Unexpected"),
        // }
    }


    #[test]
    fn structured_data_put_post_get() {
        let mut vault = Vault::new();

        let name = NameType([3u8; 64]);
        let value = generate_random_vec_u8(1024);
        let keys1 = crypto::sign::gen_keypair();
        let sd = StructuredData::new(0, name, 0, value.clone(), vec![keys1.0], vec![],
                                     Some(&keys1.1)).ok().unwrap();

        sd_manager_put(&mut vault, sd.clone());

        let keys2 = crypto::sign::gen_keypair();
        let sd_new = StructuredData::new(0, name, 1, value.clone(), vec![keys2.0], vec![keys1.0],
                                         Some(&keys1.1)).ok().unwrap();
        sd_manager_post(&mut vault, sd_new.clone());

        sd_manager_get(&mut vault, StructuredData::compute_name(0, &name), sd_new);
    }

    #[test]
    fn churn_test() {
        let mut vault = Vault::new();

        let mut available_nodes = Vec::with_capacity(30);
        for _ in 0..30 {
            available_nodes.push(NameType(vector_as_u8_64_array(generate_random_vec_u8(64))));
        }

        let value = generate_random_vec_u8(1024);
        let im_data = ImmutableData::new(ImmutableDataType::Normal, value);

        let mut small_close_group = Vec::with_capacity(5);
        for i in 0..5 {
            small_close_group.push(available_nodes[i].clone());
        }

        {// MaidManager - churn handling
            maid_manager_put(&mut vault, available_nodes[0].clone(), im_data.clone());
            let churn_data = vault.handle_churn(small_close_group.clone());
            // DataManagerStatsTransfer will always be included in the return
            assert!(churn_data.len() == 2);

            // MaidManagerAccount
            match churn_data[0] {
                MethodCall::Refresh{ref type_tag, ref from_group, ref payload} => {
                    assert_eq!(*type_tag,
                               ::transfer_parser::transfer_tags::MAID_MANAGER_ACCOUNT_TAG);
                    assert_eq!(*from_group, available_nodes[0]);
                    let mut d = cbor::Decoder::from_bytes(&payload[..]);
                    if let Some(parsed_data) = d.decode().next().and_then(|result| result.ok()) {
                        match parsed_data {
                            Transfer::MaidManagerAccount(mm_account_wrapper) => {
                                assert_eq!(mm_account_wrapper.name(), available_nodes[0]);
                                assert_eq!(mm_account_wrapper.get_account().get_data_stored(),
                                           1024);
                            },
                            _ => panic!("Unexpected"),
                        }
                    }
                },
                _ => panic!("Refresh type expected")
            };
            assert!(vault.maid_manager.retrieve_all_and_reset().is_empty());
        }

        add_nodes_to_table(&mut vault, &available_nodes);

        {// DataManager - churn handling
            data_manager_put(&mut vault, im_data.clone());
            let mut close_group = Vec::with_capacity(20);
            for i in 10..30 {
                close_group.push(available_nodes[i].clone());
            }
            // DataManagerStatsTransfer will always be included in the return
            let churn_data = vault.handle_churn(close_group.clone());
            assert_eq!(churn_data.len(), 2);

            match churn_data[0] {
                MethodCall::Refresh{ref type_tag, ref from_group, ref payload} => {
                    assert_eq!(*type_tag, transfer_tags::DATA_MANAGER_ACCOUNT_TAG);
                    assert_eq!(*from_group, im_data.name());
                    let mut d = cbor::Decoder::from_bytes(&payload[..]);
                    if let Some(parsed_data) = d.decode().next().and_then(|result| result.ok()) {
                        match parsed_data {
                            Transfer::DataManagerAccount(data_manager_sendable) => {
                                assert_eq!(data_manager_sendable.name(), im_data.name());
                            },
                            _ => panic!("Unexpected"),
                        }
                    }
                },
                MethodCall::Get { .. } => (),
                _ => panic!("Refresh type expected")
            };

            match churn_data[1] {
                MethodCall::Refresh{ref type_tag, ref from_group, ref payload} => {
                    assert_eq!(*type_tag, transfer_tags::DATA_MANAGER_STATS_TAG);
                    assert_eq!(*from_group, close_group[0]);
                    let mut d = cbor::Decoder::from_bytes(&payload[..]);
                    if let Some(parsed_data) = d.decode().next().and_then(|result| result.ok()) {
                        match parsed_data {
                            Transfer::DataManagerStats(stats_sendable) => {
                                assert_eq!(stats_sendable.get_resource_index(), 1);
                            },
                            _ => panic!("Unexpected"),
                        }
                    }
                },
                MethodCall::Get { .. } => (),
                _ => panic!("Refresh type expected")
            };
            // DataManagerStatsTransfer will always be included in the return
            assert_eq!(vault.data_manager.retrieve_all_and_reset(&mut close_group).len(), 1);
        }

        {// PmidManager - churn handling
            pmid_manager_put(&mut vault, available_nodes[1].clone(), im_data.clone());
            let churn_data = vault.handle_churn(small_close_group.clone());
            // DataManagerStatsTransfer will always be included in the return
            assert_eq!(churn_data.len(), 2);
            //assert_eq!(churn_data[0].0, from);

            match churn_data[0] {
                MethodCall::Refresh{ref type_tag, ref from_group, ref payload} => {
                    assert_eq!(*type_tag, transfer_tags::PMID_MANAGER_ACCOUNT_TAG);
                    assert_eq!(*from_group, available_nodes[1]);
                    let mut d = cbor::Decoder::from_bytes(&payload[..]);
                    if let Some(parsed_data) = d.decode().next().and_then(|result| result.ok()) {
                        match parsed_data {
                            Transfer::PmidManagerAccount(account_wrapper) => {
                                assert_eq!(account_wrapper.name(),available_nodes[1]);
                            },
                            _ => panic!("Unexpected"),
                        }
                    }
                },
                _ => panic!("Refresh type expected")
            };
            assert!(vault.pmid_manager.retrieve_all_and_reset(&Vec::new()).is_empty());
        }

        {// StructuredDataManager - churn handling
            let name = NameType([3u8; 64]);
            let value = generate_random_vec_u8(1024);
            let keys = crypto::sign::gen_keypair();
            let sdv = StructuredData::new(0, name, 0, value, vec![keys.0], vec![],
                                          Some(&keys.1)).ok().unwrap();

            sd_manager_put(&mut vault, sdv.clone());
            let churn_data = vault.handle_churn(small_close_group.clone());
            // DataManagerStatsTransfer will always be included in the return
            assert_eq!(churn_data.len(), 2);

            match churn_data[0] {
                MethodCall::Refresh{ref type_tag, ref from_group, ref payload} => {
                    assert_eq!(*type_tag, transfer_tags::SD_MANAGER_ACCOUNT_TAG);
                    assert_eq!(*from_group, sdv.name());
                    match ::routing::utils::decode::<StructuredData>(payload) {
                        Ok(sd) => { assert_eq!(sd, sdv); }
                        Err(_) => panic!("Unexpected"),
                    };
                },
                _ => panic!("Refresh type expected")
            };
            assert!(vault.sd_manager.retrieve_all_and_reset().is_empty());
        }

    }

    #[test]
    fn cache_test() {
        let mut vault = Vault::new();
        let value = generate_random_vec_u8(1024);
        let im_data = ImmutableData::new(ImmutableDataType::Normal, value);
        {
            let get_result = vault.handle_cache_get(DataRequest::ImmutableData(im_data.name(),
                im_data.get_type_tag().clone()), im_data.name().clone(), NameType::new([7u8; 64]),
                None);
            assert_eq!(get_result.is_err(), true);
            assert_eq!(get_result.err().unwrap(), ResponseError::Abort);
        }

        let put_result = vault.handle_cache_put(Authority::ManagedNode(NameType::new([6u8; 64])),
                                                NameType::new([7u8; 64]),
                                                Data::ImmutableData(im_data.clone()), None);
        assert_eq!(put_result.is_err(), true);
        match put_result.err().unwrap() {
            ResponseError::Abort => {}
            _ => panic!("Unexpected"),
        }
        {
            let get_result = vault.handle_cache_get(DataRequest::ImmutableData(im_data.name(),
                im_data.get_type_tag().clone()), im_data.name().clone(), NameType::new([7u8; 64]),
                None);
            assert_eq!(get_result.is_err(), false);
            match get_result.ok().unwrap() {
                MethodCall::Reply { data } => {
                    match data {
                        Data::ImmutableData(fetched_im_data) => {
                            assert_eq!(fetched_im_data, im_data);
                        }
                        _ => panic!("Unexpected"),
                    }
                },
                _ => panic!("Unexpected"),
            }
        }
        {
            let get_result = vault.handle_cache_get(DataRequest::ImmutableData(im_data.name(),
                im_data.get_type_tag().clone()), NameType::new([7u8; 64]), NameType::new([7u8; 64]),
                None);
            assert_eq!(get_result.is_err(), true);
            assert_eq!(get_result.err().unwrap(), ResponseError::Abort);
        }
    }
}

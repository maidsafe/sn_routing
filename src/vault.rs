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

#[cfg(not(feature = "use-mock-routing"))]
type Routing = ::routing::routing::Routing;
#[cfg(not(feature = "use-mock-routing"))]
fn get_new_routing(event_sender: ::std::sync::mpsc::Sender<(::routing::event::Event)>) -> Routing {
    ::routing::routing::Routing::new(event_sender)
}

#[cfg(feature = "use-mock-routing")]
type Routing = ::non_networking_test_framework::MockRouting;
#[cfg(feature = "use-mock-routing")]
fn get_new_routing(event_sender: ::std::sync::mpsc::Sender<(::routing::event::Event)>) -> Routing {
    ::non_networking_test_framework::MockRouting::new(event_sender)
}

fn merge<T>(from_group: ::routing::NameType, payloads: Vec<Vec<u8>>) -> Option<T>
    where T: for<'a> ::types::Refreshable + 'static {
    let mut transfer_entries = Vec::<T>::new();
    for it in payloads.iter() {
        let mut decoder = ::cbor::Decoder::from_bytes(&it[..]);
        if let Some(parsed_entry) = decoder.decode().next().and_then(|result| result.ok()) {
            transfer_entries.push(parsed_entry);
        }
    }
    T::merge(from_group, transfer_entries).and_then(|result| {
        let mut decoder = ::cbor::Decoder::from_bytes(&result.serialised_contents()[..]);
        if let Some(parsed_entry) = decoder.decode().next().and_then(|result| result.ok()) {
            let parsed: T = parsed_entry;
            Some(parsed)
        } else {
            None
        }
    })
}

/// Main struct to hold all personas and Routing instance
pub struct Vault {
    data_manager: ::data_manager::DataManager,
    maid_manager: ::maid_manager::MaidManager,
    pmid_manager: ::pmid_manager::PmidManager,
    pmid_node: ::pmid_node::PmidNode,
    sd_manager: ::sd_manager::StructuredDataManager,
    nodes_in_table: Vec<::routing::NameType>,
    #[allow(dead_code)]
    data_cache: ::lru_time_cache::LruCache<::routing::NameType, ::routing::data::Data>,
    request_cache: ::lru_time_cache::LruCache<::routing::NameType,
        Vec<(::routing::Authority, ::routing::data::DataRequest, Option<::routing::SignedToken>)>>,
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
            routing: get_new_routing(sender),
        }
    }

    fn do_run(&mut self) {
        use routing::event::Event;
        while let Ok(event) = self.receiver.recv() {
            info!("Vault received an event from routing : {:?}", event);
            match event {
                Event::Request{ request, our_authority, from_authority, response_token } =>
                    self.on_request(request, our_authority, from_authority, response_token),
                Event::Response{ response, our_authority, from_authority } =>
                    self.on_response(response, our_authority, from_authority),
                Event::Refresh(type_tag, our_authority, accounts) =>
                    self.on_refresh(type_tag, our_authority, accounts),
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
                // TODO - remove 'let _ = '
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
                self.handle_put_response(our_authority, from_authority, response_error,
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
        if close_group.len() > self.nodes_in_table.len() {
            info!("vault added connected node");
        }
        let refresh_calls = self.handle_churn(close_group);
        self.send(::routing::Authority::NaeManager(::routing::NameType::new([0u8; 64])),
                  refresh_calls, None, None, None);
    }

    fn on_bootstrapped(&self) {
        // TODO: what is expected to be done here?
        assert_eq!(0, self.nodes_in_table.len());
    }

    fn on_connected(&self) {
        // TODO: what is expected to be done here?
        assert_eq!(0, self.nodes_in_table.len());
    }

    fn on_disconnected(&mut self) {
        unimplemented!();
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
        let returned_actions = match our_authority.clone() {
            ::routing::Authority::NaeManager(name) => {
                // both DataManager and StructuredDataManager are NaeManagers and Get request to
                // them are both from Node
                match data_request.clone() {
                    // drop the message if we don't have the data
                    ::routing::data::DataRequest::ImmutableData(_, _) => {
                        // Only remember the request from client for Immutable Data
                        // as StructuredData will get replied immediately from SDManager
                        if self.request_cache.contains_key(&name) {
                            debug!("DataManager handle_get inserting original request {:?} from /
                                   {:?} into {:?} ", data_request, from_authority, name);
                            match self.request_cache.get_mut(&name) {
                                Some(ref mut request) => request.push((from_authority.clone(),
                                                                       data_request.clone(),
                                                                       response_token.clone())),
                                None => error!("Failed to insert get request in the cache."),
                            };
                        } else {
                            debug!("DataManager handle_get created original request {:?} from {:?} /
                                   as entry {:?}", data_request, from_authority, name);
                            self.request_cache.add(name, vec![(from_authority.clone(),
                                data_request.clone(), response_token.clone())]);
                        }
                        self.data_manager.handle_get(&name, data_request.clone())
                    }
                    ::routing::data::DataRequest::StructuredData(_, _) =>
                        self.sd_manager.handle_get(name),
                    _ => vec![],
                }
            }
            ::routing::Authority::ManagedNode(_) => {
                match from_authority {
                    // drop the message if we don't have the data
                    ::routing::Authority::NaeManager(name) =>
                        self.pmid_node.handle_get(name),
                    _ => vec![],
                }
            }
            _ => vec![],
        };
        self.send(our_authority, returned_actions, response_token, Some(from_authority),
                  Some(data_request));
    }

    fn handle_put(&mut self,
                  our_authority: ::routing::Authority,
                  from_authority: ::routing::Authority,
                  data: ::routing::data::Data,
                  response_token: Option<::routing::SignedToken>) {
        let returned_actions = match our_authority.clone() {
            ::routing::Authority::ClientManager(from_address) =>
                self.maid_manager.handle_put(&from_address, from_authority, data),
            ::routing::Authority::NaeManager(_) => {
                // both DataManager and StructuredDataManager are NaeManagers
                // client put other data (Immutable, StructuredData) will all goes to MaidManager
                // first, then goes to DataManager (i.e. from_authority is always ClientManager)
                match data {
                    ::routing::data::Data::ImmutableData(data) =>
                        self.data_manager.handle_put(data, &mut (self.nodes_in_table)),
                    ::routing::data::Data::StructuredData(data) =>
                        self.sd_manager.handle_put(data),
                    _ => vec![],
                }
            }
            ::routing::Authority::NodeManager(dest_address) =>
                self.pmid_manager.handle_put(dest_address, data),
            ::routing::Authority::ManagedNode(pmid_node) =>
                self.pmid_node.handle_put(pmid_node, data),
            _ => vec![],
        };
        self.send(our_authority, returned_actions, response_token, None, None);
    }

    // Post is only used to update the content or owners of a StructuredData
    fn handle_post(&mut self,
                   our_authority: ::routing::Authority,
                   _from_authority: ::routing::Authority,
                   data: ::routing::data::Data,
                   response_token: Option<::routing::SignedToken>) {
        let returned_actions = match our_authority {
            ::routing::Authority::NaeManager(_) => {
                match data {
                    ::routing::data::Data::StructuredData(data) =>
                        self.sd_manager.handle_post(data),
                    _ => vec![],
                }
            }
            _ => vec![],
        };
        self.send(our_authority, returned_actions, response_token, None, None);
    }

    fn handle_get_response(&mut self,
                           our_authority: ::routing::Authority,
                           from_authority: ::routing::Authority,
                           response: ::routing::data::Data,
                           response_token: Option<::routing::SignedToken>) {
        match our_authority.clone() {
            // Lookup in the request_cache and reply to the clients
            ::routing::Authority::NaeManager(name) => {
                if self.request_cache.contains_key(&name) {
                    match self.request_cache.remove(&name) {
                        Some(requests) => {
                            for request in requests {
                                self.send(our_authority.clone(), vec![::types::MethodCall::Reply {
                                    data: response.clone() }], request.2, Some(request.0),
                                    Some(request.1));
                            }
                        }
                        None => debug!("Failed to find any requests for get response from {:?}
                            with our authority {:?}: {:?}.", from_authority,  our_authority,
                            response),
                    };
                }
            }
            _ => {}
        }
        let returned_actions = match (from_authority, response.clone()) {
            // GetResponse used by DataManager to replicate data to new PN
            (::routing::Authority::ManagedNode(pmid_node),
                ::routing::data::Data::ImmutableData(_)) =>
                self.data_manager.handle_get_response(pmid_node, response),
            _ => vec![],
        };
        self.send(our_authority, returned_actions, response_token, None, None);
    }

    // DataManager doesn't need to carry out replication in case of sacrificial copy
    #[allow(dead_code)]
    fn handle_put_response(&mut self,
                           our_authority: ::routing::Authority,
                           from_authority: ::routing::Authority,
                           response: ::routing::error::ResponseError,
                           response_token: Option<::routing::SignedToken>) {
        let fowarding_calls = match from_authority {
            ::routing::Authority::ManagedNode(pmid_node) =>
                self.pmid_manager.handle_put_response(&pmid_node, response),
            ::routing::Authority::NodeManager(pmid_node) =>
                self.data_manager.handle_put_response(response, &pmid_node),
            ::routing::Authority::NaeManager(_) => {
                match our_authority {
                    ::routing::Authority::NodeManager(pmid_node) =>
                        self.pmid_manager.handle_get_failure_notification(&pmid_node, response),
                    _ => vec![],
                }
            }
            _ => vec![],
        };
        self.send(our_authority, fowarding_calls, response_token, None, None);
    }

    // https://maidsafe.atlassian.net/browse/MAID-1111 post_response is not required on vault
    #[allow(dead_code)]
    fn handle_post_response(&mut self,
                            _: ::routing::Authority, // from_authority
                            _: ::routing::error::ResponseError,
                            _: Option<::routing::SignedToken>)
                            -> Vec<::types::MethodCall> {
        vec![]
    }

    fn handle_churn(&mut self,
                    mut close_group: Vec<::routing::NameType>)
                    -> Vec<::types::MethodCall> {
        let mm = self.maid_manager.retrieve_all_and_reset();
        let vh = self.sd_manager.retrieve_all_and_reset();
        let pm = self.pmid_manager.retrieve_all_and_reset(&close_group);
        let dm = self.data_manager.retrieve_all_and_reset(&mut close_group);
        self.nodes_in_table = close_group;

        mm.into_iter().chain(vh.into_iter().chain(pm.into_iter().chain(dm.into_iter()))).collect()
    }

    fn handle_refresh(&mut self,
                      type_tag: u64,
                      our_authority: ::routing::Authority,
                      payloads: Vec<Vec<u8>>) {
        // TODO: The assumption of the incoming payloads is that it is a vector of serialised
        //       account entries from the close group nodes of `from_group`
        match type_tag {
            ::maid_manager::ACCOUNT_TAG => {
                if let ::routing::Authority::ClientManager(from_group) = our_authority {
                    if let Some(merged) = merge::<::maid_manager::Account>(from_group, payloads) {
                        self.maid_manager.handle_account_transfer(merged)
                    }
                } else {
                    warn!("Mismatch of refresh tag {:?} & authority {:?}", type_tag, our_authority);
                }
            }
            ::data_manager::ACCOUNT_TAG => {
                if let ::routing::Authority::NaeManager(from_group) = our_authority {
                    if let Some(merged) = merge::<::data_manager::Account>(from_group, payloads) {
                        self.data_manager.handle_account_transfer(merged);
                    }
                } else {
                    warn!("Mismatch of refresh tag {:?} & authority {:?}", type_tag, our_authority);
                }
            }
            ::data_manager::STATS_TAG => {
                if let ::routing::Authority::NaeManager(from_group) = our_authority {
                    if let Some(merged) = merge::<::data_manager::Stats>(from_group, payloads) {
                        self.data_manager.handle_stats_transfer(merged);
                    }
                } else {
                    warn!("Mismatch of refresh tag {:?} & authority {:?}", type_tag, our_authority);
                }
            }
            ::pmid_manager::ACCOUNT_TAG => {
                if let ::pmid_manager::Authority(from_group) = our_authority {
                    if let Some(merged) = merge::<::pmid_manager::Account>(from_group, payloads) {
                        self.pmid_manager.handle_account_transfer(merged);
                    }
                } else {
                    warn!("Mismatch of refresh tag {:?} & authority {:?}", type_tag, our_authority);
                }
            }
            ::sd_manager::ACCOUNT_TAG => {
                if let ::routing::Authority::NaeManager(_from_group) = our_authority {
                    for payload in payloads {
                        // TODO - pass in from_group to allow validation of payloads (should all be
                        // for same DB entry)
                        self.sd_manager.handle_account_transfer(payload);
                    }
                } else {
                    warn!("Mismatch of refresh tag {:?} & authority {:?}", type_tag, our_authority);
                }
            }
            _ => {}
        }
    }

    // The cache handling in vault is roleless, i.e. vault will do whatever routing tells it to do
    #[allow(dead_code)]
    fn handle_cache_get(&mut self,
                        _: ::routing::data::DataRequest, // data_request
                        data_location: ::routing::NameType,
                        _: ::routing::NameType,
                        _: Option<::routing::SignedToken>)
                        -> Result<::types::MethodCall, ::routing::error::ResponseError> {
        match self.data_cache.get(&data_location) {
            Some(data) => Ok(::types::MethodCall::Reply { data: data.clone() }),
            // TODO: NoData may still be preferred here
            None => Err(::routing::error::ResponseError::Abort),
        }
    }

    #[allow(dead_code)]
    fn handle_cache_put(&mut self,
                        _: ::routing::Authority, // from_authority
                        _: ::routing::NameType, // from_address
                        data: ::routing::data::Data,
                        _: Option<::routing::SignedToken>)
                        -> Result<::types::MethodCall, ::routing::error::ResponseError> {
        self.data_cache.add(data.name(), data);
        Err(::routing::error::ResponseError::Abort)
    }

    fn send(&mut self,
            our_authority: ::routing::Authority,
            actions: Vec<::types::MethodCall>,
            response_token: Option<::routing::SignedToken>,
            optional_reply_to: Option<::routing::Authority>,
            optional_original_data_request: Option<::routing::data::DataRequest>) {
        for action in actions {
            match action {
                ::types::MethodCall::Get { location, data_request } => {
                    self.routing.get_request(our_authority.clone(), location, data_request);
                }
                ::types::MethodCall::Put { location, content } => {
                    self.routing.put_request(our_authority.clone(), location, content);
                }
                ::types::MethodCall::Reply { data } => {
                    match (&optional_reply_to, &optional_original_data_request) {
                        (&Some(ref reply_to), &Some(ref original_data_request)) => {
                            debug!("as {:?} sending data {:?} to {:?} in responding to the /
                                   ori_data_request {:?}",
                                   our_authority, data, reply_to, original_data_request);
                            self.routing.get_response(our_authority.clone(), reply_to.clone(), data,
                                original_data_request.clone(), response_token.clone());
                        }
                        _ => {}
                    };
                }
                ::types::MethodCall::Refresh { type_tag, our_authority, payload } => {
                    info!("refreshing account type {:?} of group {:?} to network", type_tag,
                          our_authority);
                    self.routing.refresh_request(type_tag, our_authority, payload);
                }
                ::types::MethodCall::FailedPut { location, data } => {
                    debug!("as {:?} failed in putting data {:?}, responding to {:?}",
                           our_authority, data, location);
                    self.routing.put_response(our_authority.clone(), location,
                        ::routing::error::ResponseError::FailedRequestForData(data),
                        response_token.clone());
                }
                ::types::MethodCall::ClearSacrificial { location, name, size } => {
                    debug!("as {:?} sacrifize data {:?} freeing space {:?}, notifying {:?}",
                           our_authority, name, size, location);
                    self.routing.put_response(our_authority.clone(), location,
                        ::routing::error::ResponseError::HadToClearSacrificial(name, size),
                        response_token.clone());
                }
                ::types::MethodCall::LowBalance { location, data, balance } => {
                    debug!("as {:?} failed in putting data {:?}, responding to {:?}",
                           our_authority, data, location);
                    self.routing.put_response(our_authority.clone(), location,
                                              ::routing::error::ResponseError::LowBalance(data, balance),
                                              response_token.clone());
                },
                _ => {}
            }
        }
    }
}

pub type ResponseNotifier =
    ::std::sync::Arc<(::std::sync::Mutex<Result<Vec<::types::MethodCall>,
                      ::routing::error::ResponseError>>, ::std::sync::Condvar)>;

#[cfg(test)]
mod test {
    use cbor;
    use sodiumoxide::crypto;

    use super::*;

    #[cfg(feature = "use-mock-routing")]
    fn mock_env_setup() -> (super::Routing, ::std::sync::mpsc::Receiver<(::routing::data::Data)>) {
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
        routing.client_put(client_name, sign_keys.0,
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
        let sd = ::routing::structured_data::StructuredData::new(0, name, 0,
            value.clone(), vec![sign_keys.0], vec![], Some(&sign_keys.1)).ok().unwrap();

        let client_name = ::utils::random_name();
        routing.client_put(client_name, sign_keys.0,
            ::routing::data::Data::StructuredData(sd.clone()));
        ::std::thread::sleep_ms(2000);

        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let sd_new = ::routing::structured_data::StructuredData::new(0, name, 1,
            value.clone(), vec![keys.0], vec![sign_keys.0], Some(&sign_keys.1)).ok().unwrap();
        routing.client_post(client_name, sign_keys.0,
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
    fn network_env_setup
                         ()
                          -> (::routing::routing_client::RoutingClient,
 ::std::sync::mpsc::Receiver<(::routing::data::Data)>, ::routing::NameType) {
        use routing::event::Event;
        match ::env_logger::init() {
            Ok(()) => {}
            Err(e) => println!("Error initialising logger; continuing without: {:?}", e),
        }
        let run_vault = |mut vault: Vault| {
                            let _ = ::std::thread::spawn(move || {
                                                                  vault.do_run();
                                                              });
                        };
        for i in 0..8 {
            println!("starting node {:?}", i);
            let _ = run_vault(Vault::new());
            ::std::thread::sleep_ms(1000 + i * 1000);
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
                            info!("as {:?} received response: {:?} targeting {:?} having error /
                                  {:?}", our_authority, response, location, interface_error),
                        Event::Bootstrapped => info!("client routing Bootstrapped"),
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
        ::std::thread::sleep_ms(1000);
        (client_routing, client_receiver, client_name)
    }

    #[cfg(not(feature = "use-mock-routing"))]
    #[test]
    fn network_put_get_test() {
        let (mut client_routing, client_receiver, client_name) = network_env_setup();

        let value = ::routing::types::generate_random_vec_u8(1024);
        let im_data = ::routing::immutable_data::ImmutableData::new(
                          ::routing::immutable_data::ImmutableDataType::Normal, value);
        client_routing.put_request(::routing::Authority::ClientManager(client_name),
                                   ::routing::data::Data::ImmutableData(im_data.clone()));
        ::std::thread::sleep_ms(2000);

        client_routing.get_request(::routing::Authority::NaeManager(im_data.name()),
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
        let (mut client_routing, client_receiver, client_name) = network_env_setup();

        let name = ::utils::random_name();
        let value = ::routing::types::generate_random_vec_u8(1024);
        let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let sd = ::routing::structured_data::StructuredData::new(0, name, 0,
            value.clone(), vec![sign_keys.0], vec![], Some(&sign_keys.1)).ok().unwrap();
        client_routing.put_request(::routing::Authority::ClientManager(client_name),
                                   ::routing::data::Data::StructuredData(sd.clone()));
        ::std::thread::sleep_ms(2000);

        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let sd_new = ::routing::structured_data::StructuredData::new(0, name, 1,
            value.clone(), vec![keys.0], vec![sign_keys.0], Some(&sign_keys.1)).ok().unwrap();
        client_routing.post_request(::routing::Authority::NaeManager(sd.name()),
                                    ::routing::data::Data::StructuredData(sd_new.clone()));
        ::std::thread::sleep_ms(2000);

        client_routing.get_request(::routing::Authority::NaeManager(sd.name()),
            ::routing::data::DataRequest::StructuredData(sd.name(), 0));
        while let Ok(data) = client_receiver.recv() {
            assert_eq!(data, ::routing::data::Data::StructuredData(sd_new.clone()));
            break;
        }
    }

    #[cfg(not(feature = "use-mock-routing"))]
    #[test]
    fn network_churn_immutable_data_test() {
        let (mut client_routing, client_receiver, client_name) = network_env_setup();

        let value = ::routing::types::generate_random_vec_u8(1024);
        let im_data = ::routing::immutable_data::ImmutableData::new(
                          ::routing::immutable_data::ImmutableDataType::Normal, value);
        client_routing.put_request(::routing::Authority::ClientManager(client_name),
                                   ::routing::data::Data::ImmutableData(im_data.clone()));
        ::std::thread::sleep_ms(2000);

        let _ = ::std::thread::spawn(move || {
                                              ::vault::Vault::run();
                                          });
        ::std::thread::sleep_ms(5000);

        client_routing.get_request(::routing::Authority::NaeManager(im_data.name()),
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
        let (mut client_routing, client_receiver, client_name) = network_env_setup();

        let name = ::utils::random_name();
        let value = ::routing::types::generate_random_vec_u8(1024);
        let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let sd = ::routing::structured_data::StructuredData::new(0, name, 0,
            value.clone(), vec![sign_keys.0], vec![], Some(&sign_keys.1)).ok().unwrap();
        client_routing.put_request(::routing::Authority::ClientManager(client_name),
                                   ::routing::data::Data::StructuredData(sd.clone()));
        ::std::thread::sleep_ms(2000);

        let _ = ::std::thread::spawn(move || {
                                              ::vault::Vault::run();
                                          });
        ::std::thread::sleep_ms(5000);

        client_routing.get_request(::routing::Authority::NaeManager(sd.name()),
            ::routing::data::DataRequest::StructuredData(sd.name(), 0));
        while let Ok(data) = client_receiver.recv() {
            assert_eq!(data, ::routing::data::Data::StructuredData(sd.clone()));
            break;
        }
    }

    fn maid_manager_put(vault: &mut Vault,
                        client: ::routing::NameType,
                        im_data: ::routing::immutable_data::ImmutableData) {
        let keys = crypto::sign::gen_keypair();
        let _put_result = vault.handle_put(::routing::Authority::ClientManager(client),
                                           ::routing::Authority::Client(client, keys.0),
                                           ::routing::data::Data::ImmutableData(im_data.clone()),
                                           None);
    }

    fn data_manager_put(vault: &mut Vault, im_data: ::routing::immutable_data::ImmutableData) {
        let _put_result = vault.handle_put(
            ::routing::Authority::NaeManager(im_data.name()),
            ::routing::Authority::ClientManager(::routing::NameType::new([1u8; 64])),
            ::routing::data::Data::ImmutableData(im_data), None);
    }

    fn add_nodes_to_table(vault: &mut Vault, nodes: &Vec<::routing::NameType>) {
        for node in nodes {
            vault.nodes_in_table.push(node.clone());
        }
    }

    fn pmid_manager_put(vault: &mut Vault,
                        pmid_node: ::routing::NameType,
                        im_data: ::routing::immutable_data::ImmutableData) {
        let _put_result = vault.handle_put(
            ::routing::Authority::NodeManager(pmid_node),
            ::routing::Authority::NaeManager(im_data.name()),
            ::routing::data::Data::ImmutableData(im_data), None);
    }

    fn sd_manager_put(vault: &mut Vault, sdv: ::routing::structured_data::StructuredData) {
        let _put_result = vault.handle_put(
            ::routing::Authority::NaeManager(sdv.name()),
            ::routing::Authority::ManagedNode(::routing::NameType::new([7u8; 64])),
            ::routing::data::Data::StructuredData(sdv.clone()), None);
    }

    #[test]
    fn churn_test() {
        let mut vault = Vault::new();

        let mut available_nodes = Vec::with_capacity(30);
        for _ in 0..30 {
            available_nodes.push(::utils::random_name());
        }

        let value = ::routing::types::generate_random_vec_u8(1024);
        let im_data = ::routing::immutable_data::ImmutableData::new(
                          ::routing::immutable_data::ImmutableDataType::Normal, value);

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
                ::types::MethodCall::Refresh{ref type_tag, ref our_authority, ref payload} => {
                    assert_eq!(*type_tag, ::maid_manager::ACCOUNT_TAG);
                    assert_eq!(*our_authority.get_location(), available_nodes[0]);
                    let mut d = cbor::Decoder::from_bytes(&payload[..]);
                    let result_to_option = |r: ::cbor::CborResult<::maid_manager::Account>| r.ok();
                    if let Some(mm_account) = d.decode().next().and_then(result_to_option) {
                        assert_eq!(*mm_account.name(), available_nodes[0]);
                        assert_eq!(mm_account.value().data_stored(), 1024);
                    } else {
                        panic!("Failed to parse account during refresh.");
                    }
                    let mut payloads = vec![];
                    for _ in 0..(::routing::types::GROUP_SIZE - 1) {
                        payloads.push(payload.clone());
                    }
                    vault.handle_refresh(*type_tag, our_authority.clone(), payloads);
                }
                _ => panic!("Refresh type expected"),
            };
            add_nodes_to_table(&mut vault, &Vec::<::routing::NameType>::new());
            let re_churn_data = vault.handle_churn(small_close_group.clone());
            assert_eq!(churn_data[0], re_churn_data[0]);
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
                ::types::MethodCall::Refresh{ref type_tag, ref our_authority, ref payload} => {
                    assert_eq!(*type_tag, ::data_manager::ACCOUNT_TAG);
                    assert_eq!(*our_authority.get_location(), im_data.name());
                    let mut d = cbor::Decoder::from_bytes(&payload[..]);
                    let result_to_option = |r: ::cbor::CborResult<::data_manager::Account>| r.ok();
                    if let Some(dm_account) = d.decode().next().and_then(result_to_option) {
                        assert_eq!(*dm_account.name(), im_data.name());
                    } else {
                        panic!("Failed to parse account during refresh.");
                    }
                    let mut payloads = vec![];
                    for _ in 0..(::routing::types::GROUP_SIZE - 1) {
                        payloads.push(payload.clone());
                    }
                    vault.handle_refresh(*type_tag, our_authority.clone(), payloads);
                }
                ::types::MethodCall::Get { .. } => (),
                _ => panic!("Refresh type expected"),
            };

            match churn_data[1] {
                ::types::MethodCall::Refresh{ref type_tag, ref our_authority, ref payload} => {
                    assert_eq!(*type_tag, ::data_manager::STATS_TAG);
                    assert_eq!(*our_authority.get_location(), close_group[0]);
                    let mut d = cbor::Decoder::from_bytes(&payload[..]);
                    let result_to_option = |r: ::cbor::CborResult<::data_manager::Stats>| r.ok();
                    if let Some(dm_stats) = d.decode().next().and_then(result_to_option) {
                        assert_eq!(dm_stats.resource_index(), 1);
                    } else {
                        panic!("Failed to parse account during refresh.");
                    }
                    let mut payloads = vec![];
                    for _ in 0..(::routing::types::GROUP_SIZE - 1) {
                        payloads.push(payload.clone());
                    }
                    vault.handle_refresh(*type_tag, our_authority.clone(), payloads);
                }
                ::types::MethodCall::Get { .. } => (),
                _ => panic!("Refresh type expected"),
            };
            add_nodes_to_table(&mut vault, &available_nodes);
            let re_churn_data = vault.handle_churn(close_group.clone());
            assert_eq!(churn_data[0], re_churn_data[0]);
            assert_eq!(churn_data[1], re_churn_data[1]);
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
                ::types::MethodCall::Refresh{ref type_tag, ref our_authority, ref payload} => {
                    assert_eq!(*type_tag, ::pmid_manager::ACCOUNT_TAG);
                    assert_eq!(*our_authority.get_location(), available_nodes[1]);
                    let mut d = cbor::Decoder::from_bytes(&payload[..]);
                    let result_to_option = |r: ::cbor::CborResult<::pmid_manager::Account>| r.ok();
                    if let Some(pm_account) = d.decode().next().and_then(result_to_option) {
                        assert_eq!(*pm_account.name(), available_nodes[1]);
                    } else {
                        panic!("Failed to parse account during refresh.");
                    }
                    let mut payloads = vec![];
                    for _ in 0..(::routing::types::GROUP_SIZE - 1) {
                        payloads.push(payload.clone());
                    }
                    vault.handle_refresh(*type_tag, our_authority.clone(), payloads);
                }
                _ => panic!("Refresh type expected"),
            };
            add_nodes_to_table(&mut vault, &Vec::<::routing::NameType>::new());
            let re_churn_data = vault.handle_churn(small_close_group.clone());
            assert_eq!(churn_data[0], re_churn_data[0]);
            assert!(vault.pmid_manager.retrieve_all_and_reset(&Vec::new()).is_empty());
        }

        {// StructuredDataManager - churn handling
            let name = ::routing::NameType([3u8; 64]);
            let value = ::routing::types::generate_random_vec_u8(1024);
            let keys = crypto::sign::gen_keypair();
            let sdv = ::routing::structured_data::StructuredData::new(0, name, 0, value,
                                                                      vec![keys.0], vec![],
                                                                      Some(&keys.1)).ok().unwrap();

            sd_manager_put(&mut vault, sdv.clone());
            let churn_data = vault.handle_churn(small_close_group.clone());
            // DataManagerStatsTransfer will always be included in the return
            assert_eq!(churn_data.len(), 2);

            match churn_data[0] {
                ::types::MethodCall::Refresh{ref type_tag, ref our_authority, ref payload} => {
                    assert_eq!(*type_tag, ::sd_manager::ACCOUNT_TAG);
                    assert_eq!(*our_authority.get_location(), sdv.name());
                    match ::routing::utils::decode::<
                              ::routing::structured_data::StructuredData>(payload) {
                        Ok(sd) => {
                            assert_eq!(sd, sdv);
                        }
                        Err(_) => panic!("Unexpected"),
                    };
                    let mut payloads = vec![];
                    for _ in 0..(::routing::types::GROUP_SIZE - 1) {
                        payloads.push(payload.clone());
                    }
                    vault.handle_refresh(*type_tag, our_authority.clone(), payloads);
                }
                _ => panic!("Refresh type expected"),
            };
            add_nodes_to_table(&mut vault, &Vec::<::routing::NameType>::new());
            let re_churn_data = vault.handle_churn(small_close_group.clone());
            assert_eq!(churn_data[0], re_churn_data[0]);
            assert!(vault.sd_manager.retrieve_all_and_reset().is_empty());
        }

    }

    #[test]
    fn cache_test() {
        let mut vault = Vault::new();
        let value = ::routing::types::generate_random_vec_u8(1024);
        let im_data = ::routing::immutable_data::ImmutableData::new(
                          ::routing::immutable_data::ImmutableDataType::Normal, value);
        {
            let get_result = vault.handle_cache_get(
                ::routing::data::DataRequest::ImmutableData(im_data.name(),
                im_data.get_type_tag().clone()), im_data.name().clone(),
                ::routing::NameType::new([7u8; 64]), None);
            assert_eq!(get_result.is_err(), true);
            assert_eq!(get_result.err().unwrap(), ::routing::error::ResponseError::Abort);
        }

        let put_result = vault.handle_cache_put(
                ::routing::Authority::ManagedNode(::routing::NameType::new([6u8; 64])),
                ::routing::NameType::new([7u8; 64]),
                ::routing::data::Data::ImmutableData(im_data.clone()), None);
        assert_eq!(put_result.is_err(), true);
        match put_result.err().unwrap() {
            ::routing::error::ResponseError::Abort => {}
            _ => panic!("Unexpected"),
        }
        {
            let get_result = vault.handle_cache_get(
                ::routing::data::DataRequest::ImmutableData(im_data.name(),
                                                            im_data.get_type_tag().clone()),
                im_data.name().clone(), ::routing::NameType::new([7u8; 64]), None);
            assert_eq!(get_result.is_err(), false);
            match get_result.ok().unwrap() {
                ::types::MethodCall::Reply { data } => {
                    match data {
                        ::routing::data::Data::ImmutableData(fetched_im_data) => {
                            assert_eq!(fetched_im_data, im_data);
                        }
                        _ => panic!("Unexpected"),
                    }
                }
                _ => panic!("Unexpected"),
            }
        }
        {
            let get_result = vault.handle_cache_get(
                ::routing::data::DataRequest::ImmutableData(im_data.name(),
                                                            im_data.get_type_tag().clone()),
                ::routing::NameType::new([7u8; 64]), ::routing::NameType::new([7u8; 64]), None);
            assert_eq!(get_result.is_err(), true);
            assert_eq!(get_result.err().unwrap(), ::routing::error::ResponseError::Abort);
        }
    }
}

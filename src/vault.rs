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

use data_manager::DataManager;
use error::Error;
use maid_manager::MaidManager;
use pmid_manager::PmidManager;
use pmid_node::PmidNode;
use routing::{Authority, Data, DataRequest, Event, RequestContent, RequestMessage, ResponseContent, ResponseMessage};
use sd_manager::StructuredDataManager;
use std::sync::{Arc, atomic, mpsc};
use std::sync::atomic::AtomicBool;
use time::{Duration, SteadyTime};
use xor_name::XorName;

#[cfg(not(all(test, feature = "use-mock-routing")))]
pub type Routing = ::routing::Routing;

#[cfg(all(test, feature = "use-mock-routing"))]
pub type Routing = ::mock_routing::MockRouting;

/// Main struct to hold all personas and Routing instance
pub struct Vault {
    routing: Routing,
    data_manager: DataManager,
    maid_manager: MaidManager,
    pmid_manager: PmidManager,
    pmid_node: PmidNode,
    sd_manager: StructuredDataManager,
    receiver: mpsc::Receiver<Event>,
    churn_timestamp: SteadyTime,
    id: XorName,
    app_event_sender: Option<mpsc::Sender<Event>>,
    should_stop: Option<Arc<AtomicBool>>,
}

impl Vault {
    pub fn run() {
        // TODO - Keep retrying to construct new Vault until returns Ok() rather than using unwrap?
        unwrap_result!(Vault::new(None, None)).do_run();
    }

    fn new(app_event_sender: Option<mpsc::Sender<Event>>,
           should_stop: Option<Arc<AtomicBool>>)
           -> Result<Vault, Error> {
        ::sodiumoxide::init();
        let (sender, receiver) = mpsc::channel();
        let routing = try!(Routing::new(sender));
        Ok(Vault {
            routing: routing,
            data_manager: DataManager::new(),
            maid_manager: MaidManager::new(),
            pmid_manager: PmidManager::new(),
            pmid_node: PmidNode::new(),
            sd_manager: StructuredDataManager::new(),
            churn_timestamp: SteadyTime::now(),
            receiver: receiver,
            id: XorName::new([0u8; 64]),
            app_event_sender: app_event_sender,
            should_stop: should_stop,
        })
    }

    fn do_run(&mut self) {
        loop {
            match self.receiver.try_recv() {
                Err(_) => {}
                Ok(event) => {
                    let _ = self.app_event_sender
                                .clone()
                                .and_then(|sender| Some(sender.send(event.clone())));
                    info!("Vault {} received an event from routing: {:?}",
                          self.id,
                          event);
                    match event {
                        Event::Request(request) => self.on_request(request),
                        Event::Response(response) => self.on_response(response),
                        Event::Refresh(type_tag, our_authority, accounts) => {
                            self.on_refresh(type_tag, our_authority, accounts)
                        }
                        Event::Churn(close_group /* , churn_node */) => {
                            self.on_churn(close_group /* , churn_node */)
                        }
                        Event::DoRefresh(type_tag, our_authority, churn_node) => {
                            self.on_do_refresh(type_tag, our_authority, churn_node)
                        }
                        Event::Connected => self.on_connected(),
                        Event::Disconnected => self.on_disconnected(),
                        Event::Terminated => break,
                    };
                }
            }

            if let &Some(ref arc) = &self.should_stop {
                let ref should_stop = &*arc;
                if should_stop.load(atomic::Ordering::Relaxed) {
                    // Just stop Routing and wait for the `Event::Terminated` message to break out
                    // of this event loop.
                    self.routing.stop();
                }
            }
            ::std::thread::sleep(::std::time::Duration::from_millis(1));
        }
    }

    fn on_request(&mut self, request: RequestMessage) {
        match (&request.src, &request.dst, &request.content) {
            // ================== Get ==================
            (&Authority::Client{ .. },
             &Authority::NaeManager(_),
             &RequestContent::Get(DataRequest::ImmutableData(_, _))) => {
                self.data_manager.handle_get(&self.routing, &request)
            }
            (&Authority::Client{ .. },
             &Authority::NaeManager(_),
             &RequestContent::Get(DataRequest::StructuredData(_, _))) => {
                self.sd_manager.handle_get(&self.routing, &request)
            }
            (&Authority::NaeManager(_),
             &Authority::ManagedNode(_),
             &RequestContent::Get(DataRequest::ImmutableData(_, _))) => {
                self.pmid_node.handle_get(&self.routing, &request)
            }
            // ================== Put ==================
            (&Authority::Client{ .. },
             &Authority::ClientManager(_),
             &RequestContent::Put(Data::ImmutableData(_))) |
            (&Authority::Client{ .. },
             &Authority::ClientManager(_),
             &RequestContent::Put(Data::StructuredData(_))) => self.maid_manager.handle_put(&self.routing, &request),
            (&Authority::ClientManager(_),
             &Authority::NaeManager(_),
             &RequestContent::Put(Data::ImmutableData(ref data))) => self.data_manager.handle_put(&self.routing, data),
            (&Authority::ClientManager(_),
             &Authority::NaeManager(_),
             &RequestContent::Put(Data::StructuredData(ref data))) => self.sd_manager.handle_put(data),
            (&Authority::NaeManager(_),
             &Authority::NodeManager(pmid_node_name),
             &RequestContent::Put(Data::ImmutableData(ref data))) => {
                self.pmid_manager.handle_put(&self.routing, data, pmid_node_name)
            }
            (&Authority::NodeManager(_),
             &Authority::ManagedNode(_),
             &RequestContent::Put(Data::ImmutableData(_))) => self.pmid_node.handle_put(&self.routing, &request),
            // ================== Post ==================
            (&Authority::Client{ .. },
             &Authority::NaeManager(_),
             &RequestContent::Post(Data::StructuredData(_))) => self.sd_manager.handle_post(&request),
            // ================== Delete ==================
            (_, _, &RequestContent::Delete(_)) => unimplemented!(),
            _ => error!("Unexpected request {:?}", request),
        }
    }

    fn on_response(&mut self, response: ResponseMessage) {
        match (&response.src, &response.dst, &response.content) {
            // ================== GetSuccess ==================
            (&Authority::ManagedNode(_),
             &Authority::NaeManager(_),
             &ResponseContent::GetSuccess(Data::ImmutableData(_))) => self.data_manager.handle_get_success(&response),
            // ================== GetFailure ==================
            (&Authority::ManagedNode(pmid_node_name),
             &Authority::NaeManager(_),
             &ResponseContent::GetFailure{ ref request, ref external_error_indicator }) => {
                self.data_manager
                    .handle_get_failure(pmid_node_name, request, external_error_indicator)
            }
            // ================== PutFailure ==================
            // FIXME
            // data_manager::Authority(_) => self.data_manager.handle_put_failure(response),
            // pmid_manager::Authority(_) => self.pmid_manager.handle_put_failure(response),
            _ => error!("Unexpected response {:?}", response),
        }
    }

    fn on_refresh(&mut self, type_tag: u64, our_authority: Authority, accounts: Vec<Vec<u8>>) {
        self.handle_refresh(type_tag, our_authority, accounts);
    }

    fn on_churn(&mut self, close_group: Vec<XorName> /* , churn_node: XorName */) {
        self.id = close_group[0].clone();
        let churn_up = close_group.len() > self.data_manager.nodes_in_table_len();
        let time_now = SteadyTime::now();
        // During the process of joining network, the vault shall not refresh its just received info
        if !(churn_up && (self.churn_timestamp + Duration::seconds(5) > time_now)) {
            self.handle_churn(close_group /* , churn_node */);
        } else {
            self.data_manager.set_node_table(close_group);
        }
        if churn_up {
            info!("Vault added connected node");
            self.churn_timestamp = time_now;
        }
    }

    fn on_do_refresh(&mut self, type_tag: u64, our_authority: Authority, churn_node: XorName) {
        let _ = self.maid_manager
                    .do_refresh(&self.routing, &type_tag, &our_authority, &churn_node)
                    .or_else(|| {
                        self.data_manager
                            .do_refresh(&self.routing, &type_tag, &our_authority, &churn_node)
                    })
                    .or_else(|| {
                        self.sd_manager
                            .do_refresh(&self.routing, &type_tag, &our_authority, &churn_node)
                    })
                    .or_else(|| {
                        self.pmid_manager
                            .do_refresh(&self.routing, &type_tag, &our_authority, &churn_node)
                    });
    }

    fn on_connected(&self) {
        // TODO: what is expected to be done here?
        debug!("vault connected having {:?} connections",
               self.data_manager.nodes_in_table_len());
        // assert_eq!(kademlia_routing_table::GROUP_SIZE, self.data_manager.nodes_in_table_len());
    }

    fn on_disconnected(&mut self) {
        self.routing.stop();
        if let &Some(ref arc) = &self.should_stop {
            let ref should_stop = &*arc;
            if should_stop.load(atomic::Ordering::Relaxed) {
                return;
            }
        }
        // self.churn_timestamp = SteadyTime::now();
        // let (sender, receiver) = mpsc::channel();
        // // TODO - Keep retrying to construct new Routing until returns Ok() ?
        // let routing = unwrap_result!(Routing::new(sender));
        // self.receiver = receiver;

        // self.maid_manager.reset(&self.routing);
        // self.data_manager.reset(&self.routing);
        // self.pmid_manager.reset(&self.routing);
        // // TODO: https://github.com/maidsafe/safe_vault/issues/269
        // //   pmid_node and sd_manager shall discard the data when routing address changed
        // self.pmid_node.reset(&self.routing);
        // self.sd_manager.reset(&self.routing);
    }

    fn handle_churn(&mut self,
                    close_group: Vec<XorName> /* ,
                                               * churn_node: XorName */) {
        let churn_node = XorName::new([0; 64]);  // FIXME
        self.maid_manager.handle_churn(&self.routing, &churn_node);
        self.sd_manager.handle_churn(&self.routing, &churn_node);
        self.pmid_manager.handle_churn(&self.routing, &close_group, &churn_node);
        self.data_manager.handle_churn(&self.routing, close_group, &churn_node);
    }

    fn handle_refresh(&mut self, type_tag: u64, our_authority: ::routing::Authority, payloads: Vec<Vec<u8>>) {
        // The incoming payloads is a vector of serialised account entries,
        // collected from the close group nodes regarding `from_group`
        debug!("refresh tag {:?} & authority {:?}", type_tag, our_authority);
        let _ = self.maid_manager
                    .handle_refresh(&type_tag, &our_authority, &payloads)
                    .or_else(|| self.data_manager.handle_refresh(&type_tag, &our_authority, &payloads))
                    .or_else(|| self.pmid_manager.handle_refresh(&type_tag, &our_authority, &payloads))
                    .or_else(|| self.sd_manager.handle_refresh(&type_tag, &our_authority, &payloads));
    }
}



#[cfg(all(test, not(feature = "use-mock-routing")))]
mod test {
    use super::*;
    use kademlia_routing_table::GROUP_SIZE;
    use maidsafe_utilities::log;
    use rand::random;
    use routing::{Authority, Data, DataRequest, Event, FullId, ImmutableData, ImmutableDataType, RequestContent,
                  RequestMessage, ResponseContent, ResponseMessage, RoutingClient, StructuredData};
    use std::sync::mpsc;
    use time::{Duration, SteadyTime};
    use xor_name::XorName;

    struct VaultComms {
        notifier: ::std::sync::mpsc::Receiver<(Event)>,
        killer: ::std::sync::Arc<::std::sync::atomic::AtomicBool>,
        join_handle: Option<::std::thread::JoinHandle<()>>,
    }

    impl VaultComms {
        fn new(index: usize) -> VaultComms {
            println!("Starting vault {}", index);
            let (sender, receiver) = ::std::sync::mpsc::channel();
            let killer = ::std::sync::Arc::new(::std::sync::atomic::AtomicBool::new(false));
            let mut vault = unwrap_result!(Vault::new(Some(sender), Some(killer.clone())));
            let join_handle = Some(unwrap_result!(::std::thread::Builder::new()
                                                      .name(format!("Vault {} worker", index))
                                                      .spawn(move || vault.do_run())));
            let vault_comms = VaultComms {
                notifier: receiver,
                killer: killer,
                join_handle: join_handle,
            };
            let mut temp_comms = vec![vault_comms];
            let _ = unwrap_result!(wait_for_hits(&temp_comms,
                                                 10,
                                                 index,
                                                 ::time::Duration::seconds(10 * (index + 1) as i64)));
            temp_comms.remove(0)
        }

        fn stop(&mut self) {
            self.killer.store(true, ::std::sync::atomic::Ordering::Relaxed);
            if let Some(join_handle) = self.join_handle.take() {
                unwrap_result!(join_handle.join());
            }
        }
    }

    struct Client {
        routing: RoutingClient,
        receiver: ::std::sync::mpsc::Receiver<Data>,
        name: XorName,
    }

    impl Client {
        fn new() -> Client {
            let client_receiving = |routing_receiver: mpsc::Receiver<Event>,
                                    network_event_sender: mpsc::Sender<Event>,
                                    client_sender: mpsc::Sender<Data>| {
                let _ = ::std::thread::spawn(move || {
                    while let Ok(event) = routing_receiver.recv() {
                        match event {
                            Event::Request(request) => panic!("Received {:?}", request),
                            Event::Response(response) => {
                                info!("Received {:?}", response);
                                match response {
                                    ResponseMessage{ content: ResponseContent::GetSuccess(data), .. } => {
                                        let _ = client_sender.send(data);
                                    }
                                    _ => panic!("not expected!"),
                                }
                            }
                            Event::Refresh(_, _, _) => info!("client received a refresh"),
                            Event::Churn(_) => info!("client received a churn"),
                            Event::DoRefresh(_, _, _) => info!("client received a do_refresh"),
                            Event::Connected => unwrap_result!(network_event_sender.send(Event::Connected)),
                            Event::Disconnected => info!("client disconnected"),
                            Event::Terminated => {
                                info!("client routing listening terminated");
                                break;
                            }
                        };
                    }
                });
            };
            let (routing_sender, routing_receiver) = mpsc::channel();
            let (network_event_sender, network_event_receiver) = mpsc::channel();
            let (data_sender, data_receiver) = mpsc::channel();
            let _ = client_receiving(routing_receiver, network_event_sender, data_sender);

            let id = FullId::new();
            let client_name = id.public_id().name().clone();
            let client_routing = unwrap_result!(RoutingClient::new(routing_sender, Some(id)));
            let starting_time = SteadyTime::now();
            let time_limit = Duration::minutes(1);
            loop {
                match network_event_receiver.try_recv() {
                    Ok(Event::Connected) => break,
                    Err(_) => (),
                    _ => panic!("Failed to connect"),
                }
                ::std::thread::sleep(::std::time::Duration::from_millis(100));
                if starting_time + time_limit < ::time::SteadyTime::now() {
                    panic!("new client can't get bootstrapped in expected duration");
                }
            }
            Client {
                routing: client_routing,
                receiver: data_receiver,
                name: client_name,
            }
        }
    }

    struct Environment {
        vaults_comms: Vec<VaultComms>,
        client: Client,
    }

    impl Environment {
        fn new() -> Environment {
            log::init(true);
            Self::show_warning();

            remove_files();
            create_empty_files();

            let mut vaults_comms = Vec::new();
            for i in 0..Self::network_size() {
                vaults_comms.push(VaultComms::new(i));
            }

            Environment {
                vaults_comms: vaults_comms,
                client: Client::new(),
            }
        }

        #[cfg(windows)]
        fn show_warning() {
            println!("\nIf this test hangs, stopping the process with ctrl+C will not suffice.");
            println!("You should kill the process via the Task Manager, or by running:");
            println!("  taskkill /f /fi \"imagename eq safe_vault-*\" /im *\n");
        }

        #[cfg(not(windows))]
        fn show_warning() {
            println!("");
        }

        fn network_size() -> usize {
            GROUP_SIZE as usize
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
                let duration = ::std::time::Duration::from_millis(1);
                ::std::thread::sleep(duration);
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
            // self.client.routing.stop();
            self.stop_all_vaults();
            remove_files();
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
                     time_limit: ::time::Duration)
                     -> Result<Vec<usize>, String> {
        let starting_time = ::time::SteadyTime::now();
        let mut hit_vaults = vec![];
        while hit_vaults.len() < expected_hits {
            for i in 0..vaults_comms.len() {
                match vaults_comms[i].notifier.try_recv() {
                    Err(_) => {}
                    Ok(Event::Request(RequestMessage{ src, dst, content })) => {
                        debug!("as {:?} received request: {:?} from {:?}",
                               dst,
                               content,
                               src);
                        match (expected_tag, dst, content) {
                            (1, Authority::NaeManager(_), _) => hit_vaults.push(i),
                            (3, Authority::ManagedNode(_), RequestContent::Put(_)) => hit_vaults.push(i),
                            _ => {}
                        }
                    }
                    Ok(Event::Churn(_ /* , _ */)) => {
                        if expected_tag == 10 {
                            hit_vaults.push(i);
                        }
                    }
                    Ok(Event::Refresh(type_tag, _, _)) => {
                        match (expected_tag, type_tag) {
                            (20, 2) => hit_vaults.push(i),
                            (21, 5) => hit_vaults.push(i),
                            _ => {}
                        }
                    }
                    Ok(Event::Response(ResponseMessage{ src, dst, content })) => {
                        debug!("as {:?} received response: {:?} from {:?}",
                               dst,
                               content,
                               src);
                        match (expected_tag, content, dst, src) {
                            (30,
                             ResponseContent::PutFailure{ .. },
                             Authority::NodeManager(_),
                             Authority::NaeManager(_)) => hit_vaults.push(i),
                            _ => {}
                        }
                    }
                    Ok(_) => {}
                }
            }
            let duration = ::std::time::Duration::from_millis(1);
            ::std::thread::sleep(duration);
            if starting_time + time_limit < ::time::SteadyTime::now() {
                // As this function is only to be used in testing code, and a partially
                // established environment / testing result having a high chance indicates a failure
                // in code.  So here use panic to terminate the testing directly.
                return Err(format!("Failed to get {} hits within the expected duration.  Only hit vaults {:?}",
                                   expected_hits,
                                   hit_vaults));
            }
        }
        Ok(hit_vaults)
    }

    fn wait_for_client_get(client_receiver: &::std::sync::mpsc::Receiver<Data>,
                           expected_data: Data,
                           time_limit: ::time::Duration) {
        let starting_time = ::time::SteadyTime::now();
        loop {
            match client_receiver.try_recv() {
                Err(_) => {}
                Ok(data) => {
                    assert_eq!(data, expected_data);
                    break;
                }
            }
            let duration = ::std::time::Duration::from_millis(1);
            ::std::thread::sleep(duration);
            if starting_time + time_limit < ::time::SteadyTime::now() {
                panic!("wait_for_client_get can't resolve within the expected duration");
            }
        }
    }

    fn get_file_name(extension: &'static str) -> ::std::path::PathBuf {
        let mut name = ::crust::exe_file_stem().unwrap_or(::std::path::Path::new("unknown").to_path_buf());
        name.set_extension(extension);
        name
    }

    fn remove_file(extension: &'static str) {
        let _ = ::crust::current_bin_dir().and_then(|mut cur_bin_dir| {
            cur_bin_dir.push(get_file_name(extension));
            ::std::fs::remove_file(cur_bin_dir).map_err(|error| ::crust::error::Error::IoError(error))
        });
    }

    fn remove_files() {
        remove_file("bootstrap.cache");
        remove_file("crust.config");
    }

    fn create_empty_file(extension: &'static str, default_content: &'static str) {
        use std::io::Write;
        let _ = ::crust::current_bin_dir().and_then(|mut cur_bin_dir| {
            cur_bin_dir.push(get_file_name(extension));
            let mut file = try!(::std::fs::File::create(cur_bin_dir));
            let _ = try!(write!(&mut file, "{}", default_content));
            file.sync_all().map_err(|error| ::crust::error::Error::IoError(error))
        });
    }

    fn create_empty_files() {
        create_empty_file("bootstrap.cache", "[]");
        create_empty_file("crust.config",
                          "{\n
                    \"tcp_listening_port\": 5483,\n
                    \
                           \"utp_listening_port\": null,\n
                    \"override_default_bootstrap\": \
                           false,\n
                    \"hard_coded_contacts\": [],\n
                    \
                           \"beacon_port\": 5484\n
                }");
    }

    #[test]
    fn network_test() {
        let mut env = Environment::new();

        // ======================= Put/Get test ====================================================
        println!("\n======================= Put/Get test ====================================================");
        let value = ::routing::types::generate_random_vec_u8(1024);
        let im_data = ImmutableData::new(ImmutableDataType::Normal, value);
        println!("Putting data");
        unwrap_result!(env.client.routing.send_put_request(Authority::ClientManager(env.client.name),
                                            Data::ImmutableData(im_data.clone())));
        let _ = unwrap_result!(wait_for_hits(&env.vaults_comms,
                                             3,
                                             ::data_manager::REPLICANTS,
                                             ::time::Duration::minutes(3)));
        println!("Getting data");
        unwrap_result!(env.client.routing.send_get_request(Authority::NaeManager(im_data.name()),
                                            DataRequest::ImmutableData(im_data.name(), ImmutableDataType::Normal)));
        wait_for_client_get(&env.client.receiver,
                            Data::ImmutableData(im_data),
                            Duration::minutes(1));
        env.consume_vaults_events(Duration::seconds(10));

        // ======================= Post test =======================================================
        println!("\n======================= Post test =======================================================");
        let name = random();
        let value = ::routing::types::generate_random_vec_u8(1024);
        let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let sd = unwrap_result!(StructuredData::new(0,
                                                    name,
                                                    0,
                                                    value.clone(),
                                                    vec![sign_keys.0],
                                                    vec![],
                                                    Some(&sign_keys.1)));
        println!("Putting data");
        unwrap_result!(env.client.routing.send_put_request(Authority::ClientManager(env.client.name),
                                            Data::StructuredData(sd.clone())));
        let _ = unwrap_result!(wait_for_hits(&env.vaults_comms,
                                             1,
                                             GROUP_SIZE as usize,
                                             Duration::minutes(3)));

        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let sd_new = unwrap_result!(StructuredData::new(0,
                                                        name,
                                                        1,
                                                        value.clone(),
                                                        vec![keys.0],
                                                        vec![sign_keys.0],
                                                        Some(&sign_keys.1)));
        println!("Posting data");
        unwrap_result!(env.client.routing.send_post_request(Authority::NaeManager(sd.name()),
                                             Data::StructuredData(sd_new.clone())));
        let _ = unwrap_result!(wait_for_hits(&env.vaults_comms,
                                             1,
                                             GROUP_SIZE as usize,
                                             Duration::minutes(3)));

        println!("Getting data");
        unwrap_result!(env.client.routing.send_get_request(Authority::NaeManager(sd.name()),
                                            DataRequest::StructuredData(name, 0)));
        wait_for_client_get(&env.client.receiver,
                            Data::StructuredData(sd_new),
                            Duration::minutes(1));

        // ======================= Churn (node down) ImmutableData test ============================
        println!("\n======================= Churn (node down) ImmutableData test ============================");
        let value = ::routing::types::generate_random_vec_u8(1024);
        let im_data = ImmutableData::new(ImmutableDataType::Normal, value);
        println!("Putting data");
        unwrap_result!(env.client.routing.send_put_request(Authority::ClientManager(env.client.name),
                                            Data::ImmutableData(im_data.clone())));
        let pmid_nodes = unwrap_result!(wait_for_hits(&env.vaults_comms,
                                                      3,
                                                      ::data_manager::REPLICANTS,
                                                      Duration::minutes(3)));

        println!("Stopping vault {}", pmid_nodes[0]);
        env.vaults_comms[pmid_nodes[0]].stop();
        // Waiting for the notifications happen
        let _ = unwrap_result!(wait_for_hits(&env.vaults_comms,
                                             30,
                                             GROUP_SIZE as usize / 2 + 1,
                                             Duration::minutes(3)));
        env.consume_vaults_events(::time::Duration::seconds(10));

        // ======================= Churn (node up) ImmutableData test ==============================
        println!("\n======================= Churn (node up) ImmutableData test ==============================");
        let value = ::routing::types::generate_random_vec_u8(1024);
        let im_data = ImmutableData::new(ImmutableDataType::Normal, value);
        println!("Putting data");
        unwrap_result!(env.client.routing.send_put_request(Authority::ClientManager(env.client.name),
                                            Data::ImmutableData(im_data.clone())));
        let _ = unwrap_result!(wait_for_hits(&env.vaults_comms,
                                             3,
                                             ::data_manager::REPLICANTS,
                                             Duration::minutes(3)));

        println!("Starting new vault");
        let mut index = Environment::network_size() - 1;
        env.vaults_comms.push(VaultComms::new(index));

        println!("Getting data");
        unwrap_result!(env.client.routing.send_get_request(Authority::NaeManager(im_data.name()),
                                            DataRequest::ImmutableData(im_data.name(), ImmutableDataType::Normal)));
        wait_for_client_get(&env.client.receiver,
                            Data::ImmutableData(im_data),
                            Duration::minutes(1));
        env.consume_vaults_events(Duration::seconds(10));

        // ======================= Churn (two nodes down) ImmutableData test =======================
        println!("\n======================= Churn (two nodes down) ImmutableData test =======================");
        let value = ::routing::types::generate_random_vec_u8(1024);
        let im_data = ImmutableData::new(ImmutableDataType::Normal, value);
        println!("Putting data");
        unwrap_result!(env.client.routing.send_put_request(Authority::ClientManager(env.client.name),
                                            Data::ImmutableData(im_data.clone())));
        let pmid_nodes = unwrap_result!(wait_for_hits(&env.vaults_comms,
                                                      3,
                                                      ::data_manager::REPLICANTS,
                                                      Duration::minutes(3)));

        println!("Stopping vault {}", pmid_nodes[0]);
        env.vaults_comms[pmid_nodes[0]].stop();
        println!("Stopping vault {}", pmid_nodes[1]);
        env.vaults_comms[pmid_nodes[1]].stop();
        // Waiting for the replications happen
        let _ = unwrap_result!(wait_for_hits(&env.vaults_comms, 3, 1, ::time::Duration::minutes(3)));

        // ======================= Churn (node up) StructuredData test =============================
        println!("\n======================= Churn (node up) StructuredData test =============================");
        let name = random();
        let value = ::routing::types::generate_random_vec_u8(1024);
        let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let sd = unwrap_result!(StructuredData::new(0,
                                                    name,
                                                    0,
                                                    value.clone(),
                                                    vec![sign_keys.0],
                                                    vec![],
                                                    Some(&sign_keys.1)));
        println!("Putting data");
        unwrap_result!(env.client.routing.send_put_request(Authority::ClientManager(env.client.name),
                                            Data::StructuredData(sd.clone())));
        let _ = unwrap_result!(wait_for_hits(&env.vaults_comms,
                                             1,
                                             GROUP_SIZE as usize - 2,
                                             Duration::minutes(3)));

        println!("Starting new vault");
        index = Environment::network_size() - 2;
        env.vaults_comms.push(VaultComms::new(index));

        println!("Getting data");
        unwrap_result!(env.client.routing.send_get_request(Authority::NaeManager(sd.name()),
                                            DataRequest::StructuredData(name, 0)));
        wait_for_client_get(&env.client.receiver,
                            Data::StructuredData(sd),
                            Duration::minutes(1));
    }
}


// #[cfg(all(test, feature = "use-mock-routing"))]
// mod mock_routing_test {
// use super::*;
//
// struct VaultComms {
// receiver: ::std::sync::mpsc::Receiver<(::routing::data::Data)>,
// killer: ::std::sync::Arc<::std::sync::atomic::AtomicBool>,
// join_handle: Option<::std::thread::JoinHandle<()>>,
// }
//
// impl Drop for VaultComms {
// fn drop(&mut self) {
// self.killer.store(true, ::std::sync::atomic::Ordering::Relaxed);
// if let Some(join_handle) = self.join_handle.take() {
// unwrap_result!(join_handle.join());
// }
// }
// }
//
//
// fn mock_env_setup() -> (Routing, VaultComms) {
// ::utils::initialise_logger();
// let killer = ::std::sync::Arc::new(::std::sync::atomic::AtomicBool::new(false));
// let mut vault = Vault::new(None, Some(killer.clone()));
// let mut routing = vault.pmid_node.routing();
// let receiver = routing.get_client_receiver();
// let join_handle = Some(unwrap_result!(::std::thread::Builder::new().spawn(move || vault.do_run())));
//
// let mut available_nodes = Vec::with_capacity(30);
// for _ in 0..30 {
// available_nodes.push(random());
// }
// routing.churn_event(available_nodes, random());
// (routing,
// VaultComms {
// receiver: receiver,
// killer: killer,
// join_handle: join_handle,
// })
// }
//
// #[test]
// fn put_get_flow() {
// let (mut routing, vault_comms) = mock_env_setup();
//
// let client_name = random();
// let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
// let value = ::routing::types::generate_random_vec_u8(1024);
// let im_data =
// ImmutableData::new(ImmutableDataType::Normal, value);
// routing.client_put(client_name,
// sign_keys.0,
// ::routing::data::Data::ImmutableData(im_data.clone()));
// let duration = ::std::time::Duration::from_millis(2000);
// ::std::thread::sleep(duration);
//
// let data_request =
// ::routing::data::DataRequest::ImmutableData(im_data.name(),
// ImmutableDataType::Normal);
// routing.client_get(client_name, sign_keys.0, data_request);
// for it in vault_comms.receiver.iter() {
// assert_eq!(it, ::routing::data::Data::ImmutableData(im_data));
// break;
// }
// }
//
// #[test]
// fn post_flow() {
// let (mut routing, vault_comms) = mock_env_setup();
//
// let name = random();
// let value = ::routing::types::generate_random_vec_u8(1024);
// let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
// let sd = unwrap_result!(::routing::structured_data::StructuredData::new(0,
// name,
// 0,
// value.clone(),
// vec![sign_keys.0],
// vec![],
// Some(&sign_keys.1)));
//
// let client_name = random();
// routing.client_put(client_name,
// sign_keys.0,
// ::routing::data::Data::StructuredData(sd.clone()));
// let duration = ::std::time::Duration::from_millis(2000);
// ::std::thread::sleep(duration);
//
// let keys = ::sodiumoxide::crypto::sign::gen_keypair();
// let sd_new = unwrap_result!(::routing::structured_data::StructuredData::new(0,
// name,
// 1,
// value.clone(),
// vec![keys.0],
// vec![sign_keys.0],
// Some(&sign_keys.1)));
// routing.client_post(client_name,
// sign_keys.0,
// ::routing::data::Data::StructuredData(sd_new.clone()));
// let duration = ::std::time::Duration::from_millis(2000);
// ::std::thread::sleep(duration);
//
// let data_request = ::routing::data::DataRequest::StructuredData(name, 0);
// routing.client_get(client_name, sign_keys.0, data_request);
// for it in vault_comms.receiver.iter() {
// assert_eq!(it, ::routing::data::Data::StructuredData(sd_new));
// break;
// }
// }
// }
//

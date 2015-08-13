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

#![deny(missing_docs)]

use std::convert::From;

use time::Duration;
use cbor::Decoder;
use rustc_serialize::{Decodable, Encodable};

use lru_time_cache::LruCache;

use routing_types::*;

use data_manager::{DataManager, DataManagerSendable, DataManagerStatsSendable};
use maid_manager::{MaidManager, MaidManagerAccountWrapper, MaidManagerAccount};
use pmid_manager::{PmidManager, PmidManagerAccountWrapper, PmidManagerAccount};
use pmid_node::PmidNode;
use sd_manager::StructuredDataManager;
use transfer_parser::transfer_tags::{MAID_MANAGER_ACCOUNT_TAG, DATA_MANAGER_ACCOUNT_TAG,
    PMID_MANAGER_ACCOUNT_TAG, SD_MANAGER_ACCOUNT_TAG, DATA_MANAGER_STATS_TAG};

/// Main struct to hold all personas
pub struct VaultFacade {
    data_manager : DataManager,
    maid_manager : MaidManager,
    pmid_manager : PmidManager,
    pmid_node : PmidNode,
    sd_manager : StructuredDataManager,
    nodes_in_table : Vec<NameType>,
    data_cache: LruCache<NameType, Data>
}

fn merge_refreshable<T>(empty_entry: T, payloads: Vec<Vec<u8>>) ->
        T where T: for<'a> Sendable + Encodable + Decodable + 'static {
    let mut transfer_entries = Vec::<Box<Sendable>>::new();
    for it in payloads.iter() {
        let mut decoder = Decoder::from_bytes(&it[..]);
        if let Some(parsed_entry) = decoder.decode().next().and_then(|result| result.ok()) {
            let parsed: T = parsed_entry;
            transfer_entries.push(Box::new(parsed));
        }
    }
    match empty_entry.merge(transfer_entries) {
        Some(result) => {
            let mut decoder = Decoder::from_bytes(&result.serialised_contents()[..]);
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

impl Interface for VaultFacade {
    fn handle_get(&mut self,
                  data_request: DataRequest,
                  our_authority: Authority,
                  from_authority: Authority,
                  _: SourceAddress)->Result<Vec<MethodCall>, InterfaceError> { // from_address
        match our_authority {
            Authority::NaeManager(name) => {
                // both DataManager and StructuredDataManager are NaeManagers and Get request to them are both from Node
                match data_request {
                    DataRequest::ImmutableData(_) => self.data_manager.handle_get(&name),
                    DataRequest::StructuredData(_) => self.sd_manager.handle_get(name)
                }
            }
            Authority::ManagedNode => {
                match from_authority {
                    Authority::NaeManager(name) => self.pmid_node.handle_get(name),
                    _ => Err(From::from(ResponseError::InvalidRequest)),
                }
            }
            _ => { return Err(From::from(ResponseError::InvalidRequest)); }
        }
    }

    fn handle_put(&mut self, our_authority: Authority, _from_authority: Authority,
                  _: SourceAddress, _: DestinationAddress,
                  data: Data ) -> Result<Vec<MethodCall>, InterfaceError> {
        match our_authority {
            Authority::ClientManager(from_address) => {
                return self.maid_manager.handle_put(&from_address, data);
            }
            Authority::NaeManager(_) => {
                // both DataManager and StructuredDataManager are NaeManagers
                // client put other data (Immutable, StructuredData) will all goes to MaidManager first,
                // then goes to DataManager (i.e. from_authority is always ClientManager)
                match data {
                    Data::ImmutableData(data) => self.data_manager.handle_put(data, &mut (self.nodes_in_table)),
                    Data::StructuredData(data) => self.sd_manager.handle_put(data),
                    _ => return Err(From::from(ResponseError::InvalidRequest)),
                }
            }
            Authority::NodeManager(dest_address) => {
                return self.pmid_manager.handle_put(dest_address, data);
            }
            Authority::ManagedNode => {
                return self.pmid_node.handle_put(data);
            }
            _ => {
                return Err(From::from(ResponseError::InvalidRequest));
            }
        }
    }

    // Post is only used to update the content or owners of a StructuredData
    fn handle_post(&mut self,
                   our_authority: Authority,
                   _: Authority, // from_authority
                   _: SourceAddress, // from_address
                   _: DestinationAddress, // dest_address
                   data: Data) -> Result<Vec<MethodCall>, InterfaceError> {
        match our_authority {
            Authority::NaeManager(_) => {
                match data {
                    Data::StructuredData(data) => { return self.sd_manager.handle_post(data); }
                    _ => {}
                }
            }
            _ => {}
        }
        Err(From::from(ResponseError::InvalidRequest))
    }

    fn handle_get_response(&mut self,
                           _: NameType, // from_address
                           response: Data) -> Vec<MethodCall> {
        // GetResponse only used by DataManager to replicate data to new PN
        match response.clone() {
            Data::ImmutableData(_) => self.data_manager.handle_get_response(response),
            _ => vec![]
        }
    }

    // Put response will holding the copy of failed to store data, which will be :
    //     1, the original immutable data if it failed to squeeze in
    //     2, the sacrificial copy if it has been removed to empty the space
    // DataManager doesn't need to carry out replication in case of sacrificial copy
    fn handle_put_response(&mut self, from_authority: Authority, from_address: SourceAddress,
                           response: ResponseError) -> Vec<MethodCall> {
        match from_authority {
            Authority::ManagedNode => {
                match from_address {
                    SourceAddress::Direct(pmid_node) => self.pmid_manager.handle_put_response(&pmid_node, response),
                    _ => vec![]
                }
            }
            Authority::NodeManager(_) => {
                // TODO: this from_address shall be the original pmid_node that failing or removing the copy
                //       which requires work in routing to replace the address properly
                match from_address {
                    SourceAddress::Direct(pmid_node) => self.data_manager.handle_put_response(response, &pmid_node),
                    _ => vec![]
                }
            }
            _ => vec![]
        }
    }

    // https://maidsafe.atlassian.net/browse/MAID-1111 post_response is not required on vault
    fn handle_post_response(&mut self, 
                            _: Authority, // from_authority
                            _: SourceAddress, // from_address
                            _: ResponseError) -> Vec<MethodCall> { // response
        vec![]
    }

    fn handle_churn(&mut self, mut close_group: Vec<NameType>) -> Vec<MethodCall> {
        let mm = self.maid_manager.retrieve_all_and_reset();
        let vh = self.sd_manager.retrieve_all_and_reset();
        let pm = self.pmid_manager.retrieve_all_and_reset(&close_group);
        let dm = self.data_manager.retrieve_all_and_reset(&mut close_group);
        self.nodes_in_table = close_group;

        mm.into_iter().chain(vh.into_iter().chain(pm.into_iter().chain(dm.into_iter()))).collect()
    }

    fn handle_refresh(&mut self,
                      type_tag: u64,
                      from_group: NameType,
                      payloads: Vec<Vec<u8>>) {
        // TODO: The assumption of the incoming payloads is that it is a vector of serialised
        //       account entries from the close group nodes of `from_group`
        match type_tag {
            MAID_MANAGER_ACCOUNT_TAG => {
                let merged_account = merge_refreshable(
                    MaidManagerAccountWrapper::new(from_group, MaidManagerAccount::new()),
                    payloads);
                self.maid_manager.handle_account_transfer(merged_account);
            },
            DATA_MANAGER_ACCOUNT_TAG => {
                let merged_account = merge_refreshable(DataManagerSendable::new(from_group, vec![]),
                                                       payloads);
                self.data_manager.handle_account_transfer(merged_account);
            },
            PMID_MANAGER_ACCOUNT_TAG => {
                let merged_account = merge_refreshable(
                    PmidManagerAccountWrapper::new(from_group, PmidManagerAccount::new()),
                    payloads);
                self.pmid_manager.handle_account_transfer(merged_account);
            },
            SD_MANAGER_ACCOUNT_TAG => {
                for payload in payloads {
                    self.sd_manager.handle_account_transfer(payload);
                }
            },
            DATA_MANAGER_STATS_TAG => {
                let merged_stats = merge_refreshable(DataManagerStatsSendable::new(from_group, 0),
                                                     payloads);
                self.data_manager.handle_stats_transfer(merged_stats);
            },
            _ => {},
        }
    }

    // The cache handling in vault is roleless, i.e. vault will do whatever routing tells it to do
    fn handle_cache_get(&mut self,
                        _: DataRequest, // data_request
                        data_location: NameType,
                        _: NameType) -> Result<MethodCall, InterfaceError> { // from_address
        match self.data_cache.get(&data_location) {
            Some(data) => Ok(MethodCall::Reply { data: data.clone() }),
            None => Err(From::from(ResponseError::NoData))
        }
    }

    fn handle_cache_put(&mut self,
                        _: Authority, // from_authority
                        _: NameType, // from_address
                        data: Data) -> Result<MethodCall, InterfaceError> {
        self.data_cache.add(data.name(), data);
        Err(InterfaceError::Abort)
    }
}

pub type ResponseNotifier = ::std::sync::Arc<(::std::sync::Mutex<Result<Vec<MethodCall>, InterfaceError>>,
                                              ::std::sync::Condvar)>;

impl VaultFacade {
    pub fn new() -> VaultFacade {
        VaultFacade {
            data_manager: DataManager::new(), maid_manager: MaidManager::new(),
            pmid_manager: PmidManager::new(), pmid_node: PmidNode::new(),
            sd_manager: StructuredDataManager::new(), nodes_in_table: Vec::new(),
            data_cache: LruCache::with_expiry_duration_and_capacity(Duration::minutes(10), 100),
        }
    }

    pub fn mutex_new(notifier: ResponseNotifier,
                     receiver: ::std::sync::mpsc::Receiver<RoutingMessage>)
      -> (::std::sync::Arc<::std::sync::Mutex<VaultFacade>>, ::std::thread::JoinHandle<()>) {
        let vault_facade = ::std::sync::Arc::new(::std::sync::Mutex::new(VaultFacade {
            data_manager: DataManager::new(), maid_manager: MaidManager::new(),
            pmid_manager: PmidManager::new(), pmid_node: PmidNode::new(),
            sd_manager: StructuredDataManager::new(), nodes_in_table: Vec::new(),
            data_cache: LruCache::with_expiry_duration_and_capacity(Duration::minutes(10), 100),
        }));

        let vault_facade_cloned = vault_facade.clone();
        let receiver_joiner = ::std::thread::Builder::new().name("VaultReceiverThread".to_string()).spawn(move || {
            for it in receiver.iter() {
                let (routing_acting, actions) = match it {
                    RoutingMessage::ShutDown => (true, Ok(vec![MethodCall::ShutDown])),
                    RoutingMessage::HandleGet(data_request, our_authority,
                                              from_authority, from_address) =>
                        (true, vault_facade_cloned.lock().unwrap().handle_get(data_request, our_authority,
                                                                              from_authority, from_address)),
                    RoutingMessage::HandlePut(our_authority, from_authority,
                                              from_address, dest_address, data) =>
                        (true, vault_facade_cloned.lock().unwrap().handle_put(our_authority, from_authority,
                                                                              from_address, dest_address, data)),
                    // _ => (false, Ok(vec![MethodCall::Terminate])),
                };
                // pub enum RoutingMessage {
                //     HandleGet { data_request   : DataRequest,
                //                 our_authority  : Authority,
                //                 from_authority : Authority,
                //                 from_address   : SourceAddress },
                //     HandlePut { our_authority  : Authority,
                //                 from_authority : Authority,
                //                 from_address   : SourceAddress,
                //                 dest_address   : DestinationAddress,
                //                 data           : Data },
                //     HandlePost { our_authority : Authority,
                //                  from_authority: Authority,
                //                  from_address  : SourceAddress,
                //                  dest_address  : DestinationAddress,
                //                  data          : Data },
                //     HandleRefresh { type_tag   : u64,
                //                     from_group : NameType,
                //                     payloads   : Vec<Vec<u8>> },
                //     HandleChurn { close_group  : Vec<NameType> },
                //     HandleGetResponse { from_address    : NameType,
                //                            response     : Data},
                //     HandlePutResponse { from_authority  : Authority,
                //                         from_address    : SourceAddress,
                //                         response        : ResponseError },
                //     HandlePostResponse { from_authority : Authority,
                //                          from_address   : SourceAddress,
                //                          response       : ResponseError },
                //     HandleCacheGet { data_request       : DataRequest,
                //                      data_location      : NameType,
                //                      from_address       : NameType },
                //     HandleCachePut { from_authority     : Authority,
                //                      from_address       : NameType,
                //                      data               : Data }

                if routing_acting {
                    let &(ref lock, ref condition_var) = &*notifier;
                    // let mut routing_action = eval_result!(lock.lock());
                    let mut routing_action = lock.lock().unwrap();
                    *routing_action = actions.clone();
                    condition_var.notify_all();
                    if actions.unwrap() == vec![MethodCall::ShutDown] {
                        break;
                    }
                }
            }
        }).unwrap();

        (vault_facade, receiver_joiner)
    }

}

#[cfg(test)]
 mod test {
    use std::convert::From;

    use cbor;
    use sodiumoxide::crypto;

    use super::*;
    use data_manager;
    use transfer_parser::{Transfer, transfer_tags};
    use utils::decode;
    use routing_types::*;

    fn maid_manager_put(vault: &mut VaultFacade, from: SourceAddress,
                        dest: DestinationAddress, im_data: ImmutableData) {
        let client = match from.clone() {
            SourceAddress::Direct(address) => address,
            _ => panic!("Unexpected"),
        };
        let keys = crypto::sign::gen_keypair();
        let put_result = vault.handle_put(Authority::ClientManager(client),
                                          Authority::Client(keys.0),
                                          from, dest, Data::ImmutableData(im_data.clone()));
        assert_eq!(put_result.is_err(), false);
        let calls = put_result.ok().unwrap();
        assert_eq!(calls.len(), 1);
        match calls[0] {
            MethodCall::Forward { destination } => {
                assert_eq!(destination, im_data.name());
            }
            _ => panic!("Unexpected"),
        }
    }

    fn data_manager_put(vault: &mut VaultFacade, from: SourceAddress,
                        dest: DestinationAddress, im_data: ImmutableData) {
        let put_result = vault.handle_put(Authority::NaeManager(im_data.name()),
                                          Authority::ClientManager(NameType::new([1u8; 64])),
                                          from, dest, Data::ImmutableData(im_data));
        assert_eq!(put_result.is_err(), false);
        let calls = put_result.ok().unwrap();
        assert_eq!(calls.len(), data_manager::PARALLELISM);
    }

    fn add_nodes_to_table(vault: &mut VaultFacade, nodes: &Vec<NameType>) {
        for node in nodes {
            vault.nodes_in_table.push(node.clone());
        }
    }

    fn pmid_manager_put(vault: &mut VaultFacade, from: SourceAddress,
                        dest: DestinationAddress, im_data: ImmutableData) {
        let dest_address = match dest.clone() {
            DestinationAddress::Direct(address) => address,
            _ => panic!("Unexpected"),
        };
        let put_result = vault.handle_put(Authority::NodeManager(dest_address),
                                          Authority::NaeManager(im_data.name()),
                                          from, dest.clone(), Data::ImmutableData(im_data));
        assert_eq!(put_result.is_err(), false);
        let calls = put_result.ok().unwrap();
        assert_eq!(calls.len(), 1);
        match calls[0] {
            MethodCall::Forward { destination } => {
                assert_eq!(destination, dest_address);                
            }
            _ => panic!("Unexpected"),
        }
    }

    fn sd_manager_put(vault: &mut VaultFacade, from: SourceAddress,
                      dest: DestinationAddress, sdv: StructuredData) {
        let put_result = vault.handle_put(Authority::NaeManager(sdv.name()),
                                          Authority::ManagedNode,
                                          from.clone(), dest, Data::StructuredData(sdv.clone()));
        assert_eq!(put_result.is_ok(), true);
        let mut calls = put_result.ok().unwrap();
        assert_eq!(calls.len(), 1);
        match calls.remove(0) {
            MethodCall::Reply { data } => {
                match data {
                    Data::StructuredData(sd) => {
                        assert_eq!(sd, sdv);
                    }
                    _ => panic!("Unexpected"),
                }
            }
            _ => panic!("Unexpected"),
        }
    }

    fn sd_manager_post(vault: &mut VaultFacade, from: SourceAddress,
                       dest: DestinationAddress, sdv: StructuredData) {
        let post_result = vault.handle_post(Authority::NaeManager(sdv.name()),
                                            Authority::ManagedNode,
                                            from.clone(), dest, Data::StructuredData(sdv.clone()));
        assert_eq!(post_result.is_ok(), true);
    }

    fn sd_manager_get(vault: &mut VaultFacade, from: SourceAddress,
                      name: NameType, sd_expected: StructuredData) {
        let get_result = vault.handle_get(DataRequest::StructuredData(0),
                                          Authority::NaeManager(name),
                                          Authority::ManagedNode,
                                          from.clone());
        assert_eq!(get_result.is_ok(), true);
        let mut calls = get_result.ok().unwrap();
        assert_eq!(calls.len(), 1);
        match calls.remove(0) {
            MethodCall::Reply { data } => {
                match data {
                    Data::StructuredData(sd) => {
                        assert_eq!(sd, sd_expected);
                    }
                    _ => panic!("Unexpected"),
                }
            }
            _ => panic!("Unexpected"),
        }
    }

    #[test]
    fn put_get_flow() {
        let mut vault = VaultFacade::new();
        let value = generate_random_vec_u8(1024);
        let im_data = ImmutableData::new(ImmutableDataType::Normal, value);
        { // MaidManager, shall allowing the put and SendOn to DataManagers around name
            let from = SourceAddress::Direct(NameType::new([1u8; 64]));
            // TODO : in this stage, dest can be populated as anything ?
            let dest = DestinationAddress::Direct(NameType::new([9u8; 64]));
            maid_manager_put(&mut vault, from, dest, im_data.clone());
        }
        vault.nodes_in_table = vec![NameType::new([1u8; 64]), NameType::new([2u8; 64]), NameType::new([3u8; 64]), NameType::new([4u8; 64]),
                               NameType::new([5u8; 64]), NameType::new([6u8; 64]), NameType::new([7u8; 64]), NameType::new([8u8; 64])];
        { // DataManager, shall SendOn to pmid_nodes
            let from = SourceAddress::Direct(NameType::new([1u8; 64]));
            // TODO : in this stage, dest can be populated as anything ?
            let dest = DestinationAddress::Direct(NameType::new([9u8; 64]));
            data_manager_put(&mut vault, from.clone(), dest, im_data.clone());
            let keys = crypto::sign::gen_keypair();
            let get_result = vault.handle_get(DataRequest::ImmutableData(im_data.get_type_tag().clone()),
                                              Authority::NaeManager(im_data.name().clone()),
                                              Authority::Client(keys.0), from);
            assert_eq!(get_result.is_err(), false);
            let get_calls = get_result.ok().unwrap();
            assert_eq!(get_calls.len(), data_manager::PARALLELISM);
        }
        { // PmidManager, shall put to pmid_nodes
            let from = SourceAddress::Direct(NameType::new([3u8; 64]));
            let dest = DestinationAddress::Direct(NameType::new([7u8; 64]));
            pmid_manager_put(&mut vault, from, dest, im_data.clone());
        }
        { // PmidNode stores/retrieves data
            let from = SourceAddress::Direct(NameType::new([7u8; 64]));
            let dest = DestinationAddress::Direct(NameType::new([6u8; 64]));
            let put_result = vault.handle_put(Authority::ManagedNode, Authority::NodeManager(NameType::new([6u8; 64])),
                                              from.clone(), dest, Data::ImmutableData(im_data.clone()));
            assert_eq!(put_result.is_ok(), true);
            let mut put_calls = put_result.ok().unwrap();
            assert_eq!(put_calls.len(), 1);
            match put_calls.remove(0) {
                MethodCall::Reply { data } => {
                    match data {
                        Data::ImmutableData(fetched_im_data) => {
                            assert_eq!(fetched_im_data, im_data);
                        }
                        _ => panic!("Unexpected"),
                    }
                }
                _ => panic!("Unexpected"),
            }

            let get_result = vault.handle_get(DataRequest::ImmutableData(im_data.get_type_tag().clone()),
                                              Authority::ManagedNode,
                                              Authority::NaeManager(im_data.name().clone()), from);
            assert_eq!(get_result.is_err(), false);
            let mut get_calls = get_result.ok().unwrap();
            assert_eq!(get_calls.len(), 1);
            match get_calls.remove(0) {
                MethodCall::Reply { data } => {
                    match data {
                        Data::ImmutableData(fetched_im_data) => {
                            assert_eq!(fetched_im_data, im_data);
                        }
                        _ => panic!("Unexpected"),
                    }
                }
                _ => panic!("Unexpected"),
            }
        }
    }

    #[test]
    fn structured_data_put_post_get() {
        let mut vault = VaultFacade::new();

        let from = SourceAddress::Direct(NameType(vector_as_u8_64_array(generate_random_vec_u8(64))));
        let dest = DestinationAddress::Direct(NameType(vector_as_u8_64_array(generate_random_vec_u8(64))));
        let name = NameType([3u8; 64]);
        let value = generate_random_vec_u8(1024);
        let keys1 = crypto::sign::gen_keypair();
        let sd = StructuredData::new(0, name, value.clone(), vec![], 0, vec![keys1.0], vec![]);

        sd_manager_put(&mut vault, from.clone(), dest.clone(), sd.clone());

        let keys2 = crypto::sign::gen_keypair();
        let mut sd_new = StructuredData::new(0, name, value.clone(), vec![keys1.0], 1, vec![keys2.0], vec![]);
        assert_eq!(sd_new.add_signature(&keys1.1).ok(), Some(0));
        sd_manager_post(&mut vault, from.clone(), dest.clone(), sd_new.clone());
        
        sd_manager_get(&mut vault, from.clone(), StructuredData::compute_name(0, &name), sd_new);
    }

    #[test]
    fn churn_test() {
        let mut vault = VaultFacade::new();

        let mut available_nodes = Vec::with_capacity(30);
        for _ in 0..30 {
            available_nodes.push(NameType(vector_as_u8_64_array(generate_random_vec_u8(64))));
        }

        let value = generate_random_vec_u8(1024);
        let im_data = ImmutableData::new(ImmutableDataType::Normal, value);
        let from = SourceAddress::Direct(available_nodes[0].clone());
        let dest = DestinationAddress::Direct(available_nodes[1].clone());

        let mut small_close_group = Vec::with_capacity(5);
        for i in 0..5 {
            small_close_group.push(available_nodes[i].clone());
        }

        {// MaidManager - churn handling
            maid_manager_put(&mut vault, from.clone(), dest.clone(), im_data.clone());
            let churn_data = vault.handle_churn(small_close_group.clone());
            // DataManagerStatsTransfer will always be included in the return
            assert!(churn_data.len() == 2);

            // MaidManagerAccount
            match churn_data[0] {
                MethodCall::Refresh{ref type_tag, ref from_group, ref payload} => {
                    assert_eq!(*type_tag, transfer_tags::MAID_MANAGER_ACCOUNT_TAG);
                    assert_eq!(*from_group, available_nodes[0]);
                    let mut d = cbor::Decoder::from_bytes(&payload[..]);
                    if let Some(parsed_data) = d.decode().next().and_then(|result| result.ok()) {
                        match parsed_data {
                            Transfer::MaidManagerAccount(mm_account_wrapper) => {
                                assert_eq!(mm_account_wrapper.name(), available_nodes[0]);
                                assert_eq!(mm_account_wrapper.get_account().get_data_stored(), 1024);
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
            data_manager_put(&mut vault, from.clone(), dest.clone(), im_data.clone());
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
            pmid_manager_put(&mut vault, from.clone(), dest.clone(), im_data.clone());
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
            let sdv = StructuredData::new(0, name, value, vec![], 0, vec![], vec![]);

            sd_manager_put(&mut vault, from.clone(), dest.clone(), sdv.clone());
            let churn_data = vault.handle_churn(small_close_group.clone());
            // DataManagerStatsTransfer will always be included in the return
            assert_eq!(churn_data.len(), 2);

            match churn_data[0] {
                MethodCall::Refresh{ref type_tag, ref from_group, ref payload} => {
                    assert_eq!(*type_tag, transfer_tags::SD_MANAGER_ACCOUNT_TAG);
                    assert_eq!(*from_group, sdv.name());
                    match decode::<StructuredData>(payload) {
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
        let mut vault = VaultFacade::new();
        let value = generate_random_vec_u8(1024);
        let im_data = ImmutableData::new(ImmutableDataType::Normal, value);
        {
            let get_result = vault.handle_cache_get(DataRequest::ImmutableData(im_data.get_type_tag().clone()),
                                                    im_data.name().clone(), NameType::new([7u8; 64]));
            assert_eq!(get_result.is_err(), true);
            assert_eq!(get_result.err().unwrap(), From::from(ResponseError::NoData));
        }

        let put_result = vault.handle_cache_put(Authority::ManagedNode, NameType::new([7u8; 64]),
                                                Data::ImmutableData(im_data.clone()));
        assert_eq!(put_result.is_err(), true);
        match put_result.err().unwrap() {
            InterfaceError::Abort => { }
            _ => panic!("Unexpected"),
        }
        {
            let get_result = vault.handle_cache_get(DataRequest::ImmutableData(im_data.get_type_tag().clone()),
                                                    im_data.name().clone(), NameType::new([7u8; 64]));
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
            let get_result = vault.handle_cache_get(DataRequest::ImmutableData(im_data.get_type_tag().clone()),
                                                    NameType::new([7u8; 64]), NameType::new([7u8; 64]));
            assert_eq!(get_result.is_err(), true);
            assert_eq!(get_result.err().unwrap(), From::from(ResponseError::NoData));
        }
    }
}

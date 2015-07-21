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

use routing::NameType;
use routing::error::{ResponseError, InterfaceError};
use routing::authority::Authority;
use routing::data::{Data, DataRequest};
use routing::node_interface::{Interface, MethodCall, CreatePersonas};
use routing::sendable::Sendable;
use routing::types::{DestinationAddress, SourceAddress};

use data_manager::{DataManager, DataManagerSendable, DataManagerStatsSendable};
use maid_manager::{MaidManager, MaidManagerAccountWrapper, MaidManagerAccount};
use pmid_manager::{PmidManager, PmidManagerAccountWrapper, PmidManagerAccount};
use pmid_node::PmidNode;
use version_handler::VersionHandler;
use transfer_parser::transfer_tags::{MAID_MANAGER_ACCOUNT_TAG, DATA_MANAGER_ACCOUNT_TAG,
    PMID_MANAGER_ACCOUNT_TAG, VERSION_HANDLER_ACCOUNT_TAG, DATA_MANAGER_STATS_TAG};

/// Main struct to hold all personas
pub struct VaultFacade {
    data_manager : DataManager,
    maid_manager : MaidManager,
    pmid_manager : PmidManager,
    pmid_node : PmidNode,
    version_handler : VersionHandler,
    nodes_in_table : Vec<NameType>,
    data_cache: LruCache<NameType, Data>
}

impl Clone for VaultFacade {
    fn clone(&self) -> VaultFacade {
        VaultFacade::new()
    }
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
                // both DataManager and VersionHandler are NaeManagers and Get request to them are both from Node
                match data_request {
                    DataRequest::ImmutableData(_) => self.data_manager.handle_get(&name),
                    DataRequest::StructuredData(_) => self.version_handler.handle_get(name),
                    _ => Err(From::from(ResponseError::InvalidRequest)),
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
                // both DataManager and VersionHandler are NaeManagers
                // client put other data (Immutable, StructuredData) will all goes to MaidManager first,
                // then goes to DataManager (i.e. from_authority is always ClientManager)
                match data {
                    Data::ImmutableData(data) => self.data_manager.handle_put(data, &mut (self.nodes_in_table)),
                    Data::StructuredData(data) => self.version_handler.handle_put(data),
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

    // TODO: this will be covered by the task of https://maidsafe.atlassian.net/browse/MAID-1110
    fn handle_post(&mut self,
                   _: Authority, // our_authority
                   _: Authority, // from_authority
                   _: NameType, // from_address
                   _: NameType, // name
                   _: Data)->Result<Vec<MethodCall>, InterfaceError> { // data
        Err(From::from(ResponseError::InvalidRequest))
    }

    fn handle_get_response(&mut self,
                           _: NameType, // from_address
                           response: Data) -> Vec<MethodCall> {
        // GetResponse only used by DataManager to replicate data to new PN
        match response.clone() {
            Data::ImmutableData(_) => self.data_manager.handle_get_response(response),
            _ => vec![MethodCall::None]
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
                    _ => vec![MethodCall::None]
                }
            }
            Authority::NodeManager(_) => {
                // TODO: this from_address shall be the original pmid_node that failing or removing the copy
                //       which requires work in routing to replace the address properly
                match from_address {
                    SourceAddress::Direct(pmid_node) => self.data_manager.handle_put_response(response, &pmid_node),
                    _ => vec![MethodCall::None]
                }
            }
            _ => vec![MethodCall::None]
        }
    }

    // TODO: this will be covered by the task of https://maidsafe.atlassian.net/browse/MAID-1111
    fn handle_post_response(&mut self, 
                            _: Authority, // from_authority
                            _: NameType, // from_address
                            _: Result<Vec<u8>, ResponseError>) { // response
        ;
    }

    fn handle_churn(&mut self, mut close_group: Vec<NameType>) -> Vec<MethodCall> {
        let mm = self.maid_manager.retrieve_all_and_reset();
        let vh = self.version_handler.retrieve_all_and_reset();
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
            VERSION_HANDLER_ACCOUNT_TAG => {
                for payload in payloads {
                    self.version_handler.handle_account_transfer(payload);
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

impl VaultFacade {
    /// Initialise all the personas in the Vault interface.
    pub fn new() -> VaultFacade {
        VaultFacade {
            data_manager: DataManager::new(), maid_manager: MaidManager::new(),
            pmid_manager: PmidManager::new(), pmid_node: PmidNode::new(),
            version_handler: VersionHandler::new(), nodes_in_table: Vec::new(),
            data_cache: LruCache::with_expiry_duration_and_capacity(Duration::minutes(10), 100),
        }
    }

}

pub struct VaultGenerator;

impl CreatePersonas<VaultFacade> for VaultGenerator {
    fn create_personas(&mut self) -> VaultFacade {
        VaultFacade::new()
    }
}


#[cfg(test)]
 mod test {
    use std::convert::From;
    use super::*;
    use data_parser::Data;
    use data_manager;
    use routing;
    use cbor;
    use maidsafe_types;
    use transfer_parser::{Transfer, transfer_tags};

    use routing::authority::Authority;
    use routing::types:: { MethodCall, DestinationAddress };
    use routing::NameType;
    use routing::error::{ResponseError, InterfaceError};
    use routing::test_utils::Random;
    use routing::node_interface::{ Interface, MethodCall };
    use routing::sendable::Sendable;

    #[test]
    fn put_get_flow() {
        let mut vault = VaultFacade::new();
        let value = routing::types::generate_random_vec_u8(1024);
        let data = maidsafe_types::ImmutableData::new(value);
        { // MaidManager, shall allowing the put and SendOn to DataManagers around name
            let from = NameType::new([1u8; 64]);
            // TODO : in this stage, dest can be populated as anything ?
            let dest = DestinationAddress{ dest : NameType::generate_random(), relay_to: None };
            let put_result = vault.handle_put(Authority::ClientManager, Authority::Client,
                                              from, dest, data.serialised_contents());
            assert_eq!(put_result.is_err(), false);
            match put_result.ok().unwrap() {
                MethodCall::SendOn(ref x) => {
                    assert_eq!(x.len(), 1);
                    assert_eq!(x[0], data.name());
                }
             MethodCall::Reply(_) => panic!("Unexpected"),
            }
        }
        vault.nodes_in_table = vec![NameType::new([1u8; 64]), NameType::new([2u8; 64]), NameType::new([3u8; 64]), NameType::new([4u8; 64]),
                               NameType::new([5u8; 64]), NameType::new([6u8; 64]), NameType::new([7u8; 64]), NameType::new([8u8; 64])];
        { // DataManager, shall SendOn to pmid_nodes
            let from = NameType::new([1u8; 64]);
            // TODO : in this stage, dest can be populated as anything ?
            let dest = DestinationAddress{ dest : NameType::generate_random(), relay_to: None };
            let put_result = vault.handle_put(Authority::NaeManager, Authority::ClientManager,
                                              from, dest, data.serialised_contents());
            assert_eq!(put_result.is_err(), false);
            match put_result.ok().unwrap() {
                MethodCall::SendOn(ref x) => {
                    assert_eq!(x.len(), data_manager::PARALLELISM);
                    //assert_eq!(x[0], NameType([3u8; 64]));
                    //assert_eq!(x[1], NameType([2u8; 64]));
                    //assert_eq!(x[2], NameType([1u8; 64]));
                    //assert_eq!(x[3], NameType([7u8; 64]));
                }
                MethodCall::Reply(_) => panic!("Unexpected"),
            }
            let from = NameType::new([1u8; 64]);
            let get_result = vault.handle_get(data.type_tag(), data.name().clone(),
                                              Authority::NaeManager, Authority::Client, from);
            assert_eq!(get_result.is_err(), false);
            match get_result.ok().unwrap() {
                MethodCall::SendOn(ref x) => {
                    assert_eq!(x.len(), data_manager::PARALLELISM);
                    //assert_eq!(x[0], NameType([3u8; 64]));
                    //assert_eq!(x[1], NameType([2u8; 64]));
                    //assert_eq!(x[2], NameType([1u8; 64]));
                    //assert_eq!(x[3], NameType([7u8; 64]));
                }
                MethodCall::Reply(_) => panic!("Unexpected"),
            }
        }
        { // PmidManager, shall put to pmid_nodes
            let from = NameType::new([3u8; 64]);
            let dest = DestinationAddress{ dest : NameType::new([7u8; 64]), relay_to: None };
            let put_result = vault.handle_put(Authority::NodeManager, Authority::NaeManager,
                                              from, dest, data.serialised_contents());
            assert_eq!(put_result.is_err(), false);
            match put_result.ok().unwrap() {
                MethodCall::SendOn(ref x) => {
                    assert_eq!(x.len(), 1);
                    assert_eq!(x[0], NameType([7u8; 64]));
                }
                MethodCall::Reply(_) => panic!("Unexpected"),
            }
        }
        { // PmidNode stores/retrieves data
            let from = NameType::new([7u8; 64]);
            let dest = DestinationAddress{ dest : NameType::new([6u8; 64]), relay_to: None };
            let put_result = vault.handle_put(Authority::ManagedNode, Authority::NodeManager,
                                              from.clone(), dest, data.serialised_contents());
            assert_eq!(put_result.is_ok(), true);
            match put_result {
             Err(InterfaceError::Abort) => panic!("Unexpected"),
             Ok(MethodCall::Reply(_)) => {},
             _ => panic!("Unexpected"),
            }
            let from = NameType::new([7u8; 64]);

            let get_result = vault.handle_get(data.type_tag(), data.name().clone(),
                                              Authority::ManagedNode, Authority::NodeManager, from);
            assert_eq!(get_result.is_err(), false);
            match get_result.ok().unwrap() {
                MethodCall::Reply(ref x) => {
                    let mut d = cbor::Decoder::from_bytes(&x[..]);
                    if let Some(parsed_data) = d.decode().next().and_then(|result| result.ok()) {
                        match parsed_data {
                            Data::Immutable(data_retrieved) => {
                                assert_eq!(data.name().0.to_vec(), data_retrieved.name().0.to_vec());
                                assert_eq!(data.serialised_contents(), data_retrieved.serialised_contents());
                            },
                            _ => panic!("Unexpected"),
                        }
                    }
                },
                _ => panic!("Unexpected"),
            }
        }
    }

    fn maid_manager_put(vault: &mut VaultFacade, from: NameType, dest: DestinationAddress,
                        data_name: NameType, data: Vec<u8>) {
        let put_result = vault.handle_put(Authority::ClientManager, Authority::Client, from, dest, data);
        assert_eq!(put_result.is_err(), false);
        match put_result.ok().unwrap() {
            MethodCall::SendOn(ref x) => {
                assert_eq!(x.len(), 1);
                assert_eq!(x[0], data_name);
            }
            MethodCall::Reply(_) => panic!("Unexpected"),
        }
    }

    fn data_manager_put(vault: &mut VaultFacade, from: NameType, dest: DestinationAddress, data: Vec<u8>) {
        let put_result = vault.handle_put(Authority::NaeManager, Authority::ClientManager, from, dest, data);
        assert_eq!(put_result.is_err(), false);
        match put_result.ok().unwrap() {
            MethodCall::SendOn(ref x) => {
                assert_eq!(x.len(), data_manager::PARALLELISM);
            }
            MethodCall::Reply(_) => panic!("Unexpected"),
        }
    }

    fn add_nodes_to_table(vault: &mut VaultFacade, nodes: &Vec<NameType>) {
        for node in nodes {
            vault.nodes_in_table.push(node.clone());
        }
    }

    fn pmid_manager_put(vault: &mut VaultFacade, from: NameType, dest: DestinationAddress, data: Vec<u8>) {
        let put_result = vault.handle_put(Authority::NodeManager, Authority::NaeManager,
                                          from, dest.clone(), data);
        assert_eq!(put_result.is_err(), false);
        match put_result.ok().unwrap() {
            MethodCall::SendOn(ref x) => {
                assert_eq!(x.len(), 1);
                assert_eq!(x[0], dest.dest);
            }
            MethodCall::Reply(_) => panic!("Unexpected"),
        }
    }

    fn version_handler_put(vault: &mut VaultFacade, from: NameType, dest: DestinationAddress, data: Vec<u8>) {
        let put_result = vault.handle_put(Authority::NaeManager, Authority::ManagedNode,
                                          from.clone(), dest, data);
        assert_eq!(put_result.is_ok(), true);
        match put_result {
             Err(InterfaceError::Abort) => panic!("Unexpected"),
             Ok(MethodCall::Reply(_)) => {},
             _ => panic!("Unexpected"),
        }
    }

    #[test]
    fn churn_test() {
        let mut vault = VaultFacade::new();

        let mut available_nodes = Vec::with_capacity(30);
        for _ in 0..30 {
            available_nodes.push(NameType::generate_random());
        }

        let value = routing::types::generate_random_vec_u8(1024);
        let data = maidsafe_types::ImmutableData::new(value);
        let from = available_nodes[0].clone();
        let dest = DestinationAddress{ dest : available_nodes[1].clone(), relay_to: None };
        let data_as_vec = data.serialised_contents();

        let mut small_close_group = Vec::with_capacity(5);
        for i in 0..5 {
            small_close_group.push(available_nodes[i].clone());
        }

        {// MaidManager - churn handling
            maid_manager_put(&mut vault, from.clone(), dest.clone(), data.name().clone(), data_as_vec.clone());
            let churn_data = vault.handle_churn(small_close_group.clone());
            // DataManagerStatsTransfer will always be included in the return
            assert!(churn_data.len() == 2);

            // MaidManagerAccount
            match churn_data[0] {
                MethodCall::Refresh{ref type_tag, ref from_group, ref payload} => {
                    assert_eq!(*type_tag, transfer_tags::MAID_MANAGER_ACCOUNT_TAG);
                    assert_eq!(*from_group, from);
                    let mut d = cbor::Decoder::from_bytes(&payload[..]);
                    if let Some(parsed_data) = d.decode().next().and_then(|result| result.ok()) {
                        match parsed_data {
                            Transfer::MaidManagerAccount(mm_account_wrapper) => {
                                assert_eq!(mm_account_wrapper.name(), from.clone());
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
            data_manager_put(&mut vault, from.clone(), dest.clone(), data_as_vec.clone());
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
                    assert_eq!(*from_group, data.name());
                    let mut d = cbor::Decoder::from_bytes(&payload[..]);
                    if let Some(parsed_data) = d.decode().next().and_then(|result| result.ok()) {
                        match parsed_data {
                            Transfer::DataManagerAccount(data_manager_sendable) => {
                                assert_eq!(data_manager_sendable.name(), data.name());
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
            pmid_manager_put(&mut vault, from.clone(), dest.clone(), data_as_vec.clone());
            let churn_data = vault.handle_churn(small_close_group.clone());
            // DataManagerStatsTransfer will always be included in the return
            assert_eq!(churn_data.len(), 2);
            //assert_eq!(churn_data[0].0, from);

            match churn_data[0] {
                MethodCall::Refresh{ref type_tag, ref from_group, ref payload} => {
                    assert_eq!(*type_tag, transfer_tags::PMID_MANAGER_ACCOUNT_TAG);
                    assert_eq!(*from_group, dest.dest);
                    let mut d = cbor::Decoder::from_bytes(&payload[..]);
                    if let Some(parsed_data) = d.decode().next().and_then(|result| result.ok()) {
                        match parsed_data {
                            Transfer::PmidManagerAccount(account_wrapper) => {
                                assert_eq!(account_wrapper.name(), dest.dest);
                            },
                            _ => panic!("Unexpected"),
                        }
                    }
                },
                _ => panic!("Refresh type expected")
            };
            assert!(vault.pmid_manager.retrieve_all_and_reset(&Vec::new()).is_empty());
        }

        {// VersionHandler - churn handling
            let name = NameType::generate_random();
            let owner = NameType::generate_random();
            let mut vec_name_types = Vec::<NameType>::with_capacity(10);
            for _ in 0..10 {
                vec_name_types.push(NameType::generate_random());
            }
            let data = maidsafe_types::StructuredData::new(name, owner, vec_name_types.clone());
            let data_as_vec: Vec<u8> = data.serialised_contents();

            version_handler_put(&mut vault, from.clone(), dest.clone(), data_as_vec.clone());
            let churn_data = vault.handle_churn(small_close_group.clone());
            // DataManagerStatsTransfer will always be included in the return
            assert_eq!(churn_data.len(), 2);

            match churn_data[0] {
                MethodCall::Refresh{ref type_tag, ref from_group, ref payload} => {
                    assert_eq!(*type_tag, transfer_tags::VERSION_HANDLER_ACCOUNT_TAG);
                    assert_eq!(*from_group, data.name());
                    let mut d = cbor::Decoder::from_bytes(&payload[..]);
                    if let Some(parsed_data) = d.decode().next().and_then(|result| result.ok()) {
                        match parsed_data {
                            Transfer::VersionHandlerAccount(sendable) => {
                                assert_eq!(sendable.name(), data.name());
                            },
                            _ => panic!("Unexpected"),
                        }
                    }
                },
                _ => panic!("Refresh type expected")
            };
            

            assert!(vault.version_handler.retrieve_all_and_reset().is_empty());
        }

    }

    #[test]
    fn cache_test() {
        let mut vault = VaultFacade::new();
        let value = routing::types::generate_random_vec_u8(1024);
        let data = maidsafe_types::ImmutableData::new(value);
        {
            let get_result = vault.handle_cache_get(data.type_tag(), data.name().clone(),
                                                    Authority::ManagedNode, NameType::new([7u8; 64]));
            assert_eq!(get_result.is_err(), true);
            assert_eq!(get_result.err().unwrap(), From::from(ResponseError::NoData));
        }

        let put_result = vault.handle_cache_put(Authority::ManagedNode, NameType::new([7u8; 64]),
                                                data.serialised_contents());
        assert_eq!(put_result.is_err(), true);
        match put_result.err().unwrap() {
            InterfaceError::Abort => { }
            _ => panic!("Unexpected"),
        }
        {
            let get_result = vault.handle_cache_get(data.type_tag(), data.name().clone(),
                                                    Authority::ManagedNode, NameType::new([7u8; 64]));
            assert_eq!(get_result.is_err(), false);
            match get_result.ok().unwrap() {
                MethodCall::Reply(x) => {
                    let mut d = cbor::Decoder::from_bytes(&x[..]);
                    if let Some(parsed_data) = d.decode().next().and_then(|result| result.ok()) {
                        match parsed_data {
                            Data::Immutable(data_retrieved) => {
                                assert_eq!(data.name().0.to_vec(), data_retrieved.name().0.to_vec());
                                assert_eq!(data.serialised_contents(), data_retrieved.serialised_contents());
                            },
                            _ => panic!("Unexpected"),
                        }
                    }
                },
                _ => panic!("Unexpected"),
            }
        }
        {
            let get_result = vault.handle_cache_get(data.type_tag(), NameType::new([7u8; 64]),
                                                    Authority::ManagedNode, NameType::new([7u8; 64]));
            assert_eq!(get_result.is_err(), true);
            assert_eq!(get_result.err().unwrap(), From::from(ResponseError::NoData));
        }
    }
}

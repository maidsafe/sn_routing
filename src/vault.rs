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

use maidsafe_types::*;

use routing::NameType;
use routing::error::{ResponseError, InterfaceError};
use routing::authority::Authority;
use routing::node_interface::{ Interface, MethodCall, CreatePersonas };
use routing::sendable::Sendable;
use routing::types::{MessageAction, DestinationAddress};

use data_manager::{DataManager, DataManagerSendable, DataManagerStatsSendable};
use maid_manager::{MaidManager, MaidManagerAccountWrapper, MaidManagerAccount};
use pmid_manager::{PmidManager, PmidManagerAccountWrapper, PmidManagerAccount};
use pmid_node::PmidNode;
use version_handler::{VersionHandler, VersionHandlerSendable};
use data_parser::Data;

/// Main struct to hold all personas
pub struct VaultFacade {
    data_manager : DataManager,
    maid_manager : MaidManager,
    pmid_manager : PmidManager,
    pmid_node : PmidNode,
    version_handler : VersionHandler,
    nodes_in_table : Vec<NameType>,
    data_cache: LruCache<NameType, Vec<u8>>
}

impl Clone for VaultFacade {
    fn clone(&self) -> VaultFacade {
        VaultFacade::new()
    }
}

fn merge_payload(type_tag: u64, from_group: NameType, payloads: Vec<Vec<u8>>) -> Option<Payload> {
    match type_tag {
      200 => {
        Some(merge_refreashable(MaidManagerAccountWrapper::new(from_group, MaidManagerAccount::new()),
                                PayloadTypeTag::MaidManagerAccountTransfer, payloads))
      }
      206 => {
        Some(merge_refreashable(DataManagerSendable::new(from_group, vec![]),
                                PayloadTypeTag::DataManagerAccountTransfer, payloads))
      }
      220 => {
        Some(merge_refreashable(DataManagerStatsSendable::new(from_group, 0),
                                PayloadTypeTag::DataManagerStatsTransfer, payloads))
      }
      201 => {
        Some(merge_refreashable(PmidManagerAccountWrapper::new(from_group, PmidManagerAccount::new()),
                                PayloadTypeTag::PmidManagerAccountTransfer, payloads))
      }
      209 => {
        let seed_sdv_payload = payloads[0].clone();
        let mut d = Decoder::from_bytes(&seed_sdv_payload[..]);
        let payload: Payload = d.decode().next().unwrap().unwrap();
        let transfer_entry : VersionHandlerSendable = payload.get_data();
        Some(merge_refreashable(transfer_entry, PayloadTypeTag::VersionHandlerAccountTransfer, payloads))
      }
      _ => None
    }
}

fn merge_refreashable<T>(merged_entry: T, payload_type: PayloadTypeTag,
                         payloads: Vec<Vec<u8>>) -> Payload where T: for<'a> Sendable + Encodable + Decodable + 'static {
    let mut transfer_entries = Vec::<Box<Sendable>>::new();
    for it in payloads.iter() {
        let mut d = Decoder::from_bytes(&it[..]);
        let payload: Payload = d.decode().next().unwrap().unwrap();
        let transfer_entry : T = payload.get_data();
        transfer_entries.push(Box::new(transfer_entry));
    }
    merged_entry.merge(transfer_entries);
    Payload::new(payload_type, &merged_entry)
}

impl Interface for VaultFacade {
    fn handle_get(&mut self,
                  _: u64, // type_id
                  name: NameType,
                  our_authority: Authority,
                  _: Authority, // from_authority
                  _: NameType)->Result<MessageAction, InterfaceError> { // from_address
        match our_authority {
            Authority::NaeManager => {
                // both DataManager and VersionHandler are NaeManagers and Get request to them are both from Node
                // data input here is assumed as name only(no type info attached)
                let data_manager_result = self.data_manager.handle_get(&name);
                if data_manager_result.is_ok() {
                    return data_manager_result;
                }
                return self.version_handler.handle_get(name);
            }
            Authority::ManagedNode => { return self.pmid_node.handle_get(name); }
            _ => { return Err(From::from(ResponseError::InvalidRequest)); }
        }
    }

    fn handle_put(&mut self, our_authority: Authority, _from_authority: Authority,
                from_address: NameType, dest_address: DestinationAddress, data: Vec<u8>)->Result<MessageAction, InterfaceError> {
        match our_authority {
            Authority::ClientManager => { return self.maid_manager.handle_put(&from_address, &data); }
            Authority::NaeManager => {
                // both DataManager and VersionHandler are NaeManagers
                // client put PublicMaid will directly goes to DM (i.e. from_authority is ManagedNode)
                // client put other data types (Immutable, StructuredData) will all goes to MaidManager first,
                // then goes to DataManager (i.e. from_authority is always ClientManager)
                let mut d = Decoder::from_bytes(&data[..]);
                let payload: Payload = d.decode().next().unwrap().unwrap();
                match payload.get_type_tag() {
                    PayloadTypeTag::StructuredData => self.version_handler.handle_put(data),
                    _ => self.data_manager.handle_put(&data, &mut (self.nodes_in_table)),
                }
            }
            Authority::NodeManager => { return self.pmid_manager.handle_put(&dest_address, &data); }
            Authority::ManagedNode => { return self.pmid_node.handle_put(data); }
            _ => { return Err(From::from(ResponseError::InvalidRequest)); }
        }
    }

    // TODO: this will be covered by the task of https://maidsafe.atlassian.net/browse/MAID-1010
    fn handle_post(&mut self,
                   _: Authority, // our_authority
                   _: Authority, // from_authority
                   _: NameType, // from_address
                   _: NameType, // name
                   _: Vec<u8>)->Result<MessageAction, InterfaceError> { // data
        Err(From::from(ResponseError::InvalidRequest))
    }

    fn handle_get_response(&mut self,
                           _: NameType, // from_address
                           response: Result<Vec<u8>, ResponseError>) -> MethodCall {
        if response.is_ok() {
            self.data_manager.handle_get_response(response.ok().unwrap())
        } else {
            MethodCall::None
        }
    }

    fn handle_put_response(&mut self, from_authority: Authority, from_address: NameType,
                           response: Result<Vec<u8>, ResponseError>) -> MethodCall {
        match from_authority {
            Authority::ManagedNode => { return self.pmid_manager.handle_put_response(&from_address, &response); }
            Authority::NodeManager => {
                // TODO: this from_address shall be the original pmid_node that failing or removing the copy
                //       which requires work in routing to replace the address properly
                return self.data_manager.handle_put_response(&response, &from_address);
            }
            _ => { return MethodCall::None; }
        }
    }

    // TODO: this will be covered by the task of https://maidsafe.atlassian.net/browse/MAID-1011
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
                      payloads: Vec<Vec<u8>>) { // payloads
        // TODO: The assumption of the incoming payloads is that it is a vector of serialized Payload type
        //       holding the transferring account entry from the close group nodes of from_group
        match merge_payload(type_tag, from_group, payloads) {
            Some(payload) => {
                match payload.get_type_tag() {
                    PayloadTypeTag::MaidManagerAccountTransfer => {
                        self.maid_manager.handle_account_transfer(payload);
                    }
                    PayloadTypeTag::DataManagerAccountTransfer => {
                        self.data_manager.handle_account_transfer(payload);
                    }
                    PayloadTypeTag::DataManagerStatsTransfer => {
                        self.data_manager.handle_stats_transfer(payload);
                    }
                    PayloadTypeTag::PmidManagerAccountTransfer => {
                        self.pmid_manager.handle_account_transfer(payload);
                    }
                    PayloadTypeTag::VersionHandlerAccountTransfer => {
                        self.version_handler.handle_account_transfer(payload);
                    }
                    _ => {}
                }
            }
            None => {}
        }
    }

    // The cache handling in vault is roleless, i.e. vault will do whatever routing tells it to do
    fn handle_cache_get(&mut self,
                        _: u64, // type_id
                        name: NameType,
                        _: Authority, //from_authority
                        _: NameType) -> Result<MessageAction, InterfaceError> { // from_address
        match self.data_cache.get(&name) {
            Some(data) => Ok(MessageAction::Reply(data.clone())),
            None => Err(From::from(ResponseError::NoData))
        }
    }

    fn handle_cache_put(&mut self,
                        _: Authority, // from_authority
                        _: NameType, // from_address
                        data: Vec<u8>) -> Result<MessageAction, InterfaceError> {
        let mut data_name : NameType;
        let mut d = Decoder::from_bytes(&data[..]);
        let payload: Payload = d.decode().next().unwrap().unwrap();
        match payload.get_type_tag() {
          PayloadTypeTag::ImmutableData => {
            data_name = payload.get_data::<ImmutableData>().name();
          }
          PayloadTypeTag::PublicMaid => {
            data_name = payload.get_data::<PublicIdType>().name();
          }
          _ => return Err(From::from(ResponseError::InvalidRequest))
        }
        // the type_tag needs to be stored as well
        self.data_cache.add(data_name, data);
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
    use data_manager;
    use routing;
    use cbor;
    use maidsafe_types;
    use maid_manager;
    use pmid_manager;
    use version_handler;
    use maidsafe_types::{PayloadTypeTag, Payload};
    use routing::authority::Authority;
    use routing::types:: { MessageAction, DestinationAddress };
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
        let payload = Payload::new(PayloadTypeTag::ImmutableData, &data);
        let mut encoder = cbor::Encoder::from_memory();
        let encode_result = encoder.encode(&[&payload]);
        assert_eq!(encode_result.is_ok(), true);

        { // MaidManager, shall allowing the put and SendOn to DataManagers around name
            let from = NameType::new([1u8; 64]);
            // TODO : in this stage, dest can be populated as anything ?
            let dest = DestinationAddress{ dest : NameType::generate_random(), relay_to: None };
            let put_result = vault.handle_put(Authority::ClientManager, Authority::Client, from, dest,
                                             routing::types::array_as_vector(encoder.as_bytes()));
            assert_eq!(put_result.is_err(), false);
            match put_result.ok().unwrap() {
                MessageAction::SendOn(ref x) => {
                    assert_eq!(x.len(), 1);
                    assert_eq!(x[0], data.name());
                }
             MessageAction::Reply(_) => panic!("Unexpected"),
            }
        }
        vault.nodes_in_table = vec![NameType::new([1u8; 64]), NameType::new([2u8; 64]), NameType::new([3u8; 64]), NameType::new([4u8; 64]),
                               NameType::new([5u8; 64]), NameType::new([6u8; 64]), NameType::new([7u8; 64]), NameType::new([8u8; 64])];
        { // DataManager, shall SendOn to pmid_nodes
            let from = NameType::new([1u8; 64]);
            // TODO : in this stage, dest can be populated as anything ?
            let dest = DestinationAddress{ dest : NameType::generate_random(), relay_to: None };
            let put_result = vault.handle_put(Authority::NaeManager, Authority::ClientManager, from, dest,
                                             routing::types::array_as_vector(encoder.as_bytes()));
            assert_eq!(put_result.is_err(), false);
            match put_result.ok().unwrap() {
                MessageAction::SendOn(ref x) => {
                    assert_eq!(x.len(), data_manager::PARALLELISM);
                    //assert_eq!(x[0], NameType([3u8; 64]));
                    //assert_eq!(x[1], NameType([2u8; 64]));
                    //assert_eq!(x[2], NameType([1u8; 64]));
                    //assert_eq!(x[3], NameType([7u8; 64]));
                }
                MessageAction::Reply(_) => panic!("Unexpected"),
            }
            let from = NameType::new([1u8; 64]);
            let get_result = vault.handle_get(payload.get_type_tag() as u64, data.name().clone(), Authority::NaeManager,
                                             Authority::Client, from);
            assert_eq!(get_result.is_err(), false);
            match get_result.ok().unwrap() {
                MessageAction::SendOn(ref x) => {
                    assert_eq!(x.len(), data_manager::PARALLELISM);
                    //assert_eq!(x[0], NameType([3u8; 64]));
                    //assert_eq!(x[1], NameType([2u8; 64]));
                    //assert_eq!(x[2], NameType([1u8; 64]));
                    //assert_eq!(x[3], NameType([7u8; 64]));
                }
                MessageAction::Reply(_) => panic!("Unexpected"),
            }
        }
        { // PmidManager, shall put to pmid_nodes
            let from = NameType::new([3u8; 64]);
            let dest = DestinationAddress{ dest : NameType::new([7u8; 64]), relay_to: None };
            let put_result = vault.handle_put(Authority::NodeManager, Authority::NaeManager, from, dest,
                                         routing::types::array_as_vector(encoder.as_bytes()));
            assert_eq!(put_result.is_err(), false);
            match put_result.ok().unwrap() {
                MessageAction::SendOn(ref x) => {
                    assert_eq!(x.len(), 1);
                    assert_eq!(x[0], NameType([7u8; 64]));
                }
                MessageAction::Reply(_) => panic!("Unexpected"),
            }
        }
        { // PmidNode stores/retrieves data
            let from = NameType::new([7u8; 64]);
            let dest = DestinationAddress{ dest : NameType::new([6u8; 64]), relay_to: None };
            let put_result = vault.handle_put(Authority::ManagedNode, Authority::NodeManager, from.clone(), dest,
                                             routing::types::array_as_vector(encoder.as_bytes()));
            assert_eq!(put_result.is_ok(), true);
            match put_result {
             Err(InterfaceError::Abort) => panic!("Unexpected"),
             Ok(MessageAction::Reply(_)) => {},
             _ => panic!("Unexpected"),
            }
            let from = NameType::new([7u8; 64]);

            let get_result = vault.handle_get(payload.get_type_tag() as u64, data.name().clone(), Authority::ManagedNode,
                                             Authority::NodeManager, from);
            assert_eq!(get_result.is_err(), false);
            match get_result.ok().unwrap() {
                MessageAction::Reply(ref x) => {
                    let mut d = cbor::Decoder::from_bytes(&x[..]);
                    let payload_retrieved: Payload = d.decode().next().unwrap().unwrap();
                    assert_eq!(payload_retrieved.get_type_tag(), PayloadTypeTag::ImmutableData);
                    let data_retrieved = payload_retrieved.get_data::<maidsafe_types::ImmutableData>();
                    assert_eq!(data.name().0.to_vec(), data_retrieved.name().0.to_vec());
                    assert_eq!(data.serialised_contents(), data_retrieved.serialised_contents());
                },
                _ => panic!("Unexpected"),
            }
        }
    }

    fn maid_manager_put(vault: &mut VaultFacade, from: NameType, dest: DestinationAddress,
                        payload_name: NameType, payload: Vec<u8>) {
        let put_result = vault.handle_put(Authority::ClientManager, Authority::Client, from, dest,
                                         payload);
        assert_eq!(put_result.is_err(), false);
        match put_result.ok().unwrap() {
            MessageAction::SendOn(ref x) => {
                assert_eq!(x.len(), 1);
                assert_eq!(x[0], payload_name);
            }
            MessageAction::Reply(_) => panic!("Unexpected"),
        }
    }

    fn data_manager_put(vault: &mut VaultFacade, from: NameType, dest: DestinationAddress,
                        payload: Vec<u8>) {
        let put_result = vault.handle_put(Authority::NaeManager, Authority::ClientManager, from,
            dest, payload);
        assert_eq!(put_result.is_err(), false);
        match put_result.ok().unwrap() {
            MessageAction::SendOn(ref x) => {
                assert_eq!(x.len(), data_manager::PARALLELISM);
            }
            MessageAction::Reply(_) => panic!("Unexpected"),
        }
    }

    fn add_nodes_to_table(vault: &mut VaultFacade, nodes: &Vec<NameType>) {
        for node in nodes {
            vault.nodes_in_table.push(node.clone());
        }
    }

    fn pmid_manager_put(vault: &mut VaultFacade, from: NameType, dest: DestinationAddress,
                        payload: Vec<u8>) {
        let put_result = vault.handle_put(Authority::NodeManager, Authority::NaeManager, from, dest.clone(),
                                     payload);
        assert_eq!(put_result.is_err(), false);
        match put_result.ok().unwrap() {
            MessageAction::SendOn(ref x) => {
                assert_eq!(x.len(), 1);
                assert_eq!(x[0], dest.dest);
            }
            MessageAction::Reply(_) => panic!("Unexpected"),
        }
    }

    fn version_handler_put(vault: &mut VaultFacade, from: NameType, dest: DestinationAddress,
                        payload: Vec<u8>) {
        let put_result = vault.handle_put(Authority::NaeManager, Authority::ManagedNode,
            from.clone(), dest, payload);
        assert_eq!(put_result.is_ok(), true);
        match put_result {
             Err(InterfaceError::Abort) => panic!("Unexpected"),
             Ok(MessageAction::Reply(_)) => {},
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
        let payload = Payload::new(PayloadTypeTag::ImmutableData, &data);

        let mut encoder = cbor::Encoder::from_memory();
        let encode_result = encoder.encode(&[&payload]);
        assert_eq!(encode_result.is_ok(), true);

        let from = available_nodes[0].clone();
        let dest = DestinationAddress{ dest : available_nodes[1].clone(), relay_to: None };
        let data_as_vec = encoder.into_bytes();

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
            let mm_account_wrapper: maid_manager::MaidManagerAccountWrapper = match churn_data[0] {
                MethodCall::Refresh{ref type_tag, ref from_group, ref payload} => {
                    assert_eq!(*type_tag, 200);
                    assert_eq!(*from_group, from);
                    let mut d = cbor::Decoder::from_bytes(&payload[..]);
                    let transfer_payload: Payload = d.decode().next().unwrap().unwrap();
                    assert_eq!(transfer_payload.get_type_tag(), PayloadTypeTag::MaidManagerAccountTransfer);
                    transfer_payload.get_data()
                },
                _ => panic!("Refresh type expected")
            };
            assert_eq!(mm_account_wrapper.name(), from.clone());
            assert_eq!(mm_account_wrapper.get_account().get_data_stored(), 1024);
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
                    assert_eq!(*type_tag, 206);
                    assert_eq!(*from_group, data.name());
                    let mut d = cbor::Decoder::from_bytes(&payload[..]);
                    let transfer_payload: Payload = d.decode().next().unwrap().unwrap();
                    assert_eq!(transfer_payload.get_type_tag(), PayloadTypeTag::DataManagerAccountTransfer);
                    let data_manager_sendable: data_manager::DataManagerSendable = transfer_payload.get_data();
                    assert_eq!(data_manager_sendable.name(), data.name());
                },
                MethodCall::Get { .. } => (),
                _ => panic!("Refresh type expected")
            };

            match churn_data[1] {
                MethodCall::Refresh{ref type_tag, ref from_group, ref payload} => {
                    assert_eq!(*type_tag, 220);
                    assert_eq!(*from_group, close_group[0]);
                    let mut d = cbor::Decoder::from_bytes(&payload[..]);
                    let transfer_payload: Payload = d.decode().next().unwrap().unwrap();
                    assert_eq!(transfer_payload.get_type_tag(), PayloadTypeTag::DataManagerStatsTransfer);
                    let stats_sendable: data_manager::DataManagerStatsSendable = transfer_payload.get_data();
                    assert_eq!(stats_sendable.get_resource_index(), 1);
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

            let pmid_manager: pmid_manager::PmidManagerAccountWrapper = match churn_data[0] {
                MethodCall::Refresh{ref type_tag, ref from_group, ref payload} => {
                    assert_eq!(*type_tag, 201);
                    assert_eq!(*from_group, dest.dest);
                    let mut d = cbor::Decoder::from_bytes(&payload[..]);
                    let transfer_payload: Payload = d.decode().next().unwrap().unwrap();
                    assert_eq!(transfer_payload.get_type_tag(), PayloadTypeTag::PmidManagerAccountTransfer);
                    transfer_payload.get_data()
                },
                _ => panic!("Refresh type expected")
            };
            assert_eq!(pmid_manager.name(), dest.dest);

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
            let payload = Payload::new(PayloadTypeTag::StructuredData, &data);

            let mut encoder = cbor::Encoder::from_memory();
            let encode_result = encoder.encode(&[&payload]);
            assert_eq!(encode_result.is_ok(), true);
            let data_as_vec: Vec<u8> = encoder.into_bytes();

            version_handler_put(&mut vault, from.clone(), dest.clone(), data_as_vec.clone());
            let churn_data = vault.handle_churn(small_close_group.clone());
            // DataManagerStatsTransfer will always be included in the return
            assert_eq!(churn_data.len(), 2);

            let sendable: version_handler::VersionHandlerSendable = match churn_data[0] {
                MethodCall::Refresh{ref type_tag, ref from_group, ref payload} => {
                    assert_eq!(*type_tag, 209);
                    assert_eq!(*from_group, data.name());
                    let mut d = cbor::Decoder::from_bytes(&payload[..]);
                    let transfer_payload: Payload = d.decode().next().unwrap().unwrap();
                    assert_eq!(transfer_payload.get_type_tag(), PayloadTypeTag::VersionHandlerAccountTransfer);
                    transfer_payload.get_data()
                },
                _ => panic!("Refresh type expected")
            };
            assert_eq!(sendable.name(), data.name());

            assert!(vault.version_handler.retrieve_all_and_reset().is_empty());
        }

    }

    #[test]
    fn cache_test() {
        let mut vault = VaultFacade::new();
        let value = routing::types::generate_random_vec_u8(1024);
        let data = maidsafe_types::ImmutableData::new(value);
        let payload = Payload::new(PayloadTypeTag::ImmutableData, &data);
        let mut encoder = cbor::Encoder::from_memory();
        let encode_result = encoder.encode(&[&payload]);
        assert_eq!(encode_result.is_ok(), true);

        {
            let get_result = vault.handle_cache_get(payload.get_type_tag() as u64, data.name().clone(),
                                                    Authority::ManagedNode, NameType::new([7u8; 64]));
            assert_eq!(get_result.is_err(), true);
            assert_eq!(get_result.err().unwrap(), From::from(ResponseError::NoData));
        }

        let put_result = vault.handle_cache_put(Authority::ManagedNode, NameType::new([7u8; 64]),
                                                routing::types::array_as_vector(encoder.as_bytes()));
        assert_eq!(put_result.is_err(), true);
        match put_result.err().unwrap() {
            InterfaceError::Abort => { }
            _ => panic!("Unexpected"),
        }
        {
            let get_result = vault.handle_cache_get(payload.get_type_tag() as u64, data.name().clone(),
                                                    Authority::ManagedNode, NameType::new([7u8; 64]));
            assert_eq!(get_result.is_err(), false);
            match get_result.ok().unwrap() {
                MessageAction::Reply(ref x) => {
                    let mut d = cbor::Decoder::from_bytes(&x[..]);
                    let payload_retrieved: Payload = d.decode().next().unwrap().unwrap();
                    assert_eq!(payload_retrieved.get_type_tag(), PayloadTypeTag::ImmutableData);
                    let data_retrieved = payload_retrieved.get_data::<maidsafe_types::ImmutableData>();
                    assert_eq!(data.name().0.to_vec(), data_retrieved.name().0.to_vec());
                    assert_eq!(data.serialised_contents(), data_retrieved.serialised_contents());
                },
                _ => panic!("Unexpected"),
            }
        }
        {
            let get_result = vault.handle_cache_get(payload.get_type_tag() as u64, NameType::new([7u8; 64]),
                                                    Authority::ManagedNode, NameType::new([7u8; 64]));
            assert_eq!(get_result.is_err(), true);
            assert_eq!(get_result.err().unwrap(), From::from(ResponseError::NoData));
        }
    }
}

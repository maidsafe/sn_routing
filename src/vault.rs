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
// relating to use of the SAFE Network Software.                                                              */


#![deny(missing_docs)]

use routing;
use routing::{Action, RoutingError, NameType};
use routing::types::{Authority, DestinationAddress};

use data_manager::DataManager;
use maid_manager::MaidManager;
use pmid_manager::PmidManager;
use pmid_node::PmidNode;
use version_handler::VersionHandler;
use routing::node_interface::{ Interface, RoutingNodeAction };


/// Main struct to hold all personas
pub struct VaultFacade {
    data_manager : DataManager,
    maid_manager : MaidManager,
    pmid_manager : PmidManager,
    pmid_node : PmidNode,
    version_handler : VersionHandler,
    nodes_in_table : Vec<NameType>,
}

impl Clone for VaultFacade {
    fn clone(&self) -> VaultFacade {
        VaultFacade::new()
    }
}

impl Interface for VaultFacade {
    fn handle_get(&mut self, type_id: u64, name: NameType, our_authority: Authority, from_authority: Authority,
                from_address: NameType)->Result<Action, RoutingError> {
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
            _ => { return Err(RoutingError::InvalidRequest); }
        }
    }

    fn handle_get_key(&mut self, type_id: u64, name: NameType, our_authority: Authority, from_authority: Authority,
                from_address: NameType)->Result<Action, RoutingError> {
        unimplemented!();
    }

    fn handle_put(&mut self, our_authority: Authority, from_authority: Authority,
                from_address: NameType, dest_address: DestinationAddress, data: Vec<u8>)->Result<Action, RoutingError> {
        match our_authority {
            Authority::ClientManager => { return self.maid_manager.handle_put(&from_address, &data); }
            Authority::NaeManager => {
                // both DataManager and VersionHandler are NaeManagers
                // However Put request to DataManager is from ClientManager (MaidManager)
                // meanwhile Put request to VersionHandler is from Node
                match from_authority {
                  Authority::ClientManager => { return self.data_manager.handle_put(&data, &mut (self.nodes_in_table)); }
                  Authority::ManagedNode => { return self.version_handler.handle_put(data); }
                  _ => { return Err(RoutingError::InvalidRequest); }
                }
            }
            Authority::NodeManager => { return self.pmid_manager.handle_put(&dest_address, &data); }
            Authority::ManagedNode => { return self.pmid_node.handle_put(data); }
            _ => { return Err(RoutingError::InvalidRequest); }
        }
    }

    fn handle_post(&mut self, our_authority: Authority, from_authority: Authority, from_address: NameType, data: Vec<u8>)->Result<Action, RoutingError> {
        ;
        Err(RoutingError::InvalidRequest)
    }

    fn handle_get_response(&mut self, from_address: NameType, response: Result<Vec<u8>,
         RoutingError>) -> RoutingNodeAction {
        if response.is_ok() {
            self.data_manager.handle_get_response(response.ok().unwrap())
        } else {
            routing::node_interface::RoutingNodeAction::None
        }
    }

    fn handle_put_response(&mut self, from_authority: Authority, from_address: NameType, response: Result<Vec<u8>, RoutingError>) {
        ;
    }

    fn handle_post_response(&mut self, from_authority: Authority, from_address: NameType, response: Result<Vec<u8>, RoutingError>) {
        ;
    }

    fn handle_churn(&mut self, mut close_group: Vec<NameType>) -> Vec<RoutingNodeAction> {
        let mut mm = self.maid_manager.retrieve_all_and_reset();
        let mut vh = self.version_handler.retrieve_all_and_reset();
        let mut pm = self.pmid_manager.retrieve_all_and_reset(&close_group);
        let mut dm = self.data_manager.retrieve_all_and_reset(&mut close_group);

        dm.into_iter().chain(mm.into_iter().chain(pm.into_iter().chain(vh.into_iter()))).collect()
    }

    fn handle_cache_get(&mut self,
                        type_id: u64,
                        name: NameType,
                        from_authority: Authority,
                        from_address: NameType) -> Result<Action, RoutingError> { unimplemented!() }

    fn handle_cache_put(&mut self,
                        from_authority: routing::types::Authority,
                        from_address: routing::NameType,
                        data: Vec<u8>) -> Result<Action, RoutingError> { unimplemented!() }
}

impl VaultFacade {
   /// Initialise all the personas in the Vault interface.
  pub fn new() -> VaultFacade {
    VaultFacade {
        data_manager: DataManager::new(), maid_manager: MaidManager::new(),
        pmid_manager: PmidManager::new(), pmid_node: PmidNode::new(),
        version_handler: VersionHandler::new(), nodes_in_table: Vec::new(),
    }
  }

}

#[cfg(test)]
 mod test {
    use super::*;
    use data_manager;
    use routing;
    use cbor;
    use maidsafe_types;
    use maid_manager;
    use pmid_manager;
    use maidsafe_types::{PayloadTypeTag, Payload};
    use routing::types:: { Authority, DestinationAddress };
    use routing::NameType;
    use routing::test_utils::Random;
    use routing::node_interface::Interface;
    use routing::sendable::Sendable;

    fn array_as_vector_u8(array : [u8;64]) -> Vec<u8> {
        let mut vec = Vec::with_capacity(array.len());
        for i in array.iter() {
          vec.push(*i);
        }
        vec
    }

    #[test]
    fn put_get_flow() {
        let mut vault = VaultFacade::new();

        let name = NameType([3u8; 64]);
        let value = routing::types::generate_random_vec_u8(1024);
        let data = maidsafe_types::ImmutableData::new(value);
        let payload = Payload::new(PayloadTypeTag::ImmutableData, &data);
        let mut encoder = cbor::Encoder::from_memory();
        let encode_result = encoder.encode(&[&payload]);
        assert_eq!(encode_result.is_ok(), true);

        { // MaidManager, shall allowing the put and SendOn to DataManagers around name
            let from = NameType::new([1u8; 64]);
            // TODO : in this stage, dest can be populated as anything ?
            let dest = DestinationAddress{ dest : NameType::generate_random(), reply_to: None };
            let put_result = vault.handle_put(Authority::ClientManager, Authority::Client, from, dest,
                                             routing::types::array_as_vector(encoder.as_bytes()));
            assert_eq!(put_result.is_err(), false);
            match put_result.ok().unwrap() {
                routing::Action::SendOn(ref x) => {
                    assert_eq!(x.len(), 1);
                    assert_eq!(x[0], data.name());
                }
             routing::Action::Reply(x) => panic!("Unexpected"),
            }
        }
        vault.nodes_in_table = vec![NameType::new([1u8; 64]), NameType::new([2u8; 64]), NameType::new([3u8; 64]), NameType::new([4u8; 64]),
                               NameType::new([5u8; 64]), NameType::new([6u8; 64]), NameType::new([7u8; 64]), NameType::new([8u8; 64])];
        { // DataManager, shall SendOn to pmid_nodes
            let from = NameType::new([1u8; 64]);
            // TODO : in this stage, dest can be populated as anything ?
            let dest = DestinationAddress{ dest : NameType::generate_random(), reply_to: None };
            let put_result = vault.handle_put(Authority::NaeManager, Authority::ClientManager, from, dest,
                                             routing::types::array_as_vector(encoder.as_bytes()));
            assert_eq!(put_result.is_err(), false);
            match put_result.ok().unwrap() {
                routing::Action::SendOn(ref x) => {
                    assert_eq!(x.len(), data_manager::PARALLELISM);
                    //assert_eq!(x[0], NameType([3u8; 64]));
                    //assert_eq!(x[1], NameType([2u8; 64]));
                    //assert_eq!(x[2], NameType([1u8; 64]));
                    //assert_eq!(x[3], NameType([7u8; 64]));
                }
                routing::Action::Reply(x) => panic!("Unexpected"),
            }
            let from = NameType::new([1u8; 64]);
            let get_result = vault.handle_get(payload.get_type_tag() as u64, data.name().clone(), Authority::NaeManager,
                                             Authority::Client, from);
            assert_eq!(get_result.is_err(), false);
            match get_result.ok().unwrap() {
                routing::Action::SendOn(ref x) => {
                    assert_eq!(x.len(), data_manager::PARALLELISM);
                    //assert_eq!(x[0], NameType([3u8; 64]));
                    //assert_eq!(x[1], NameType([2u8; 64]));
                    //assert_eq!(x[2], NameType([1u8; 64]));
                    //assert_eq!(x[3], NameType([7u8; 64]));
                }
                routing::Action::Reply(x) => panic!("Unexpected"),
            }
        }
        { // PmidManager, shall put to pmid_nodes
            let from = NameType::new([3u8; 64]);
            let dest = DestinationAddress{ dest : NameType::new([7u8; 64]), reply_to: None };
            let put_result = vault.handle_put(Authority::NodeManager, Authority::NaeManager, from, dest,
                                         routing::types::array_as_vector(encoder.as_bytes()));
            assert_eq!(put_result.is_err(), false);
            match put_result.ok().unwrap() {
                routing::Action::SendOn(ref x) => {
                    assert_eq!(x.len(), 1);
                    assert_eq!(x[0], NameType([7u8; 64]));
                }
                routing::Action::Reply(x) => panic!("Unexpected"),
            }
        }
        { // PmidNode stores/retrieves data
            let from = NameType::new([7u8; 64]);
            let dest = DestinationAddress{ dest : NameType::new([6u8; 64]), reply_to: None };
            let put_result = vault.handle_put(Authority::ManagedNode, Authority::NodeManager, from.clone(), dest,
                                             routing::types::array_as_vector(encoder.as_bytes()));
            assert_eq!(put_result.is_err(), true);
            match put_result.err().unwrap() {
             routing::RoutingError::Success => { }
             _ => panic!("Unexpected"),
            }
            let from = NameType::new([7u8; 64]);

            let get_result = vault.handle_get(payload.get_type_tag() as u64, data.name().clone(), Authority::ManagedNode,
                                             Authority::NodeManager, from);
            assert_eq!(get_result.is_err(), false);
            match get_result.ok().unwrap() {
                routing::Action::Reply(ref x) => {
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
            routing::Action::SendOn(ref x) => {
                assert_eq!(x.len(), 1);
                assert_eq!(x[0], payload_name);
            }
            routing::Action::Reply(x) => panic!("Unexpected"),
        }
    }

    fn data_manager_put(vault: &mut VaultFacade, from: NameType, dest: DestinationAddress,
                        payload: Vec<u8>) {
        let put_result = vault.handle_put(Authority::NaeManager, Authority::ClientManager, from,
            dest, payload);
        assert_eq!(put_result.is_err(), false);
        match put_result.ok().unwrap() {
            routing::Action::SendOn(ref x) => {
                assert_eq!(x.len(), data_manager::PARALLELISM);
            }
            routing::Action::Reply(x) => panic!("Unexpected"),
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
            routing::Action::SendOn(ref x) => {
                assert_eq!(x.len(), 1);
                assert_eq!(x[0], dest.dest);
            }
            routing::Action::Reply(x) => panic!("Unexpected"),
        }
    }

    fn version_handler_put(vault: &mut VaultFacade, from: NameType, dest: DestinationAddress,
                        payload: Vec<u8>) {
        let put_result = vault.handle_put(Authority::NaeManager, Authority::ManagedNode,
            from.clone(), dest, payload);
        assert_eq!(put_result.is_err(), true);
        match put_result.err().unwrap() {
             routing::RoutingError::Success => { },
             _ => panic!("Unexpected"),
        }
    }

    //#[test]
    //fn churn_test() {
    //    let mut vault = VaultFacade::new();

    //    let mut available_nodes = Vec::with_capacity(30);
    //    for _ in 0..30 {
    //        available_nodes.push(NameType::generate_random());
    //    }

    //    let value = routing::types::generate_random_vec_u8(1024);
    //    let data = maidsafe_types::ImmutableData::new(value);
    //    let payload = Payload::new(PayloadTypeTag::ImmutableData, &data);

    //    let mut encoder = cbor::Encoder::from_memory();
    //    let encode_result = encoder.encode(&[&payload]);
    //    assert_eq!(encode_result.is_ok(), true);

    //    let from = available_nodes[0].clone();
    //    let dest = DestinationAddress{ dest : available_nodes[1].clone(), reply_to: None };
    //    let data_as_vec = routing::types::array_as_vector(encoder.as_bytes());

    //    {// MaidManager - churn handling
    //        maid_manager_put(&mut vault, from.clone(), dest.clone(), data.name().clone(), data_as_vec.clone());
    //        let churn_data = vault.handle_churn(Vec::<NameType>::with_capacity(0));
    //        assert!(churn_data.len() == 1);
    //        assert!(churn_data[0].name() == from);
    //        // MaidManagerAccount
    //        let sendable: GenericSendableType = churn_data[0].clone();
    //        assert_eq!(sendable.name(), from.clone());

    //        let mut decoder = cbor::Decoder::from_bytes(sendable.serialised_contents());
    //        let maid_manager: maid_manager::MaidManagerAccount = decoder.decode().next().unwrap().unwrap();
    //        assert_eq!(maid_manager.get_data_stored(), 1024);

    //        assert!(vault.maid_manager.retrieve_all_and_reset().is_empty());
    //    }

    //    add_nodes_to_table(&mut vault, &available_nodes);

    //    {// DataManager - churn handling
    //        data_manager_put(&mut vault, from.clone(), dest.clone(), data_as_vec.clone());
    //        let mut close_group = Vec::with_capacity(20);
    //        for i in 10..30 {
    //            close_group.push(available_nodes[i].clone());
    //        }
    //
    //        let churn_data = vault.handle_churn(close_group);
    //        assert_eq!(churn_data.len(), 1);
    //        assert!(churn_data[0].name() == data.name().clone());

    //        let sendable: GenericSendableType = churn_data[0].clone();
    //        assert_eq!(sendable.name(), data.name().clone());

    //        let mut decoder = cbor::Decoder::from_bytes(sendable.serialised_contents());
    //        let pmids: Vec<NameType> = decoder.decode().next().unwrap().unwrap();
    //        assert!(pmids.len() >= 3);

    //        assert!(vault.data_manager.retrieve_all_and_reset(&mut Vec::new()).is_empty());
    //    }

    //    {// PmidManager - churn handling
    //        pmid_manager_put(&mut vault, from.clone(), dest.clone(), data_as_vec.clone());
    //        let churn_data = vault.handle_churn(vec![dest.dest.clone()]);
    //        assert_eq!(churn_data.len(), 1);
    //        //assert_eq!(churn_data[0].0, from);

    //        let sendable: GenericSendableType = churn_data[0].clone();
    //        assert_eq!(sendable.name(), dest.dest);

    //        assert!(vault.pmid_manager.retrieve_all_and_reset(&Vec::new()).is_empty());
    //    }

    //    {// VersionHandler - churn handling
    //        let name = NameType::generate_random();
    //        let owner = NameType::generate_random();
    //        let mut vec_name_types = Vec::<NameType>::with_capacity(10);
    //        for i in 0..10 {
    //            vec_name_types.push(NameType::generate_random());
    //        }
    //        let data = maidsafe_types::StructuredData::new(name, owner, vec![vec_name_types.clone()]);
    //        let payload = Payload::new(PayloadTypeTag::StructuredData, &data);

    //        let mut encoder = cbor::Encoder::from_memory();
    //        let encode_result = encoder.encode(&[&payload]);
    //        assert_eq!(encode_result.is_ok(), true);
    //        let data_as_vec = routing::types::array_as_vector(encoder.as_bytes());

    //        version_handler_put(&mut vault, from.clone(), dest.clone(), data_as_vec.clone());
    //        let churn_data = vault.handle_churn(Vec::<NameType>::with_capacity(0));
    //        assert_eq!(churn_data.len(), 1);
    //        assert_eq!(churn_data[0].name(), data.name());

    //        let sendable: GenericSendableType = churn_data[0].clone();
    //        assert_eq!(sendable.name(), data.name());
    //        let mut decoder = cbor::Decoder::from_bytes(sendable.serialised_contents());
    //        let decoded_data: Payload = decoder.decode().next().unwrap().unwrap();
    //        assert_eq!(decoded_data, payload);
    //        assert!(vault.version_handler.retrieve_all_and_reset().is_empty());
    //    }

    //}
}

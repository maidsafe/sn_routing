/*  Copyright 2015 MaidSafe.net limited
    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").
    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses
    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.
    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe
    Software.                                                                 */

#![allow(unused_variables)]
#![deny(missing_docs)]

use routing;
use routing::{Action, RoutingError};
use routing::types::{Authority, DestinationAddress, DhtId};

use data_manager::DataManager;
use maid_manager::MaidManager;
use pmid_manager::PmidManager;
use pmid_node::PmidNode;
use version_handler::VersionHandler;

/// Main struct to hold all personas
pub struct VaultFacade {
  data_manager : DataManager,
  maid_manager : MaidManager,
  pmid_manager : PmidManager,
  pmid_node : PmidNode,
  version_handler : VersionHandler,
  nodes_in_table : Vec<DhtId>
}

impl routing::interface::Interface for VaultFacade {
  fn handle_get(&mut self, type_id: u64, our_authority: Authority, from_authority: Authority,
                from_address: DhtId, data_name: Vec<u8>)->Result<Action, RoutingError> {
    let name = DhtId(data_name);
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

  fn handle_put(&mut self, our_authority: Authority, from_authority: Authority,
                from_address: DhtId, dest_address: DestinationAddress, data: Vec<u8>)->Result<Action, RoutingError> {
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

  fn handle_post(&mut self, our_authority: Authority, from_authority: Authority, from_address: DhtId, data: Vec<u8>)->Result<Action, RoutingError> {
    ;
    Err(RoutingError::InvalidRequest)
  }

  fn handle_get_response(&mut self, from_address: DhtId, response: Result<Vec<u8>, RoutingError>) {
    ;
  }

  fn handle_put_response(&mut self, from_authority: Authority, from_address: DhtId, response: Result<Vec<u8>, RoutingError>) {
    ;
  }

  fn handle_post_response(&mut self, from_authority: Authority, from_address: DhtId, response: Result<Vec<u8>, RoutingError>) {
    ;
  }

  fn add_node(&mut self, node: DhtId) { self.nodes_in_table.push(node); }

  fn drop_node(&mut self, node: DhtId) {
    for index in 0..self.nodes_in_table.len() {
      if self.nodes_in_table[index] == node {
        self.nodes_in_table.remove(index);
        break;
      }
    }
  }
}

impl VaultFacade {
  /// Initialise all the personas in the Vault interface.
  pub fn new() -> VaultFacade {
    VaultFacade { data_manager: DataManager::new(), maid_manager: MaidManager::new(),
                  pmid_manager: PmidManager::new(), pmid_node: PmidNode::new(),
                  version_handler: VersionHandler::new(), nodes_in_table: Vec::new() }
  }
}


#[cfg(test)]
mod test {
  extern crate cbor;
  extern crate maidsafe_types;
  extern crate routing;

  use super::VaultFacade;
  use maidsafe_types::*;
  use routing::types::{Authority, DestinationAddress, DhtId, generate_random_vec_u8};
  use routing::interface::Interface;
  use routing::message_interface::MessageInterface;

  static PARALLELISM: usize = 4;

  #[test]
  fn put_get_flow() {
    let mut vault = VaultFacade::new();

    let value = routing::types::generate_random_vec_u8(1024);
    let data = ImmutableData::new(value);
    let data_name = data.get_name();
    let payload = Payload::new(PayloadTypeTag::ImmutableData, &data);
    let mut encoder = cbor::Encoder::from_memory();
    let encode_result = encoder.encode(&[&payload]);
    assert_eq!(encode_result.is_ok(), true);

    { // MaidManager, shall allowing the put and SendOn to DataManagers around name
      let from = DhtId::new(&[1u8; 64]);
      // TODO : in this stage, dest can be populated as anything ?
      let dest = DestinationAddress{ dest : DhtId::generate_random(), reply_to: None };
      let put_result = vault.handle_put(Authority::ClientManager, Authority::Client,
                                        from, dest, encoder.as_bytes().to_vec());
      assert_eq!(put_result.is_err(), false);
      match put_result.ok().unwrap() {
        routing::Action::SendOn(ref x) => {
          assert_eq!(x.len(), 1);
          assert_eq!(x[0].0, data_name.get_id().to_vec());
        }
        routing::Action::Reply(x) => panic!("Unexpected"),
      }
    }
    let nodes_in_table = vec![DhtId::new(&[1u8; 64]), DhtId::new(&[2u8; 64]), DhtId::new(&[3u8; 64]), DhtId::new(&[4u8; 64]),
                              DhtId::new(&[5u8; 64]), DhtId::new(&[6u8; 64]), DhtId::new(&[7u8; 64]), DhtId::new(&[8u8; 64])];
    for node in nodes_in_table.iter() {
      vault.add_node(node.clone());
    }
    { // DataManager, shall SendOn to pmid_nodes
      let from = DhtId::new(&[1u8; 64]);
      // TODO : in this stage, dest can be populated as anything ?
      let dest = DestinationAddress{ dest : DhtId::generate_random(), reply_to: None };
      let put_result = vault.handle_put(Authority::NaeManager, Authority::ClientManager,
                                        from, dest, encoder.as_bytes().to_vec());
      assert_eq!(put_result.is_err(), false);
      match put_result.ok().unwrap() {
        routing::Action::SendOn(ref x) => {
          assert_eq!(x.len(), PARALLELISM);
          assert_eq!(x[0], vault.nodes_in_table[0]);
          assert_eq!(x[1], vault.nodes_in_table[1]);
          assert_eq!(x[2], vault.nodes_in_table[2]);
          assert_eq!(x[3], vault.nodes_in_table[3]);
        }
        routing::Action::Reply(x) => panic!("Unexpected"),
      }
      let from = DhtId::new(&[1u8; 64]);
      let get_result = vault.handle_get(payload.get_type_tag() as u64, Authority::NaeManager,
                                        Authority::Client, from, data.get_name().0.to_vec());
      assert_eq!(get_result.is_err(), false);
      match get_result.ok().unwrap() {
        routing::Action::SendOn(ref x) => {
          assert_eq!(x.len(), PARALLELISM);
          assert_eq!(x[0], vault.nodes_in_table[0]);
          assert_eq!(x[1], vault.nodes_in_table[1]);
          assert_eq!(x[2], vault.nodes_in_table[2]);
          assert_eq!(x[3], vault.nodes_in_table[3]);
        }
        routing::Action::Reply(x) => panic!("Unexpected"),
      }
    }
    { // PmidManager, shall put to pmid_nodes
      let from = DhtId::new(&[3u8; 64]);
      let dest = DestinationAddress{ dest : DhtId::new(&[7u8; 64]), reply_to: None };
      let put_result = vault.handle_put(Authority::NodeManager, Authority::NaeManager,
                                        from, dest, encoder.as_bytes().to_vec());
      assert_eq!(put_result.is_err(), false);
      match put_result.ok().unwrap() {
        routing::Action::SendOn(ref x) => {
          assert_eq!(x.len(), 1);
          assert_eq!(x[0].0, [7u8; 64].to_vec());
        }
        routing::Action::Reply(x) => panic!("Unexpected"),
      }
    }
    { // PmidNode stores/retrieves data
      let from = DhtId::new(&[7u8; 64]);
      let dest = DestinationAddress{ dest : DhtId::new(&[6u8; 64]), reply_to: None };
      let put_result = vault.handle_put(Authority::ManagedNode, Authority::NodeManager,
                                        from, dest, encoder.as_bytes().to_vec());
      assert_eq!(put_result.is_err(), true);
      match put_result.err().unwrap() {
        routing::RoutingError::Success => { }
        _ => panic!("Unexpected"),
      }
      let from = DhtId::new(&[7u8; 64]);
      let get_result = vault.handle_get(payload.get_type_tag() as u64, Authority::ManagedNode,
                                        Authority::NodeManager, from, data_name.get_id().to_vec());
      assert_eq!(get_result.is_err(), false);
      match get_result.ok().unwrap() {
          routing::Action::Reply(ref x) => {
              let mut d = cbor::Decoder::from_bytes(&x[..]);
              let payload_retrieved: Payload = d.decode().next().unwrap().unwrap();
              assert_eq!(payload_retrieved.get_type_tag(), PayloadTypeTag::ImmutableData);
              let data_retrieved = payload_retrieved.get_data::<maidsafe_types::ImmutableData>();
              assert_eq!(data.get_name().0.to_vec(), data_retrieved.get_name().0.to_vec());
              assert_eq!(data.get_value(), data_retrieved.get_value());
          },
          _ => panic!("Unexpected"),
      }
    }
  }

}

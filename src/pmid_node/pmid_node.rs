// Copyright 2015 MaidSafe.net limited
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe
// Software.

#![allow(dead_code)]

extern crate routing;
extern crate maidsafe_types;

use chunk_store::ChunkStore;

use cbor::{ Decoder};

type CloseGroupDifference = self::routing::types::CloseGroupDifference;
type Address = self::routing::types::Address;

pub struct PmidNode {
  chunk_store_ : ChunkStore
}

impl PmidNode {
  pub fn new() -> PmidNode {
    PmidNode { chunk_store_: ChunkStore::new() }
  }

  pub fn handle_get(&self, name: Vec<u8>) ->Result<routing::Action, routing::RoutingError> {
    let data = self.chunk_store_.get(name);
    if data.len() == 0 {
      return Err(routing::RoutingError::NoData);
    }
    Ok(routing::Action::Reply(data))
  }

  pub fn handle_put(&mut self, data : &Vec<u8>) ->Result<routing::Action, routing::RoutingError> {
    // TODO the data_type shall be passed down or data needs to be name + content
    //      here assuming data is serialised_data of ImmutableData
    let mut d = Decoder::from_bytes(&data[..]);
    let immutable_data: maidsafe_types::ImmutableData = d.decode().next().unwrap().unwrap();
    let data_name = self::routing::types::array_as_vector(&immutable_data.get_name().get_id());
    self.chunk_store_.put(data_name, data.clone());
    return Err(routing::RoutingError::Success);
  }

}
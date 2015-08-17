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

#![allow(dead_code)]

use chunk_store::ChunkStore;
use routing_types::*;
use utils::{encode, decode};

pub struct PmidNode {
    chunk_store_ : ChunkStore
}

impl PmidNode {
    pub fn new() -> PmidNode {
        PmidNode { chunk_store_: ChunkStore::with_max_disk_usage(1073741824), } // TODO adjustable max_disk_space
    }

    pub fn handle_get(&self, name: NameType) ->Result<Vec<MethodCall>, InterfaceError> {
        let data = self.chunk_store_.get(name);
        if data.len() == 0 {
            return Err(From::from(ResponseError::NoData));
        }
        let sd : ImmutableData = try!(decode(&data));
        Ok(vec![MethodCall::Reply { data: Data::ImmutableData(sd) }])
    }

    pub fn handle_put(&mut self, incoming_data : Data) ->Result<Vec<MethodCall>, InterfaceError> {
        let immutable_data = match incoming_data {
            Data::ImmutableData(data) => { data }
            _ => { return Err(From::from(ResponseError::InvalidRequest)); }
        };
        let data = try!(encode(&immutable_data));
        let data_name_and_remove_sacrificial = match *immutable_data.get_type_tag() {
            ImmutableDataType::Normal => (immutable_data.name(), true),
            _ => (immutable_data.name(), false),
        };
        if self.chunk_store_.has_disk_space(data.len()) {
            // the type_tag needs to be stored as well
            self.chunk_store_.put(data_name_and_remove_sacrificial.0, data);
            return Ok(vec![MethodCall::Reply { data: Data::ImmutableData(immutable_data) }]);
        }
        // TODO: keeps removing sacrificial copies till enough space emptied
        //       if all sacrificial copies removed but still can not satisfy, do not restore
        if !data_name_and_remove_sacrificial.1 {
            return Err(From::from(ResponseError::InvalidRequest))
        }
        let required_space = data.len() - (self.chunk_store_.max_disk_usage() - self.chunk_store_.current_disk_usage());
        let names = self.chunk_store_.names();
        for name in names.iter() {
            let fetched_data = self.chunk_store_.get(name.clone());
            let parsed_data : ImmutableData = try!(decode(&fetched_data));
            match *parsed_data.get_type_tag() {
                ImmutableDataType::Sacrificial => {
                    if fetched_data.len() > required_space {
                        self.chunk_store_.delete(name.clone());
                        self.chunk_store_.put(data_name_and_remove_sacrificial.0, data);
                        // TODO: ideally, the InterfaceError shall have an option holding a list of copies
                        return Err(From::from(ResponseError::FailedToStoreData(Data::ImmutableData(immutable_data))));
                    }
                },
                _ => {}
            }
        }
        Err(From::from(ResponseError::InvalidRequest))
    }

}

#[cfg(test)]
mod test {
    use super::*;

    use routing_types::*;

    #[test]
    fn handle_put_get() {
        let mut pmid_node = PmidNode::new();
        let value = generate_random_vec_u8(1024);
        let im_data = ImmutableData::new(ImmutableDataType::Normal, value);
        {
            let put_result = pmid_node.handle_put(Data::ImmutableData(im_data.clone()));
            assert_eq!(put_result.is_ok(), true);
            let mut calls = put_result.ok().unwrap();
            assert_eq!(calls.len(), 1);
            match calls.remove(0) {
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
        {
            let get_result = pmid_node.handle_get(im_data.name());
            assert_eq!(get_result.is_err(), false);
            let mut calls = get_result.ok().unwrap();
            assert_eq!(calls.len(), 1);
            match calls.remove(0) {
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
}

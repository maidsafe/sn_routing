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

pub struct PmidNode {
    chunk_store_ : ChunkStore
}

impl PmidNode {
    pub fn new() -> PmidNode {
        PmidNode { chunk_store_: ChunkStore::with_max_disk_usage(1073741824), } // TODO adjustable max_disk_space
    }

    pub fn handle_get(&self, name: NameType) ->Vec<MethodCall> {
        let data = self.chunk_store_.get(name);
        if data.len() == 0 {
            return vec![];
        }
        let sd: ImmutableData = match ::routing::utils::decode(&data) {
            Ok(data) => data,
            Err(_) => return vec![]
        };
        vec![MethodCall::Reply { data: Data::ImmutableData(sd) }]
    }

    pub fn handle_put(&mut self, pmid_node: NameType,
                      incoming_data: Data) -> Vec<MethodCall> {
        info!("pmid_node {:?} storing {:?}", pmid_node, incoming_data.name());
        let immutable_data = match incoming_data.clone() {
            Data::ImmutableData(data) => { data }
            _ => { return vec![]; }
        };
        let data = match ::routing::utils::encode(&immutable_data) {
            Ok(data) => data,
            Err(_) => return vec![]
        };
        let data_name_and_remove_sacrificial = match *immutable_data.get_type_tag() {
            ImmutableDataType::Normal => (immutable_data.name(), true),
            _ => (immutable_data.name(), false),
        };
        if self.chunk_store_.has_disk_space(data.len()) {
            // the type_tag needs to be stored as well
            self.chunk_store_.put(data_name_and_remove_sacrificial.0, data);
            return vec![];
        }
        if !data_name_and_remove_sacrificial.1 {
            // For sacrifized data, just notify PmidManager to update the account
            // Replication shall not be carried out for it
            return vec![MethodCall::ClearSacrificial { location: Authority::NodeManager(pmid_node),
                                                       name: incoming_data.name(),
                                                       size: incoming_data.payload_size() as u32 }];
        }
        let required_space = data.len() - (self.chunk_store_.max_disk_usage() - self.chunk_store_.current_disk_usage());
        let names = self.chunk_store_.names();
        let mut returned_calls = vec![];
        let mut emptied_space = 0;
        for name in names.iter() {
            let fetched_data = self.chunk_store_.get(name.clone());
            let parsed_data : ImmutableData = match ::routing::utils::decode(&fetched_data) {
                Ok(data) => data,
                Err(_) => return vec![],
            };
            match *parsed_data.get_type_tag() {
                ImmutableDataType::Sacrificial => {
                    emptied_space += fetched_data.len();
                    self.chunk_store_.delete(name.clone());
                    // For sacrifized data, just notify PmidManager to update the account
                    // and DataManager need to adjust its farming rate, replication shall not be carried out for it
                    returned_calls.push(MethodCall::ClearSacrificial {
                            location: Authority::NodeManager(pmid_node.clone()),
                            name: parsed_data.name(),
                            size: parsed_data.payload_size() as u32 });
                    if emptied_space > required_space {
                        self.chunk_store_.put(data_name_and_remove_sacrificial.0, data);
                        return returned_calls;
                    }
                },
                _ => {}
            }
        }
        // Reduplication needs to be carried out
        returned_calls.push(MethodCall::FailedPut { location: Authority::NodeManager(pmid_node),
                                                    data: incoming_data });
        returned_calls
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
            let put_result = pmid_node.handle_put(NameType::new([0u8; 64]),
                                                  Data::ImmutableData(im_data.clone()));
            assert_eq!(put_result.len(), 0);
        }
        {
            let mut get_result = pmid_node.handle_get(im_data.name());
            assert_eq!(get_result.len(), 1);
            match get_result.remove(0) {
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

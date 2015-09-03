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
use transfer_parser::transfer_tags::SD_MANAGER_ACCOUNT_TAG;

pub struct StructuredDataManager {
    // TODO: This is assuming ChunkStore has the ability of handling mutable(SDV) data, and put is overwritable
    // If such assumption becomes in-valid, LruCache or Sqlite based persona specific database shall be used
    chunk_store_ : ChunkStore
}

impl StructuredDataManager {
    pub fn new() -> StructuredDataManager {
        // TODO adjustable max_disk_space
        StructuredDataManager { chunk_store_: ChunkStore::with_max_disk_usage(1073741824) }
    }

    pub fn handle_get(&self, name: NameType) -> Vec<MethodCall> {
        let data = self.chunk_store_.get(name);
        if data.len() == 0 {
            return vec![];
        }
        let sd: StructuredData = match ::routing::utils::decode(&data) {
            Ok(data) => data,
            Err(_) => return vec![]
        };
        vec![MethodCall::Reply { data: Data::StructuredData(sd) }]
    }

    pub fn handle_put(&mut self, structured_data: StructuredData) -> Vec<MethodCall> {
        // TODO: SD using PUT for the first copy, then POST to update and transfer in case of churn
        //       so if the data exists, then the put shall be rejected
        //          if the data does not exist, and the request is not from SDM(i.e. a transfer),
        //              then the post shall be rejected
        //       in addition to above, POST shall check the ownership
        if self.chunk_store_.has_chunk(structured_data.name()) {
            vec![]
        } else {
            if let Ok(serialised_data) = ::routing::utils::encode(&structured_data) {
                self.chunk_store_.put(structured_data.name(), serialised_data);
                vec![MethodCall::Reply { data: Data::StructuredData(structured_data) }]
            } else {
                vec![]
            }
        }
    }

    pub fn handle_post(&mut self, in_coming_data: StructuredData) -> Vec<MethodCall> {
        // TODO: SD using PUT for the first copy, then POST to update and transfer in case of churn
        //       so if the data exists, then the put shall be rejected
        //          if the data does not exist, and the request is not from SDM(i.e. a transfer),
        //              then the post shall be rejected
        //       in addition to above, POST shall check the ownership
        let data = self.chunk_store_.get(in_coming_data.name());
        if data.len() == 0 {
            return vec![MethodCall::InvalidRequest { data: Data::StructuredData(in_coming_data) }];
        }
        if let Ok(mut sd) = ::routing::utils::decode::<StructuredData>(&data) {
            debug!("sd_manager updating {:?} to {:?}", sd, in_coming_data);
            match sd.replace_with_other(in_coming_data.clone()) {
                Ok(_) => {},
                Err(_) => return vec![MethodCall::InvalidRequest { data: Data::StructuredData(in_coming_data) }]
            }
            if let Ok(serialised_data) = ::routing::utils::encode(&sd) {
                self.chunk_store_.put(in_coming_data.name(), serialised_data);
            }
        }
        vec![]
    }

    pub fn handle_account_transfer(&mut self, in_coming_sd: Vec<u8>) {
        let sd : StructuredData = match ::routing::utils::decode(&in_coming_sd) {
            Ok(result) => { result }
            Err(_) => return
        };
        info!("SdManager transferred structured_data {:?} in", sd.name());
        self.chunk_store_.delete(sd.name());
        self.chunk_store_.put(sd.name(), in_coming_sd);
    }

    pub fn retrieve_all_and_reset(&mut self) -> Vec<MethodCall> {
        let names = self.chunk_store_.names();
        let mut actions = Vec::with_capacity(names.len());
        for name in names {
            let data = self.chunk_store_.get(name.clone());
            actions.push(MethodCall::Refresh {
                type_tag: SD_MANAGER_ACCOUNT_TAG,
                from_group: name,
                payload: data
            });
        }
        self.chunk_store_ = ChunkStore::with_max_disk_usage(1073741824);
        actions
    }

}



#[cfg(test)]
mod test {
    use super::*;
    use sodiumoxide::crypto;
    use routing_types::*;

    #[test]
    fn handle_put_get() {
        let mut sd_manager = StructuredDataManager::new();
        let name = NameType([3u8; 64]);
        let value = generate_random_vec_u8(1024);
        let keys = crypto::sign::gen_keypair();
        let sdv = StructuredData::new(0, name, 0, value.clone(), vec![keys.0], vec![], Some(&keys.1)).ok().unwrap();
        {
            let mut put_result = sd_manager.handle_put(sdv.clone());
            assert_eq!(put_result.len(), 1);
            match put_result.remove(0) {
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
        {
            let data_name = NameType::new(sdv.name().0);
            let mut get_result = sd_manager.handle_get(data_name);
            assert_eq!(get_result.len(), 1);
            match get_result.remove(0) {
                MethodCall::Reply { data } => {
                    match data {
                        Data::StructuredData(sd) => {
                            assert_eq!(sd, sdv);
                            assert_eq!(sd.name(), StructuredData::compute_name(0, &NameType([3u8; 64])));
                            assert_eq!(*sd.get_data(), value);
                        }
                        _ => panic!("Unexpected"),
                    }
                }
                _ => panic!("Unexpected"),
            }
        }
    }

    #[test]
    fn handle_post() {
        let mut sd_manager = StructuredDataManager::new();
        let name = NameType([3u8; 64]);
        let value = generate_random_vec_u8(1024);
        let keys = crypto::sign::gen_keypair();
        let sdv = StructuredData::new(0, name, 0, value.clone(), vec![keys.0], vec![], Some(&keys.1)).ok().unwrap();
        { // posting to none existing data
            assert_eq!(sd_manager.handle_post(sdv.clone())[0],
                       MethodCall::InvalidRequest { data: Data::StructuredData(sdv.clone()) });
        }
        {
            let mut put_result = sd_manager.handle_put(sdv.clone());
            assert_eq!(put_result.len(), 1);
            match put_result.remove(0) {
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
        { // incorrect version
            let sdv_new = StructuredData::new(0, name, 3, value.clone(), vec![keys.0], vec![], Some(&keys.1)).ok().unwrap();
            assert_eq!(sd_manager.handle_post(sdv_new.clone())[0],
                       MethodCall::InvalidRequest { data: Data::StructuredData(sdv_new) });
        }
        { // correct version
            let sdv_new = StructuredData::new(0, name, 1, value.clone(), vec![keys.0], vec![], Some(&keys.1)).ok().unwrap();
            assert_eq!(sd_manager.handle_post(sdv_new.clone()).len(), 0);
        }
        let keys2 = crypto::sign::gen_keypair();
        { // update to a new owner, wrong signature
            let sdv_new = StructuredData::new(0, name, 2, value.clone(), vec![keys2.0], vec![keys.0], Some(&keys2.1)).ok().unwrap();
            assert_eq!(sd_manager.handle_post(sdv_new.clone())[0],
                       MethodCall::InvalidRequest { data: Data::StructuredData(sdv_new) });
        }
        { // update to a new owner, correct signature
            let sdv_new = StructuredData::new(0, name, 2, value.clone(), vec![keys2.0], vec![keys.0], Some(&keys.1)).ok().unwrap();
            assert_eq!(sd_manager.handle_post(sdv_new.clone()).len(), 0);
        }
    }

    #[test]
    fn handle_account_transfer() {
        let name = NameType([3u8; 64]);
        let value = generate_random_vec_u8(1024);
        let keys = crypto::sign::gen_keypair();
        let sdv = StructuredData::new(0, name, 0, value, vec![keys.0], vec![], Some(&keys.1)).ok().unwrap();

        let mut sd_manager = StructuredDataManager::new();
        let serialised_data = match ::routing::utils::encode(&sdv) {
            Ok(result) => result,
            Err(_) => panic!("Unexpected"),
        };
        sd_manager.handle_account_transfer(serialised_data);
        assert_eq!(sd_manager.chunk_store_.has_chunk(StructuredData::compute_name(0, &NameType([3u8; 64]))), true);
    }

}

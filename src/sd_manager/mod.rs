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

use chunk_store::ChunkStore;
use types::Refreshable;
pub const ACCOUNT_TAG: u64 = ::transfer_tag::TransferTag::StructuredDataManagerAccount as u64;

pub use ::routing::Authority::NaeManager as Authority;

pub struct StructuredDataManager {
    routing: ::vault::Routing,
    // TODO: This is assuming ChunkStore has the ability of handling mutable(SDV)
    // data, and put is overwritable
    // If such assumption becomes invalid, LruCache or Sqlite based persona specific
    // database shall be used
    chunk_store: ChunkStore,
}

impl StructuredDataManager {
    pub fn new(routing: ::vault::Routing) -> StructuredDataManager {
        // TODO adjustable max_disk_space
        StructuredDataManager { routing: routing, chunk_store: ChunkStore::new(1073741824) }
    }

    pub fn handle_get(&mut self,
                      our_authority: &::routing::Authority,
                      from_authority: &::routing::Authority,
                      data_request: &::routing::data::DataRequest,
                      response_token: &Option<::routing::SignedToken>)
                       -> Option<()> {
        // Check if this is for this persona, and that the Data is StructuredData.
        if !::utils::is_sd_manager_authority_type(&our_authority) {
            return ::utils::NOT_HANDLED;
        }
        let structured_data_name_and_type = match data_request {
            &::routing::data::DataRequest::StructuredData(ref data_name, ref data_type) =>
                (data_name, data_type),
            _ => return ::utils::NOT_HANDLED,
        };

        // Validate from authority.
        if !::utils::is_client_authority_type(&from_authority) {
            warn!("Invalid authority for GET at StructuredDataManager: {:?}", from_authority);
            return ::utils::HANDLED;
        }

        let data = self.chunk_store.get(*structured_data_name_and_type.0);
        if data.len() == 0 {
            warn!("Failed to GET data with name {:?}", structured_data_name_and_type.0);
            return ::utils::HANDLED;
        }
        let decoded: ::routing::structured_data::StructuredData =
                match ::routing::utils::decode(&data) {
            Ok(data) => data,
            Err(_) => {
                warn!("Failed to parse data with name {:?}", structured_data_name_and_type.0);
                return ::utils::HANDLED;
            },
        };
        debug!("As {:?} sending data {:?} to {:?} in response to the original request {:?}",
               our_authority, ::routing::data::Data::StructuredData(decoded.clone()),
               from_authority, data_request);
        self.routing.get_response(our_authority.clone(), from_authority.clone(),
                                  ::routing::data::Data::StructuredData(decoded),
                                  data_request.clone(), response_token.clone());
        ::utils::HANDLED
    }

    pub fn handle_put(&mut self,
                      our_authority: &::routing::Authority,
                      from_authority: &::routing::Authority,
                      data: &::routing::data::Data) -> Option<()> {
        // Check if this is for this persona, and that the Data is StructuredData.
        if !::utils::is_sd_manager_authority_type(&our_authority) {
            return ::utils::NOT_HANDLED;
        }
        let structured_data = match data {
            &::routing::data::Data::StructuredData(ref structured_data) => structured_data,
            _ => return ::utils::NOT_HANDLED,
        };

        // Validate from authority.
        if !::utils::is_maid_manager_authority_type(&from_authority) {
            warn!("Invalid authority for PUT at StructuredDataManager: {:?}", from_authority);
            return ::utils::HANDLED;
        }

        // TODO: SD using PUT for the first copy, then POST to update and transfer in case of churn
        //       so if the data exists, then the put shall be rejected
        //          if the data does not exist, and the request is not from SDM(i.e. a transfer),
        //              then the post shall be rejected
        //       in addition to above, POST shall check the ownership
        if !self.chunk_store.has_chunk(structured_data.name()) {
            if let Ok(serialised_data) = ::routing::utils::encode(&structured_data) {
                self.chunk_store.put(structured_data.name(), serialised_data);
            }
        }
        ::utils::HANDLED
    }

    pub fn handle_post(&mut self,
                       in_coming_data: ::routing::structured_data::StructuredData)
                       -> Vec<::types::MethodCall> {
        // TODO: SD using PUT for the first copy, then POST to update and transfer in case of churn
        //       so if the data exists, then the put shall be rejected
        //          if the data does not exist, and the request is not from SDM(i.e. a transfer),
        //              then the post shall be rejected
        //       in addition to above, POST shall check the ownership
        let data = self.chunk_store.get(in_coming_data.name());
        if data.len() == 0 {
            return vec![::types::MethodCall::InvalidRequest {
                            data: ::routing::data::Data::StructuredData(in_coming_data)
                        }];
        }
        if let Ok(mut sd) =
               ::routing::utils::decode::<::routing::structured_data::StructuredData>(&data) {
            debug!("sd_manager updating {:?} to {:?}", sd, in_coming_data);
            match sd.replace_with_other(in_coming_data.clone()) {
                Ok(_) => {}
                Err(_) => {
                    return vec![::types::MethodCall::InvalidRequest {
                                    data: ::routing::data::Data::StructuredData(in_coming_data)
                                }]
                }
            }
            if let Ok(serialised_data) = ::routing::utils::encode(&sd) {
                self.chunk_store.put(in_coming_data.name(), serialised_data);
            }
        }
        vec![]
    }

    pub fn handle_refresh(&mut self, type_tag: &u64, our_authority: &::routing::Authority,
                          payloads: &Vec<Vec<u8>>) -> Option<()> {
        if *type_tag == ACCOUNT_TAG {
            if let &Authority(from_group) = our_authority {
                if let Some(merged_structured_data) =
                        ::utils::merge::<::routing::structured_data::StructuredData>(
                                from_group, payloads.clone()) {
                    self.handle_account_transfer(merged_structured_data);
                }
            } else {
                warn!("Invalid authority for refresh at StructuredDataManager: {:?}",
                      our_authority);
            }
            ::utils::HANDLED
        } else {
            ::utils::NOT_HANDLED
        }
    }

    fn handle_account_transfer(&mut self,
                               structured_data: ::routing::structured_data::StructuredData) {
        self.chunk_store.delete(structured_data.name());
        self.chunk_store.put(structured_data.name(), structured_data.serialised_contents());
    }

    pub fn handle_churn(&mut self) {
        let names = self.chunk_store.names();
        for name in names {
            let data = self.chunk_store.get(name.clone());
            debug!("SDManager sends out a refresh regarding data {:?}", name);
            self.routing.refresh_request(ACCOUNT_TAG, Authority(name), data);
        }
        self.chunk_store = ChunkStore::new(1073741824);
    }
}

#[cfg(all(test, feature = "use-mock-routing"))]
mod test {
    use cbor;

    use super::*;

    fn env_setup() -> (::routing::Authority, ::vault::Routing, StructuredDataManager,
                       ::routing::Authority, ::routing::structured_data::StructuredData,
                       ::routing::NameType, (::sodiumoxide::crypto::sign::PublicKey,
                                             ::sodiumoxide::crypto::sign::SecretKey)) {
        let routing = ::vault::Routing::new(::std::sync::mpsc::channel().0);
        let sd_manager = StructuredDataManager::new(routing.clone());
        let name = ::routing::NameType([3u8; 64]);
        let value = ::routing::types::generate_random_vec_u8(1024);

        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let sd = ::routing::structured_data::StructuredData::new(0,
                name, 0, value.clone(), vec![keys.0], vec![], Some(&keys.1)).ok().unwrap();
        (Authority(sd.name().clone()), routing, sd_manager,
         ::maid_manager::Authority(::utils::random_name()), sd, name, keys)
    }

    #[test]
    fn handle_put_get() {
        let (our_authority, routing, mut sd_manager, from_authority, sdv, _, _) = env_setup();
        {
            assert_eq!(::utils::HANDLED,
                       sd_manager.handle_put(&our_authority, &from_authority,
                                             &::routing::data::Data::StructuredData(sdv.clone())));
            assert_eq!(0, routing.put_requests_given().len());
            assert_eq!(0, routing.put_responses_given().len());
        }
        {
            let from = ::utils::random_name();
            let keys = ::sodiumoxide::crypto::sign::gen_keypair();
            let client = ::routing::Authority::Client(from, keys.0);

            let request = ::routing::data::DataRequest::StructuredData(sdv.name().clone(), 0);

            assert_eq!(::utils::HANDLED,
                       sd_manager.handle_get(&our_authority, &client, &request, &None));
            let get_responses = routing.get_responses_given();
            assert_eq!(get_responses.len(), 1);
            assert_eq!(get_responses[0].our_authority, our_authority);
            assert_eq!(get_responses[0].location, client);
            assert_eq!(get_responses[0].data, ::routing::data::Data::StructuredData(sdv.clone()));
            assert_eq!(get_responses[0].data_request, request);
            assert_eq!(get_responses[0].response_token, None);
        }
    }

    #[test]
    fn handle_post() {
        let (our_authority, _, mut sd_manager,
             from_authority, sdv, name, keys) = env_setup();
        { // posting to non-existent data
            assert_eq!(sd_manager.handle_post(sdv.clone())[0],
                       ::types::MethodCall::InvalidRequest {
                           data: ::routing::data::Data::StructuredData(sdv.clone())
                       });
        }
        {
            assert_eq!(::utils::HANDLED,
                       sd_manager.handle_put(&our_authority, &from_authority,
                                             &::routing::data::Data::StructuredData(sdv.clone())));
        }
        { // incorrect version
            let sdv_new = ::routing::structured_data::StructuredData::new(0, name, 3,
                sdv.get_data().clone(), vec![keys.0], vec![], Some(&keys.1)).ok().unwrap();
            assert_eq!(sd_manager.handle_post(sdv_new.clone())[0],
                       ::types::MethodCall::InvalidRequest {
                           data: ::routing::data::Data::StructuredData(sdv_new)
                       });
        }
        { // correct version
            let sdv_new = ::routing::structured_data::StructuredData::new(0, name, 1,
                sdv.get_data().clone(), vec![keys.0], vec![], Some(&keys.1)).ok().unwrap();
            assert_eq!(sd_manager.handle_post(sdv_new.clone()).len(), 0);
        }
        let keys2 = ::sodiumoxide::crypto::sign::gen_keypair();
        { // update to a new owner, wrong signature
            let sdv_new = ::routing::structured_data::StructuredData::new(0, name, 2,
                sdv.get_data().clone(), vec![keys2.0], vec![keys.0], Some(&keys2.1)).ok().unwrap();
            assert_eq!(sd_manager.handle_post(sdv_new.clone())[0],
                       ::types::MethodCall::InvalidRequest {
                           data: ::routing::data::Data::StructuredData(sdv_new)
                       });
        }
        { // update to a new owner, correct signature
            let sdv_new = ::routing::structured_data::StructuredData::new(0, name, 2,
                sdv.get_data().clone(), vec![keys2.0], vec![keys.0], Some(&keys.1)).ok().unwrap();
            assert_eq!(sd_manager.handle_post(sdv_new.clone()).len(), 0);
        }
    }

    #[test]
    fn handle_churn_and_account_transfer() {
        let (our_authority, routing, mut sd_manager, from_authority, sdv, _, _) = env_setup();
        assert_eq!(::utils::HANDLED,
                   sd_manager.handle_put(&our_authority, &from_authority,
                                         &::routing::data::Data::StructuredData(sdv.clone())));
        sd_manager.handle_churn();
        let refresh_requests = routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), 1);
        assert_eq!(refresh_requests[0].type_tag, ACCOUNT_TAG);
        assert_eq!(refresh_requests[0].our_authority, our_authority);

        let mut d = cbor::Decoder::from_bytes(&refresh_requests[0].content[..]);
        if let Some(sd_account) = d.decode().next().and_then(|result| result.ok()) {
            sd_manager.handle_account_transfer(sd_account);
        }
        sd_manager.handle_churn();
        let refresh_requests = routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), 2);
        assert_eq!(refresh_requests[0], refresh_requests[1]);

        sd_manager.handle_churn();
        let refresh_requests = routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), 2);
    }
}

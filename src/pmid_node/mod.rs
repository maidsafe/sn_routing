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

pub use routing::Authority::ManagedNode as Authority;

pub struct PmidNode {
    routing: ::vault::Routing,
    chunk_store: ::chunk_store::ChunkStore,
}

impl PmidNode {
    pub fn new(routing: ::vault::Routing) -> PmidNode {
        PmidNode {
            routing: routing,
            // TODO allow adjustable max_disk_space and return meaningful error rather than panic
            // if the ChunkStore creation fails.
            // See https://maidsafe.atlassian.net/browse/MAID-1189
            chunk_store: ::chunk_store::ChunkStore::new(1073741824).unwrap()
        }
    }

    pub fn handle_get(&mut self,
                      our_authority: &::routing::Authority,
                      from_authority: &::routing::Authority,
                      data_request: &::routing::data::DataRequest,
                      response_token: &Option<::routing::SignedToken>)
                      -> Option<()> {
        // Check if this is for this persona.
        if !::utils::is_pmid_node_authority_type(our_authority) {
            return ::utils::NOT_HANDLED;
        }

        // Validate from authority, and that the Data is ImmutableData.
        if !::utils::is_data_manager_authority_type(from_authority) {
            warn!("Invalid authority for GET at PmidNode: {:?}", from_authority);
            return ::utils::HANDLED;
        }
        let immutable_data_name_and_type = match data_request {
            &::routing::data::DataRequest::ImmutableData(ref immutable_data, ref data_type) =>
                (immutable_data, data_type),
            _ => {
                warn!("Invalid data type for GET at PmidNode: {:?}", data_request);
                return ::utils::HANDLED;
            }
        };

        let data = self.chunk_store.get(immutable_data_name_and_type.0);
        if data.len() == 0 {
            warn!("Failed to GET data with name {:?}", immutable_data_name_and_type.0);
            return ::utils::HANDLED;
        }
        let decoded: ::routing::immutable_data::ImmutableData =
            match ::routing::utils::decode(&data) {
                Ok(data) => data,
                Err(_) => {
                    warn!("Failed to parse data with name {:?}", immutable_data_name_and_type.0);
                    return ::utils::HANDLED;
                }
            };
        debug!("As {:?} sending data {:?} to {:?} in response to the original request {:?}",
               our_authority, ::routing::data::Data::ImmutableData(decoded.clone()), from_authority,
               data_request);
        self.routing.get_response(our_authority.clone(),
                                  from_authority.clone(),
                                  ::routing::data::Data::ImmutableData(decoded),
                                  data_request.clone(),
                                  response_token.clone());
        ::utils::HANDLED
    }

    pub fn handle_put(&mut self,
                      our_authority: &::routing::Authority,
                      from_authority: &::routing::Authority,
                      data: &::routing::data::Data,
                      response_token: &Option<::routing::SignedToken>)
                      -> Option<()> {
        // Check if this is for this persona.
        if !::utils::is_pmid_node_authority_type(our_authority) {
            return ::utils::NOT_HANDLED;
        }

        // Validate from authority, and that the Data is ImmutableData.
        if !::utils::is_pmid_manager_authority_type(from_authority) {
            warn!("Invalid authority for PUT at PmidNode: {:?}", from_authority);
            return ::utils::HANDLED;
        }
        let immutable_data = match data {
            &::routing::data::Data::ImmutableData(ref immutable_data) => immutable_data,
            _ => {
                warn!("Invalid data type for PUT at PmidNode: {:?}", data);
                return ::utils::HANDLED;
            }
        };

        // Store the data if we can.
        info!("pmid_node {:?} storing {:?}", our_authority, immutable_data.name());
        let serialised_data = match ::routing::utils::encode(&immutable_data) {
            Ok(data) => data,
            Err(_) => return ::utils::HANDLED,
        };
        if self.chunk_store.has_disk_space(serialised_data.len()) {
            // the type_tag needs to be stored as well
            self.chunk_store.put(&immutable_data.name(), serialised_data);
            return ::utils::HANDLED;
        }

        // If we can't store the data and it's a Backup or Sacrificial copy, just notify PmidManager
        // to update the account - replication shall not be carried out for it.
        if *immutable_data.get_type_tag() != ::routing::immutable_data::ImmutableDataType::Normal {
            self.notify_managers_of_sacrifice(our_authority,
                                              immutable_data.clone(),
                                              response_token);
            return ::utils::HANDLED;
        }

        // If we can't store the data and it's a Normal copy, try to make room for it by clearing
        // out Sacrificial chunks.
        let required_space = serialised_data.len() -
                             (self.chunk_store.max_disk_usage() -
                              self.chunk_store.current_disk_usage());
        let names = self.chunk_store.names();
        let mut emptied_space = 0;
        for name in names.iter() {
            let fetched_data = self.chunk_store.get(name);
            let parsed_data: ::routing::immutable_data::ImmutableData =
                match ::routing::utils::decode(&fetched_data) {
                    Ok(data) => data,
                    Err(_) => {
                        // remove corrupted data
                        self.chunk_store.delete(name);
                        continue
                    }
                };
            match *parsed_data.get_type_tag() {
                ::routing::immutable_data::ImmutableDataType::Sacrificial => {
                    emptied_space += fetched_data.len();
                    self.chunk_store.delete(name);
                    // For sacrificed data, just notify PmidManager to update the account and
                    // DataManager need to adjust its farming rate, replication shall not be carried
                    // out for it.
                    self.notify_managers_of_sacrifice(&our_authority, parsed_data, &response_token);
                    if emptied_space > required_space {
                        self.chunk_store.put(&immutable_data.name(), serialised_data);
                        return ::utils::HANDLED;
                    }
                }
                _ => {}
            }
        }

        // We failed to make room for it - replication needs to be carried out.
        let location = ::pmid_manager::Authority(our_authority.get_location().clone());
        let original_data = ::routing::data::Data::ImmutableData(immutable_data.clone());
        debug!("As {:?} failed in putting data {:?}, responding to {:?}", our_authority,
               original_data, location);
        let error = ::routing::error::ResponseError::FailedRequestForData(original_data);
        self.routing.put_response(our_authority.clone(), location, error, response_token.clone());
        ::utils::HANDLED
    }

    fn notify_managers_of_sacrifice(&self,
                                    our_authority: &::routing::Authority,
                                    data: ::routing::immutable_data::ImmutableData,
                                    response_token: &Option<::routing::SignedToken>) {
        let location = ::pmid_manager::Authority(our_authority.get_location().clone());
        let error =
            ::routing::error::ResponseError::HadToClearSacrificial(data.name(),
                                                                   data.payload_size() as u32);
        debug!("As {:?} sacrificing data {:?} freeing space {:?}, notifying {:?}", our_authority,
               data.name(), data.payload_size(), location);
        self.routing.put_response(our_authority.clone(), location, error, response_token.clone());
    }

    pub fn reset(&mut self, routing: ::vault::Routing) {
        self.routing = routing;
        match ::chunk_store::ChunkStore::new(1073741824) {
            Ok(chunk_store) => self.chunk_store = chunk_store,
            Err(err) => { debug!("Failed to reset pmid_node chunk store {:?}", err); },
        };
    }

    pub fn routing(&self) -> ::vault::Routing {
        self.routing.clone()
    }
}



#[cfg(all(test, feature = "use-mock-routing"))]
mod test {
    use super::*;

    #[test]
    fn handle_put_get() {
        let routing = ::vault::Routing::new(::std::sync::mpsc::channel().0);
        let mut pmid_node = PmidNode::new(routing.clone());

        let us = ::utils::random_name();
        let our_authority = Authority(us.clone());

        let from_authority = ::pmid_manager::Authority(us.clone());

        let value = ::routing::types::generate_random_vec_u8(1024);
        let data = ::routing::immutable_data::ImmutableData::new(
                       ::routing::immutable_data::ImmutableDataType::Normal, value);
        {
            assert_eq!(::utils::HANDLED,
                pmid_node.handle_put(&our_authority, &from_authority,
                                     &::routing::data::Data::ImmutableData(data.clone()), &None));
            assert_eq!(0, routing.put_requests_given().len());
            assert_eq!(0, routing.put_responses_given().len());
        }
        {
            let from = ::utils::random_name();
            let from_authority = ::data_manager::Authority(from.clone());

            let request = ::routing::data::DataRequest::ImmutableData(data.name().clone(),
                              ::routing::immutable_data::ImmutableDataType::Normal);

            assert_eq!(::utils::HANDLED,
                       pmid_node.handle_get(&our_authority, &from_authority, &request, &None));
            let get_responses = routing.get_responses_given();
            assert_eq!(get_responses.len(), 1);
            assert_eq!(get_responses[0].our_authority, our_authority);
            assert_eq!(get_responses[0].location, from_authority);
            assert_eq!(get_responses[0].data, ::routing::data::Data::ImmutableData(data.clone()));
            assert_eq!(get_responses[0].data_request, request);
            assert_eq!(get_responses[0].response_token, None);
        }
    }
}

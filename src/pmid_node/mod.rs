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

use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Data, DataRequest, ImmutableData, ImmutableDataType, RequestContent, RequestMessage, ResponseContent};
use vault::Routing;

pub struct PmidNode {
    chunk_store: ::chunk_store::ChunkStore,
}

impl PmidNode {
    pub fn new() -> PmidNode {
        PmidNode {
            // TODO allow adjustable max_disk_space and return meaningful error rather than panic
            // if the ChunkStore creation fails.
            // See https://maidsafe.atlassian.net/browse/MAID-1189
            chunk_store: ::chunk_store::ChunkStore::new(1073741824).unwrap(),
        }
    }

    pub fn handle_get(&mut self, routing: &Routing, request: &RequestMessage) {
        let data_name = match &request.content {
            &RequestContent::Get(DataRequest::ImmutableData(ref name, _)) => name,
            _ => unreachable!("Error in vault demuxing"),
        };

        let data = self.chunk_store.get(data_name);
        if data.len() == 0 {
            warn!("Failed to GET data with name {:?}", data_name);
            return;
        }
        let decoded = match deserialise::<ImmutableData>(&data) {
            Ok(data) => data,
            Err(_) => {
                warn!("Failed to parse data with name {:?}", data_name);
                return;
            }
        };
        let content = ResponseContent::GetSuccess(Data::ImmutableData(decoded));
        debug!("As {:?} sending data {:?} to {:?}",
               request.dst,
               content,
               request.src);
        let _ = routing.send_get_response(request.dst.clone(), request.src.clone(), content);
    }

    pub fn handle_put(&mut self, routing: &Routing, request: &RequestMessage) {
        let data = match request.content {
            RequestContent::Put(Data::ImmutableData(ref data)) => data.clone(),
            _ => unreachable!("Error in vault demuxing"),
        };
        let data_name = data.name();
        info!("pmid_node {:?} storing {:?}",
              request.dst.get_name(),
              data_name);
        let serialised_data = match serialise(&data) {
            Ok(data) => data,
            Err(_) => return,
        };
        if self.chunk_store.has_disk_space(serialised_data.len()) {
            // the type_tag needs to be stored as well
            self.chunk_store.put(&data_name, serialised_data);
            return;
        }

        // If we can't store the data and it's a Backup or Sacrificial copy, just notify PmidManager
        // to update the account - replication shall not be carried out for it.
        if *data.get_type_tag() != ImmutableDataType::Normal {
            // self.notify_managers_of_sacrifice(our_authority, data, response_token);
            return;
        }

        // If we can't store the data and it's a Normal copy, try to make room for it by clearing
        // out Sacrificial chunks.
        let required_space = serialised_data.len() -
                             (self.chunk_store.max_disk_usage() - self.chunk_store.current_disk_usage());
        let names = self.chunk_store.names();
        let mut emptied_space = 0;
        for name in names.iter() {
            let fetched_data = self.chunk_store.get(name);
            let parsed_data = match deserialise::<ImmutableData>(&fetched_data) {
                Ok(data) => data,
                Err(_) => {
                    // remove corrupted data
                    self.chunk_store.delete(name);
                    continue;
                }
            };
            match *parsed_data.get_type_tag() {
                ImmutableDataType::Sacrificial => {
                    emptied_space += fetched_data.len();
                    self.chunk_store.delete(name);
                    // For sacrificed data, just notify PmidManager to update the account and
                    // DataManager need to adjust its farming rate, replication shall not be carried
                    // out for it.
                    // self.notify_managers_of_sacrifice(&our_authority, parsed_data, &response_token);
                    if emptied_space > required_space {
                        self.chunk_store.put(&data_name, serialised_data);
                        return;
                    }
                }
                _ => {}
            }
        }

        // We failed to make room for it - replication needs to be carried out.
        //        let error = ::routing::error::ResponseError::FailedRequestForData(original_data);
        let src = request.dst.clone();
        let dst = request.src.clone();
        let content = ResponseContent::PutFailure {
            request: request.clone(),
            external_error_indicator: vec![],
        };  // TODO - set proper error value
        debug!("As {:?} sending {:?} to {:?}", src, content, dst);
        let _ = routing.send_put_response(src, dst, content);
    }

    // fn notify_managers_of_sacrifice(&self,
    //                                 our_authority: &::routing::Authority,
    //                                 data: ImmutableData,
    //                                 response_token: &Option<::routing::SignedToken>) {
    //     let location = Authority::NodeManager(our_authority.get_name().clone());
    //     let error =
    //         ::routing::error::ResponseError::HadToClearSacrificial(data.name(),
    //                                                                data.payload_size() as u32);
    //     debug!("As {:?} sacrificing data {:?} freeing space {:?}, notifying {:?}", our_authority,
    //            data.name(), data.payload_size(), location);
    //     self.routing.put_response(our_authority.clone(), location, error, response_token.clone());
    // }

    // pub fn reset(&mut self, routing: &Routing) {
    //     self.routing = routing;
    //     match ::chunk_store::ChunkStore::new(1073741824) {
    //         Ok(chunk_store) => self.chunk_store = chunk_store,
    //         Err(err) => { debug!("Failed to reset pmid_node chunk store {:?}", err); },
    //     };
    // }
}



#[cfg(all(test, feature = "use-mock-routing"))]
mod test {
    use super::*;

    #[test]
    fn handle_put_get() {
        let routing = ::vault::Routing::new(::std::sync::mpsc::channel().0);
        let mut pmid_node = PmidNode::new(routing.clone());

        let us = random();
        let our_authority = Authority(us.clone());

        let from_authority = Authority::NodeManager(us.clone());

        let value = ::routing::types::generate_random_vec_u8(1024);
        let data =
            ImmutableData::new(ImmutableDataType::Normal, value);
        {
            assert_eq!(::utils::HANDLED,
                       pmid_node.handle_put(&our_authority,
                                            &from_authority,
                                            &::routing::data::Data::ImmutableData(data.clone()),
                                            &None));
            assert_eq!(0, routing.put_requests_given().len());
            assert_eq!(0, routing.put_responses_given().len());
        }
        {
            let from = random();
            let from_authority = ::data_manager::Authority(from.clone());

            let request =
                ::routing::data::DataRequest::ImmutableData(data.name().clone(),
                                                            ImmutableDataType::Normal);

            assert_eq!(::utils::HANDLED,
                       pmid_node.handle_get(&our_authority, &from_authority, &request, &None));
            let get_responses = routing.get_responses_given();
            assert_eq!(get_responses.len(), 1);
            assert_eq!(get_responses[0].our_authority, our_authority);
            assert_eq!(get_responses[0].location, from_authority);
            assert_eq!(get_responses[0].data,
                       ::routing::data::Data::ImmutableData(data.clone()));
            assert_eq!(get_responses[0].data_request, request);
            assert_eq!(get_responses[0].response_token, None);
        }
    }
}

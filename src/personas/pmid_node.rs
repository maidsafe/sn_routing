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
use error::InternalError;
use safe_network_common::client_errors::GetError;
use maidsafe_utilities::serialisation;
use routing::{Data, DataRequest, ImmutableData, MessageId, RequestContent, RequestMessage};
use sodiumoxide::crypto::hash::sha512;
use vault::{CHUNK_STORE_PREFIX, RoutingNode};
use xor_name::XorName;

pub struct PmidNode {
    chunk_store: ChunkStore,
}

impl PmidNode {
    pub fn new(capacity: u64) -> Result<PmidNode, InternalError> {
        Ok(PmidNode { chunk_store: try!(ChunkStore::new(CHUNK_STORE_PREFIX, capacity)) })
    }

    pub fn handle_get(&mut self,
                      routing_node: &RoutingNode,
                      request: &RequestMessage)
                      -> Result<(), InternalError> {
        let (data_name, message_id) =
            if let RequestContent::Get(DataRequest::Immutable(ref name, _), ref message_id) =
                   request.content {
                (name, message_id)
            } else {
                unreachable!("Error in vault demuxing")
            };

        if let Ok(data) = self.chunk_store.get(data_name) {
            if let Ok(decoded) = serialisation::deserialise::<ImmutableData>(&data) {
                let immutable_data = Data::Immutable(decoded);
                trace!("As {:?} sending data {:?} to {:?}",
                       request.dst,
                       immutable_data,
                       request.src);
                let _ = routing_node.send_get_success(request.dst.clone(),
                                                      request.src.clone(),
                                                      immutable_data,
                                                      *message_id);
                return Ok(());
            }
        }
        let error = GetError::NoSuchData;
        let external_error_indicator = try!(serialisation::serialise(&error));
        trace!("As {:?} sending get failure of data {} to {:?}",
               request.dst,
               data_name,
               request.src);
        let _ = routing_node.send_get_failure(request.dst.clone(),
                                              request.src.clone(),
                                              request.clone(),
                                              external_error_indicator,
                                              *message_id);
        Ok(())
    }

    pub fn handle_put(&mut self,
                      routing_node: &RoutingNode,
                      request: &RequestMessage)
                      -> Result<(), InternalError> {
        let (data, message_id) = if let RequestContent::Put(Data::Immutable(ref data),
                                                            ref message_id) = request.content {
            (data.clone(), message_id)
        } else {
            unreachable!("Error in vault demuxing")
        };
        let data_name = data.name();
        info!("pmid_node {:?} storing {:?}", request.dst.name(), data_name);
        let serialised_data = try!(serialisation::serialise(&data));
        if self.chunk_store.has_space(serialised_data.len() as u64) {
            if let Ok(_) = self.chunk_store.put(&data_name, &serialised_data) {
                let _ = self.notify_managers_of_success(routing_node,
                                                        &data_name,
                                                        &message_id,
                                                        request);
                return Ok(());
            }
        }

        let src = request.dst.clone();
        let dst = request.src.clone();
        trace!("As {:?} sending Put failure of data {} to {:?} ",
               src,
               data_name,
               dst);
        let _ = routing_node.send_put_failure(src, dst, request.clone(), vec![], *message_id);
        Ok(())
    }

    pub fn handle_churn(&mut self, routing_node: &RoutingNode) {
        // Only retain chunks for which we're still in the close group
        let chunk_names = self.chunk_store.names();
        for chunk_name in chunk_names {
            match routing_node.close_group(chunk_name) {
                Ok(None) => {
                    trace!("No longer a PN for {}", chunk_name);
                    let _ = self.chunk_store.delete(&chunk_name);
                }
                Ok(Some(_)) => (),
                Err(error) => {
                    error!("Failed to get close group: {:?} for {}", error, chunk_name);
                    let _ = self.chunk_store.delete(&chunk_name);
                }
            }
        }
    }

    fn notify_managers_of_success(&mut self,
                                  routing_node: &RoutingNode,
                                  data_name: &XorName,
                                  message_id: &MessageId,
                                  request: &RequestMessage)
                                  -> Result<(), InternalError> {
        let message_hash = sha512::hash(&try!(serialisation::serialise(&request))[..]);
        let src = request.dst.clone();
        let dst = request.src.clone();
        trace!("As {:?} sending put success of data {} to {:?}",
               src,
               data_name,
               dst);
        let _ = routing_node.send_put_success(src, dst, message_hash, *message_id);
        Ok(())
    }

    // fn notify_managers_of_sacrifice(&self,
    //                                 our_authority: &::routing::Authority,
    //                                 data: ImmutableData,
    //                                 response_token: &Option<::routing::SignedToken>) {
    //     let location = Authority::NodeManager(our_authority.name().clone());
    //     let error =
    //         ::routing::error::ResponseError::HadToClearSacrificial(data.name(),
    //                                                                data.payload_size() as u32);
    //     debug!("As {:?} sacrificing data {:?} freeing space {:?}, notifying {:?}", our_authority,
    //            data.name(), data.payload_size(), location);
    //    self.routing.put_response(our_authority.clone(), location, error, response_token.clone());
    // }
}


// #[cfg(all(test, feature = "use-mock-routing"))]
// mod test {
// use super::*;
// use lru_time_cache::LruCache;
// use maidsafe_utilities::serialisation::serialise;
// use rand::random;
// use routing::{Authority, Data, DataRequest, ImmutableData, ImmutableDataType, RequestContent,
// RequestMessage, ResponseContent, ResponseMessage};
// use std::cmp::{max, min, Ordering};
// use std::collections::BTreeSet;
// use time::{Duration, SteadyTime};
// use types::Refreshable;
// use utils::{median, merge, HANDLED, NOT_HANDLED};
// use vault::Routing;
// use xor_name::{XorName, closer_to_target};
//
// #[test]
// fn handle_put_get() {
// let routing = ::vault::Routing::new(::std::sync::mpsc::channel().0);
// let mut pmid_node = PmidNode::new(routing.clone());
//
// let us = random();
// let our_authority = Authority::ManagedNode(us.clone());
//
// let from_authority = Authority::NodeManager(us.clone());
//
// let value = generate_random_vec_u8(1024);
// let data =
// ImmutableData::new(ImmutableDataType::Normal, value);
// {
// assert_eq!(::utils::HANDLED,
// pmid_node.handle_put(&our_authority,
// &from_authority,
// &::routing::data::Data::Immutable(data.clone()),
// &None));
// assert_eq!(0, routing.put_requests_given().len());
// assert_eq!(0, routing.put_responses_given().len());
// }
// {
// let from = random();
// let from_authority = Authority::NaeManager(from.clone());
//
// let request =
// ::routing::data::DataRequest::Immutable(data.name().clone(),
// ImmutableDataType::Normal);
//
// assert_eq!(::utils::HANDLED,
// pmid_node.handle_get(&our_authority, &from_authority, &request, &None));
// let get_responses = routing.get_responses_given();
// assert_eq!(get_responses.len(), 1);
// assert_eq!(get_responses[0].our_authority, our_authority);
// assert_eq!(get_responses[0].location, from_authority);
// assert_eq!(get_responses[0].data,
// ::routing::data::Data::Immutable(data.clone()));
// assert_eq!(get_responses[0].data_request, request);
// assert_eq!(get_responses[0].response_token, None);
// }
// }
// }
//

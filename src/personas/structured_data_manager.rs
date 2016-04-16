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

use std::collections::HashSet;
use std::convert::From;

use chunk_store::ChunkStore;
use error::InternalError;
use maidsafe_utilities::serialisation;
use routing::{Authority, Data, DataRequest, MessageId, RequestContent, RequestMessage,
              StructuredData};
use safe_network_common::client_errors::{MutationError, GetError};
use types::{Refresh, RefreshValue};
use vault::{CHUNK_STORE_PREFIX, RoutingNode};
use xor_name::XorName;

pub struct StructuredDataManager {
    chunk_store: ChunkStore,
}

impl StructuredDataManager {
    pub fn new(capacity: u64) -> Result<StructuredDataManager, InternalError> {
        Ok(StructuredDataManager {
            chunk_store: try!(ChunkStore::new(CHUNK_STORE_PREFIX, capacity)),
        })
    }

    pub fn handle_get(&mut self,
                      routing_node: &RoutingNode,
                      request: &RequestMessage)
                      -> Result<(), InternalError> {
        // TODO - handle type_tag from name too
        let (data_name, message_id) =
            if let RequestContent::Get(ref data_request @ DataRequest::Structured(_, _),
                                       ref message_id) = request.content {
                (data_request.name(), message_id)
            } else {
                unreachable!("Error in vault demuxing")
            };

        if let Ok(data) = self.chunk_store.get(&data_name) {
            if let Ok(decoded) = serialisation::deserialise::<StructuredData>(&data) {
                trace!("As {:?} sending data {:?} to {:?}",
                       request.dst,
                       Data::Structured(decoded.clone()),
                       request.src);
                let _ = routing_node.send_get_success(request.dst.clone(),
                                                      request.src.clone(),
                                                      Data::Structured(decoded),
                                                      *message_id);
                return Ok(());
            }
        }
        trace!("SDM sending get_failure of sd {}", data_name);
        let error = GetError::NoSuchData;
        let external_error_indicator = try!(serialisation::serialise(&error));
        try!(routing_node.send_get_failure(request.dst.clone(),
                                           request.src.clone(),
                                           request.clone(),
                                           external_error_indicator,
                                           message_id.clone()));
        Ok(())
    }

    pub fn handle_put(&mut self,
                      routing_node: &RoutingNode,
                      full_pmid_nodes: &HashSet<XorName>,
                      request: &RequestMessage)
                      -> Result<(), InternalError> {
        let (data, message_id) = if let RequestContent::Put(Data::Structured(ref data),
                                                            ref message_id) = request.content {
            (data, message_id)
        } else {
            unreachable!("Logic error")
        };

        let data_name = data.name();
        let response_src = request.dst.clone();
        let response_dst = request.src.clone();

        if self.chunk_store.has_chunk(&data_name) {
            debug!("Already have SD {:?}", data_name);
            let error = MutationError::DataExists;
            let external_error_indicator = try!(serialisation::serialise(&error));
            trace!("SDM sending PutFailure for data {}", data_name);
            let _ = routing_node.send_put_failure(response_src,
                                                  response_dst,
                                                  request.clone(),
                                                  external_error_indicator,
                                                  *message_id);
            return Err(From::from(error));
        }

        // TODO: Reconsider this. The client manager should check whether the network is full.
        // Check there aren't too many full nodes in the close group to this data
        match try!(routing_node.close_group(data_name)) {
            Some(mut close_group) => {
                close_group.retain(|member| !full_pmid_nodes.contains(member));
                // TODO - Use routing getter `dynamic_quorum_size()` once available
                if close_group.len() < 5 {
                    trace!("Close group for SD {} only has {} non-full PmidNodes",
                           data_name,
                           close_group.len());
                    let error = MutationError::NetworkFull;
                    let external_error_indicator = try!(serialisation::serialise(&error));
                    let _ = routing_node.send_put_failure(response_src,
                                                          response_dst,
                                                          request.clone(),
                                                          external_error_indicator,
                                                          *message_id);
                    return Err(From::from(error));
                }
            }
            None => return Err(InternalError::NotInCloseGroup),
        }

        if let Err(err) = self.chunk_store.put(&data_name, &try!(serialisation::serialise(data))) {
            trace!("SDM failed to store {} in chunkstore: {:?}", data_name, err);
            let error = MutationError::Unknown;
            let external_error_indicator = try!(serialisation::serialise(&error));
            let _ = routing_node.send_put_failure(response_src,
                                                  response_dst,
                                                  request.clone(),
                                                  external_error_indicator,
                                                  *message_id);
            Err(From::from(error))
        } else {
            trace!("SDM sending PutSuccess for data {}", data_name);
            let _ = routing_node.send_put_success(response_src,
                                                  response_dst,
                                                  data_name,
                                                  *message_id);
            self.send_refresh(routing_node, &data_name, MessageId::zero());
            Ok(())
        }
    }

    pub fn handle_post(&mut self,
                       routing_node: &RoutingNode,
                       request: &RequestMessage)
                       -> Result<(), InternalError> {
        let (new_data, message_id) =
            if let RequestContent::Post(Data::Structured(ref structured_data), ref message_id) =
                   request.content {
                (structured_data, message_id)
            } else {
                unreachable!("Error in vault demuxing")
            };

        if let Ok(serialised_data) = self.chunk_store.get(&new_data.name()) {
            if let Ok(mut existing_data) =
                   serialisation::deserialise::<StructuredData>(&serialised_data) {
                if existing_data.replace_with_other(new_data.clone()).is_ok() {
                    if let Ok(serialised_data) = serialisation::serialise(&existing_data) {
                        if let Ok(()) = self.chunk_store
                                            .put(&existing_data.name(), &serialised_data) {
                            trace!("SDM updated {:?} to {:?}", existing_data, new_data);
                            let _ = routing_node.send_post_success(request.dst.clone(),
                                                                   request.src.clone(),
                                                                   new_data.name(),
                                                                   *message_id);
                            self.send_refresh(routing_node, &new_data.name(), MessageId::zero());
                            return Ok(());
                        }
                    }
                }
            }
        }
        trace!("SDM sending post_failure of sd {}", new_data.name());
        try!(routing_node.send_post_failure(request.dst.clone(),
                                            request.src.clone(),
                                            request.clone(),
                                            Vec::new(),
                                            *message_id));
        Ok(())
    }

    /// The structured_data in the delete request must be a valid updating version of the target
    pub fn handle_delete(&mut self,
                         routing_node: &RoutingNode,
                         request: &RequestMessage)
                         -> Result<(), InternalError> {
        let (data, message_id) = if let RequestContent::Delete(Data::Structured(ref data),
                                                               ref message_id) = request.content {
            (data.clone(), message_id)
        } else {
            unreachable!("Error in vault demuxing")
        };

        if let Ok(serialised_data) = self.chunk_store.get(&data.name()) {
            if let Ok(existing_data) =
                   serialisation::deserialise::<StructuredData>(&serialised_data) {
                if existing_data.validate_self_against_successor(&data).is_ok() {
                    // Reducing content to empty to avoid later on put bearing the same name
                    // chunk_store::put() deletes the old data automatically
                    if let Ok(()) = self.chunk_store.put(&data.name(), &[]) {
                        trace!("SDM deleted {:?} with requested new version {:?}",
                               existing_data,
                               data);
                        let _ = routing_node.send_delete_success(request.dst.clone(),
                                                                 request.src.clone(),
                                                                 data.name(),
                                                                 *message_id);
                        // TODO: Send a refresh message.
                        return Ok(());
                    }
                }
            }
        }
        trace!("SDM sending delete_failure of sd {}", data.name());
        try!(routing_node.send_delete_failure(request.dst.clone(),
                                              request.src.clone(),
                                              request.clone(),
                                              Vec::new(),
                                              *message_id));
        Ok(())
    }

    pub fn handle_refresh(&mut self,
                          routing_node: &RoutingNode,
                          structured_data: StructuredData)
                          -> Result<(), InternalError> {
        match routing_node.close_group(structured_data.name()) {
            Ok(None) | Err(_) => return Ok(()),
            Ok(Some(_)) => (),
        }
        if self.chunk_store.has_chunk(&structured_data.name()) {
            if let Ok(serialised_data) = self.chunk_store.get(&structured_data.name()) {
                if let Ok(existing_data) =
                       serialisation::deserialise::<StructuredData>(&serialised_data) {
                    // Make sure we don't 'update' to a lower version due to delayed accumulation.
                    // We do accept any greater version, however, in case we missed some update,
                    // e. g. because an earlier refresh hasn't accumulated yet. The validity of the
                    // new data is not checked here: If the group has reached consensus, a quorum
                    // has already been reached by the nodes that checked it.
                    if existing_data.get_version() < structured_data.get_version() {
                        // chunk_store::put() deletes the old data automatically
                        let serialised_data = try!(serialisation::serialise(&structured_data));
                        return Ok(try!(self.chunk_store
                                           .put(&structured_data.name(), &serialised_data)));
                    }
                }
            }
        } else {
            return Ok(try!(self.chunk_store
                               .put(&structured_data.name(),
                                    &try!(serialisation::serialise(&structured_data)))));
        }
        Ok(())
    }

    pub fn handle_node_added(&mut self, routing_node: &RoutingNode, node_name: &XorName) {
        // Only retain data for which we're still in the close group
        let data_names = self.chunk_store.names();
        for data_name in data_names {
            match routing_node.close_group(data_name) {
                Ok(None) => {
                    trace!("{} added. No longer a SDM for {}", node_name, data_name);
                    let _ = self.chunk_store.delete(&data_name);
                }
                Ok(Some(_)) => {
                    self.send_refresh(routing_node,
                                      &data_name,
                                      MessageId::from_added_node(*node_name))
                }
                Err(error) => {
                    error!("Failed to get close group: {:?} for {}", error, data_name);
                    let _ = self.chunk_store.delete(&data_name);
                }
            }
        }
    }

    pub fn handle_node_lost(&mut self, routing_node: &RoutingNode, node_name: &XorName) {
        for data_name in self.chunk_store.names() {
            self.send_refresh(routing_node,
                              &data_name,
                              MessageId::from_lost_node(*node_name));
        }
    }

    #[cfg(feature = "use-mock-crust")]
    pub fn get_stored_names(&self) -> Vec<XorName> {
        self.chunk_store.names()
    }

    fn send_refresh(&self,
                    routing_node: &RoutingNode,
                    data_name: &XorName,
                    message_id: MessageId) {
        let serialised_data = match self.chunk_store.get(data_name) {
            Ok(data) => data,
            _ => return,
        };

        let structured_data =
            match serialisation::deserialise::<StructuredData>(&serialised_data) {
                Ok(parsed_data) => parsed_data,
                Err(_) => return,
            };

        let src = Authority::NaeManager(*data_name);
        let refresh = Refresh::new(data_name,
                                   RefreshValue::StructuredDataManager(structured_data));
        if let Ok(serialised_refresh) = serialisation::serialise(&refresh) {
            trace!("SDM sending refresh for data {:?}", src.name());
            let _ = routing_node.send_refresh_request(src.clone(),
                                                      src.clone(),
                                                      serialised_refresh,
                                                      message_id);
        }
    }
}



#[cfg(test)]
#[cfg(not(feature="use-mock-crust"))]
mod test {
    use super::*;

    use std::collections::HashSet;
    use std::sync::mpsc;

    use maidsafe_utilities::{log, serialisation};
    use rand::distributions::{IndependentSample, Range};
    use rand::{random, thread_rng};
    use routing::{Authority, Data, DataRequest, MessageId, RequestContent, RequestMessage,
                  ResponseContent, ResponseMessage, StructuredData};
    use safe_network_common::client_errors::{GetError, MutationError};
    use sodiumoxide::crypto::sign::{self, PublicKey, SecretKey};
    use types::{Refresh, RefreshValue};
    use utils;
    use vault::RoutingNode;
    use xor_name::XorName;

    pub struct Environment {
        pub routing: RoutingNode,
        pub structured_data_manager: StructuredDataManager,
    }

    pub struct PutEnvironment {
        pub keys: (PublicKey, SecretKey),
        pub client: Authority,
        pub client_manager: Authority,
        pub sd_data: StructuredData,
        pub message_id: MessageId,
        pub request: RequestMessage,
    }

    pub struct GetEnvironment {
        pub client: Authority,
        pub message_id: MessageId,
        pub request: RequestMessage,
    }

    pub struct PostEnvironment {
        pub keys: (PublicKey, SecretKey),
        pub client: Authority,
        pub sd_data: StructuredData,
        pub message_id: MessageId,
        pub request: RequestMessage,
    }

    pub struct DeleteEnvironment {
        pub keys: (PublicKey, SecretKey),
        pub client: Authority,
        pub sd_data: StructuredData,
        pub message_id: MessageId,
        pub request: RequestMessage,
    }

    impl Environment {
        pub fn new() -> Environment {
            let _ = log::init(true);
            let routing = unwrap_result!(RoutingNode::new(mpsc::channel().0, false));
            Environment {
                routing: routing,
                structured_data_manager: unwrap_result!(StructuredDataManager::new(322_122_546)),
            }
        }

        pub fn get_close_data(&self, keys: (PublicKey, SecretKey)) -> StructuredData {
            loop {
                let identifier = random();
                let structured_data = unwrap_result!(StructuredData::new(0,
                                                       identifier,
                                                       0,
                                                       utils::generate_random_vec_u8(1024),
                                                       vec![keys.0],
                                                       vec![],
                                                       Some(&keys.1)));
                if let Ok(Some(_)) = self.routing.close_group(structured_data.name()) {
                    return structured_data;
                }
            }
        }

        pub fn lose_close_node(&self, target: &XorName) -> XorName {
            if let Ok(Some(close_group)) = self.routing.close_group(*target) {
                let mut rng = thread_rng();
                let range = Range::new(0, close_group.len());
                let our_name = if let Ok(ref name) = self.routing.name() {
                    *name
                } else {
                    unreachable!()
                };
                loop {
                    let index = range.ind_sample(&mut rng);
                    if close_group[index] != our_name {
                        return close_group[index];
                    }
                }
            } else {
                random::<XorName>()
            }
        }

        pub fn put_sd_data(&mut self) -> PutEnvironment {
            let keys = sign::gen_keypair();
            let sd_data = self.get_close_data(keys.clone());
            self.put_existing_sd_data(sd_data, keys)
        }

        pub fn put_existing_sd_data(&mut self,
                                    sd_data: StructuredData,
                                    keys: (PublicKey, SecretKey))
                                    -> PutEnvironment {
            let message_id = MessageId::new();
            let content = RequestContent::Put(Data::Structured(sd_data.clone()), message_id);
            let client = Authority::Client {
                client_key: keys.0,
                peer_id: random(),
                proxy_node_name: random::<XorName>(),
            };
            let client_manager = Authority::ClientManager(utils::client_name(&client));
            let request = RequestMessage {
                src: client_manager.clone(),
                dst: Authority::NaeManager(sd_data.name()),
                content: content.clone(),
            };
            let full_pmid_nodes = HashSet::new();
            let _ = self.structured_data_manager
                        .handle_put(&self.routing, &full_pmid_nodes, &request);
            PutEnvironment {
                keys: keys,
                client: client,
                client_manager: client_manager,
                sd_data: sd_data,
                message_id: message_id,
                request: request,
            }
        }

        pub fn get_sd_data(&mut self, sd_data: StructuredData) -> GetEnvironment {
            let message_id = MessageId::new();
            let content = RequestContent::Get(DataRequest::Structured(*sd_data.get_identifier(),
                                                                      sd_data.get_type_tag()),
                                              message_id);
            let keys = sign::gen_keypair();
            let client = Authority::Client {
                client_key: keys.0,
                peer_id: random(),
                proxy_node_name: random::<XorName>(),
            };
            let request = RequestMessage {
                src: client.clone(),
                dst: Authority::NaeManager(sd_data.name()),
                content: content.clone(),
            };
            let _ = self.structured_data_manager.handle_get(&self.routing, &request);
            GetEnvironment {
                client: client,
                message_id: message_id,
                request: request,
            }
        }

        pub fn post_sd_data(&mut self) -> PostEnvironment {
            let keys = sign::gen_keypair();
            let sd_data = self.get_close_data(keys.clone());
            let client = Authority::Client {
                client_key: keys.0,
                peer_id: random(),
                proxy_node_name: random::<XorName>(),
            };
            self.post_existing_sd_data(sd_data, keys, client)
        }

        pub fn post_existing_sd_data(&mut self,
                                     sd_data: StructuredData,
                                     keys: (PublicKey, SecretKey),
                                     client: Authority)
                                     -> PostEnvironment {
            let message_id = MessageId::new();
            let content = RequestContent::Post(Data::Structured(sd_data.clone()), message_id);
            let request = RequestMessage {
                src: client.clone(),
                dst: Authority::NaeManager(sd_data.name()),
                content: content.clone(),
            };
            let _ = self.structured_data_manager.handle_post(&self.routing, &request);
            PostEnvironment {
                keys: keys,
                client: client,
                sd_data: sd_data,
                message_id: message_id,
                request: request,
            }
        }

        pub fn delete_sd_data(&mut self) -> DeleteEnvironment {
            let keys = sign::gen_keypair();
            let sd_data = self.get_close_data(keys.clone());
            let client = Authority::Client {
                client_key: keys.0,
                peer_id: random(),
                proxy_node_name: random::<XorName>(),
            };
            self.delete_existing_sd_data(sd_data, keys, client)
        }

        pub fn delete_existing_sd_data(&mut self,
                                       sd_data: StructuredData,
                                       keys: (PublicKey, SecretKey),
                                       client: Authority)
                                       -> DeleteEnvironment {
            let message_id = MessageId::new();
            let content = RequestContent::Delete(Data::Structured(sd_data.clone()), message_id);
            let request = RequestMessage {
                src: client.clone(),
                dst: Authority::NaeManager(sd_data.name()),
                content: content.clone(),
            };
            let _ = self.structured_data_manager.handle_delete(&self.routing, &request);
            DeleteEnvironment {
                keys: keys,
                client: client,
                sd_data: sd_data,
                message_id: message_id,
                request: request,
            }
        }

        pub fn get_from_chunkstore(&self, data_name: &XorName) -> Option<StructuredData> {
            if let Ok(data) = self.structured_data_manager.chunk_store.get(data_name) {
                serialisation::deserialise::<StructuredData>(&data).ok()
            } else {
                None
            }
        }
    }

    #[test]
    fn handle_put_get_normal_flow() {
        let mut env = Environment::new();
        let put_env = env.put_sd_data();
        assert_eq!(Some(put_env.sd_data.clone()),
                   env.get_from_chunkstore(&put_env.sd_data.name()));
        assert_eq!(0, env.routing.put_requests_given().len());
        let put_responses = env.routing.put_successes_given();
        assert_eq!(put_responses.len(), 1);
        if let ResponseContent::PutSuccess(name, id) = put_responses[0].content.clone() {
            assert_eq!(put_env.message_id, id);
            assert_eq!(put_env.sd_data.name(), name);
        } else {
            panic!("Received unexpected response {:?}", put_responses[0]);
        }
        assert_eq!(put_env.client_manager, put_responses[0].dst);
        assert_eq!(Authority::NaeManager(put_env.sd_data.name()),
                   put_responses[0].src);

        let get_env = env.get_sd_data(put_env.sd_data.clone());
        let get_responses = env.routing.get_successes_given();
        assert_eq!(get_responses.len(), 1);
        if let ResponseMessage { content: ResponseContent::GetSuccess(response_data, id), .. } =
               get_responses[0].clone() {
            assert_eq!(Data::Structured(put_env.sd_data.clone()), response_data);
            assert_eq!(get_env.message_id, id);
        } else {
            panic!("Received unexpected response {:?}", get_responses[0]);
        }
        assert_eq!(get_responses[0].dst, get_env.client);
    }

    #[test]
    fn handle_put_get_error_flow() {
        // This shows a non-owner can still store the sd_data
        let mut env = Environment::new();
        let keys = sign::gen_keypair();
        let sd_data = env.get_close_data(keys.clone());
        let put_env = env.put_existing_sd_data(sd_data.clone(), keys.clone());
        assert_eq!(env.routing.put_successes_given().len(), 1);

        // Put to the same data
        let put_existing_env = env.put_existing_sd_data(put_env.sd_data.clone(),
                                                        put_env.keys.clone());
        let put_failures = env.routing.put_failures_given();

        assert_eq!(put_failures.len(), 1);
        assert_eq!(put_failures[0].dst, put_existing_env.client_manager);

        if let ResponseContent::PutFailure { ref id, ref request, ref external_error_indicator } =
               put_failures[0].content {
            assert_eq!(*id, put_existing_env.message_id);
            assert_eq!(*request, put_existing_env.request);
            let err = unwrap_result!(
                    serialisation::deserialise::<MutationError>(external_error_indicator));
            match err.clone() {
                MutationError::DataExists => {}
                _ => panic!("received unexpected erro r {:?}", err),
            }
        } else {
            unreachable!()
        }

        // Get non-existing data
        let non_existing_sd_data = env.get_close_data(keys.clone());
        let get_env = env.get_sd_data(non_existing_sd_data.clone());
        assert_eq!(env.routing.get_requests_given().len(), 0);
        assert_eq!(env.routing.get_successes_given().len(), 0);
        let get_failure = env.routing.get_failures_given();
        assert_eq!(get_failure.len(), 1);
        if let ResponseContent::GetFailure { ref external_error_indicator, ref id, .. } =
               get_failure[0].content.clone() {
            assert_eq!(get_env.message_id, *id);
            let parsed_error = unwrap_result!(serialisation::deserialise(external_error_indicator));
            if let GetError::NoSuchData = parsed_error {} else {
                panic!("Received unexpected external_error_indicator with parsed error as {:?}",
                       parsed_error);
            }
        } else {
            panic!("Received unexpected response {:?}", get_failure[0]);
        }
        assert_eq!(get_env.client, get_failure[0].dst);
        assert_eq!(Authority::NaeManager(non_existing_sd_data.name()),
                   get_failure[0].src);
    }

    #[test]
    fn handle_post() {
        let mut env = Environment::new();
        // posting to non-existent data
        let post_env = env.post_sd_data();
        assert_eq!(None, env.get_from_chunkstore(&post_env.sd_data.name()));
        let mut post_failure = env.routing.post_failures_given();
        assert_eq!(post_failure.len(), 1);
        if let ResponseContent::PostFailure { ref external_error_indicator, ref id, .. } =
               post_failure[0].content.clone() {
            assert_eq!(post_env.message_id, *id);
            assert!(external_error_indicator.is_empty());
        } else {
            panic!("Received unexpected response {:?}", post_failure[0]);
        }
        assert_eq!(post_env.client, post_failure[0].dst);
        assert_eq!(Authority::NaeManager(post_env.sd_data.name()),
                   post_failure[0].src);

        // PUT the data
        let put_env = env.put_existing_sd_data(post_env.sd_data.clone(), post_env.keys.clone());
        assert_eq!(env.routing.put_successes_given().len(), 1);

        // incorrect version
        let mut sd_new_bad = unwrap_result!(StructuredData::new(0,
                                                                *put_env.sd_data.get_identifier(),
                                                                3,
                                                                put_env.sd_data
                                                                       .get_data()
                                                                       .clone(),
                                                                vec![put_env.keys.0],
                                                                vec![],
                                                                Some(&put_env.keys.1)));
        let post_incorrect_env = env.post_existing_sd_data(sd_new_bad.clone(),
                                                           put_env.keys.clone(),
                                                           put_env.client.clone());
        post_failure = env.routing.post_failures_given();
        assert_eq!(post_failure.len(), 2);
        if let ResponseContent::PostFailure { ref external_error_indicator, ref id, .. } =
               post_failure[1].content.clone() {
            assert_eq!(post_incorrect_env.message_id, *id);
            assert!(external_error_indicator.is_empty());
        } else {
            panic!("Received unexpected response {:?}", post_failure[1]);
        }
        assert_eq!(post_incorrect_env.client, post_failure[1].dst);
        assert_eq!(Authority::NaeManager(post_incorrect_env.sd_data.name()),
                   post_failure[1].src);
        assert_eq!(Some(put_env.sd_data.clone()),
                   env.get_from_chunkstore(&sd_new_bad.name()));

        // correct version
        let mut sd_new = unwrap_result!(StructuredData::new(0,
                                                            *put_env.sd_data.get_identifier(),
                                                            1,
                                                            put_env.sd_data.get_data().clone(),
                                                            vec![put_env.keys.0],
                                                            vec![],
                                                            Some(&put_env.keys.1)));
        let mut post_correct_env = env.post_existing_sd_data(sd_new.clone(),
                                                             put_env.keys.clone(),
                                                             put_env.client.clone());
        let mut post_success = env.routing.post_successes_given();
        assert_eq!(post_success.len(), 1);
        if let ResponseContent::PostSuccess(name, id) = post_success[0].content.clone() {
            assert_eq!(post_correct_env.message_id, id);
            assert_eq!(sd_new.name(), name);
        } else {
            panic!("Received unexpected response {:?}", post_success[0]);
        }
        assert_eq!(post_correct_env.client, post_success[0].dst);
        assert_eq!(Authority::NaeManager(post_correct_env.sd_data.name()),
                   post_success[0].src);
        assert_eq!(Some(sd_new.clone()),
                   env.get_from_chunkstore(&put_env.sd_data.name()));

        // update to a new owner, wrong signature
        let keys2 = sign::gen_keypair();
        sd_new_bad = unwrap_result!(StructuredData::new(0,
                                                        *put_env.sd_data.get_identifier(),
                                                        2,
                                                        put_env.sd_data.get_data().clone(),
                                                        vec![keys2.0],
                                                        vec![put_env.keys.0],
                                                        Some(&keys2.1)));
        let _ = env.post_existing_sd_data(sd_new_bad.clone(),
                                          put_env.keys.clone(),
                                          put_env.client.clone());
        post_failure = env.routing.post_failures_given();
        assert_eq!(post_failure.len(), 3);
        if let ResponseContent::PostFailure { ref external_error_indicator, .. } = post_failure[2]
                                                                                       .content
                                                                                       .clone() {
            assert!(external_error_indicator.is_empty());
        } else {
            panic!("Received unexpected response {:?}", post_failure[2]);
        }
        assert_eq!(Some(sd_new.clone()),
                   env.get_from_chunkstore(&put_env.sd_data.name()));

        // update to a new owner, correct signature
        sd_new = unwrap_result!(StructuredData::new(0,
                                                    *put_env.sd_data.get_identifier(),
                                                    2,
                                                    put_env.sd_data.get_data().clone(),
                                                    vec![keys2.0],
                                                    vec![put_env.keys.0],
                                                    Some(&put_env.keys.1)));
        post_correct_env = env.post_existing_sd_data(sd_new.clone(),
                                                     put_env.keys.clone(),
                                                     put_env.client.clone());
        post_success = env.routing.post_successes_given();
        assert_eq!(env.routing.post_successes_given().len(), 2);
        if let ResponseContent::PostSuccess(name, id) = post_success[1].content.clone() {
            assert_eq!(post_correct_env.message_id, id);
            assert_eq!(sd_new.name(), name);
        } else {
            panic!("Received unexpected response {:?}", post_success[1]);
        }
        assert_eq!(Some(sd_new.clone()),
                   env.get_from_chunkstore(&put_env.sd_data.name()));
    }

    #[test]
    fn handle_delete() {
        let mut env = Environment::new();
        // posting to non-existent data
        let delete_env = env.delete_sd_data();
        assert_eq!(None, env.get_from_chunkstore(&delete_env.sd_data.name()));
        let mut delete_failure = env.routing.delete_failures_given();
        assert_eq!(delete_failure.len(), 1);
        if let ResponseContent::DeleteFailure { ref external_error_indicator, ref id, .. } =
               delete_failure[0].content.clone() {
            assert_eq!(delete_env.message_id, *id);
            assert!(external_error_indicator.is_empty());
        } else {
            panic!("Received unexpected response {:?}", delete_failure[0]);
        }
        assert_eq!(delete_env.client, delete_failure[0].dst);
        assert_eq!(Authority::NaeManager(delete_env.sd_data.name()),
                   delete_failure[0].src);

        // PUT the data
        let put_env = env.put_existing_sd_data(delete_env.sd_data.clone(), delete_env.keys.clone());
        assert_eq!(env.routing.put_successes_given().len(), 1);

        // incorrect version
        let sd_new_bad = unwrap_result!(StructuredData::new(0,
                                                            *put_env.sd_data.get_identifier(),
                                                            3,
                                                            vec![],
                                                            vec![put_env.keys.0],
                                                            vec![],
                                                            Some(&put_env.keys.1)));
        let _ = env.delete_existing_sd_data(sd_new_bad.clone(),
                                            put_env.keys.clone(),
                                            put_env.client.clone());
        delete_failure = env.routing.delete_failures_given();
        assert_eq!(delete_failure.len(), 2);
        if let ResponseContent::DeleteFailure { ref external_error_indicator, .. } =
               delete_failure[1].content.clone() {
            assert!(external_error_indicator.is_empty());
        } else {
            panic!("Received unexpected response {:?}", delete_failure[1]);
        }
        assert_eq!(Some(put_env.sd_data.clone()),
                   env.get_from_chunkstore(&sd_new_bad.name()));

        // correct version
        let sd_new = unwrap_result!(StructuredData::new(0,
                                                        *put_env.sd_data.get_identifier(),
                                                        1,
                                                        vec![],
                                                        vec![put_env.keys.0],
                                                        vec![],
                                                        Some(&put_env.keys.1)));
        let delete_correct_env = env.delete_existing_sd_data(sd_new.clone(),
                                                             put_env.keys.clone(),
                                                             put_env.client.clone());
        let delete_success = env.routing.delete_successes_given();
        assert_eq!(delete_success.len(), 1);
        if let ResponseContent::DeleteSuccess(name, id) = delete_success[0].content.clone() {
            assert_eq!(delete_correct_env.message_id, id);
            assert_eq!(sd_new.name(), name);
        } else {
            panic!("Received unexpected response {:?}", delete_success[0]);
        }
        assert_eq!(delete_correct_env.client, delete_success[0].dst);
        assert_eq!(Authority::NaeManager(delete_correct_env.sd_data.name()),
                   delete_success[0].src);
        assert_eq!(None, env.get_from_chunkstore(&put_env.sd_data.name()));

        // block put after deletion
        let _ = env.put_existing_sd_data(put_env.sd_data.clone(), put_env.keys.clone());
        assert_eq!(env.routing.put_failures_given().len(), 1);
        assert_eq!(None, env.get_from_chunkstore(&put_env.sd_data.name()));

        // block post after deletion
        let _ = env.post_existing_sd_data(put_env.sd_data.clone(),
                                          put_env.keys.clone(),
                                          put_env.client.clone());
        assert_eq!(env.routing.post_failures_given().len(), 1);
        assert_eq!(None, env.get_from_chunkstore(&put_env.sd_data.name()));

        // block refresh in after deletion
        let _ = env.structured_data_manager.handle_refresh(&env.routing, put_env.sd_data.clone());
        assert_eq!(None, env.get_from_chunkstore(&put_env.sd_data.name()));
    }

    #[test]
    fn handle_churn() {
        let mut env = Environment::new();
        let put_env = env.put_sd_data();
        assert_eq!(env.routing.put_successes_given().len(), 1);

        let lost_node = env.lose_close_node(&put_env.sd_data.name());
        env.routing.remove_node_from_routing_table(&lost_node);
        let _ = env.structured_data_manager.handle_node_lost(&env.routing, &random::<XorName>());

        let refresh_requests = env.routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), 2);
        assert_eq!(refresh_requests[0].src,
                   Authority::NaeManager(put_env.sd_data.name()));
        assert_eq!(refresh_requests[0].dst,
                   Authority::NaeManager(put_env.sd_data.name()));
        assert_eq!(refresh_requests[1].src,
                   Authority::NaeManager(put_env.sd_data.name()));
        assert_eq!(refresh_requests[1].dst,
                   Authority::NaeManager(put_env.sd_data.name()));
        if let RequestContent::Refresh(received_serialised_refresh, _) = refresh_requests[0]
                                                                             .content
                                                                             .clone() {
            let parsed_refresh = unwrap_result!(serialisation::deserialise::<Refresh>(
                    &received_serialised_refresh[..]));
            if let RefreshValue::StructuredDataManager(received_data) = parsed_refresh.value
                                                                                      .clone() {
                assert_eq!(received_data, put_env.sd_data);
            } else {
                panic!("Received unexpected refresh value {:?}", parsed_refresh);
            }
        } else {
            panic!("Received unexpected refresh {:?}", refresh_requests[0]);
        }
    }

    #[test]
    fn handle_refresh() {
        // Refresh a structured_data in
        let mut env = Environment::new();
        let keys = sign::gen_keypair();
        let sd_data = env.get_close_data(keys.clone());
        let _ = env.structured_data_manager.handle_refresh(&env.routing, sd_data.clone());
        assert_eq!(Some(sd_data.clone()),
                   env.get_from_chunkstore(&sd_data.name()));
        // Refresh an incorrect version new structured_data in
        let sd_bad = unwrap_result!(StructuredData::new(0,
                                                        *sd_data.get_identifier(),
                                                        0,
                                                        sd_data.get_data().clone(),
                                                        vec![keys.0],
                                                        vec![],
                                                        Some(&keys.1)));
        let _ = env.structured_data_manager.handle_refresh(&env.routing, sd_bad.clone());
        // Refresh a correct version new structured_data in
        let sd_new = unwrap_result!(StructuredData::new(0,
                                                        *sd_data.get_identifier(),
                                                        3,
                                                        sd_data.get_data().clone(),
                                                        vec![keys.0],
                                                        vec![],
                                                        Some(&keys.1)));
        let _ = env.structured_data_manager.handle_refresh(&env.routing, sd_new.clone());
        assert_eq!(Some(sd_new.clone()),
                   env.get_from_chunkstore(&sd_data.name()));
    }
}

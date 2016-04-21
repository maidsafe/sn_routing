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

use std::convert::From;
use std::fmt::{self, Debug, Formatter};

use chunk_store::ChunkStore;
use error::InternalError;
use maidsafe_utilities::serialisation;
use routing::{Authority, Data, DataIdentifier, MessageId, RequestMessage, StructuredData};
use safe_network_common::client_errors::{MutationError, GetError};
use vault::{CHUNK_STORE_PREFIX, RoutingNode};
use xor_name::XorName;

const MAX_FULL_PERCENT: u64 = 50;

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
struct Refresh(Data);

pub struct DataManager {
    chunk_store: ChunkStore<DataIdentifier, Data>,
    immutable_data_count: u64,
    structured_data_count: u64,
}

impl Debug for DataManager {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter,
               "Data stored - ImmData {} - SD {} - total {} bytes",
               self.immutable_data_count,
               self.structured_data_count,
               self.chunk_store.used_space())
    }
}

impl DataManager {
    pub fn new(capacity: u64) -> Result<DataManager, InternalError> {
        Ok(DataManager {
            chunk_store: try!(ChunkStore::new(CHUNK_STORE_PREFIX, capacity)),
            immutable_data_count: 0,
            structured_data_count: 0,
        })
    }

    pub fn handle_get(&mut self,
                      routing_node: &RoutingNode,
                      request: &RequestMessage,
                      data_id: &DataIdentifier,
                      msg_id: &MessageId)
                      -> Result<(), InternalError> {
        if let Ok(data) = self.chunk_store.get(&data_id) {
            trace!("As {:?} sending data {:?} to {:?}",
                   request.dst,
                   data,
                   request.src);
            let _ = routing_node.send_get_success(request.dst.clone(),
                                                  request.src.clone(),
                                                  data,
                                                  *msg_id);
            return Ok(());
        }
        trace!("DM sending get_failure of {:?}", data_id);
        let error = GetError::NoSuchData;
        let external_error_indicator = try!(serialisation::serialise(&error));
        try!(routing_node.send_get_failure(request.dst.clone(),
                                           request.src.clone(),
                                           request.clone(),
                                           external_error_indicator,
                                           msg_id.clone()));
        Ok(())
    }

    pub fn handle_put(&mut self,
                      routing_node: &RoutingNode,
                      request: &RequestMessage,
                      data: &Data,
                      msg_id: &MessageId)
                      -> Result<(), InternalError> {
        let data_identifier = data.identifier();
        let response_src = request.dst.clone();
        let response_dst = request.src.clone();

        if self.chunk_store.has(&data_identifier) {
            let error = MutationError::DataExists;
            let external_error_indicator = try!(serialisation::serialise(&error));
            trace!("DM sending PutFailure for data {:?}", data_identifier);
            let _ = routing_node.send_put_failure(response_src,
                                                  response_dst,
                                                  request.clone(),
                                                  external_error_indicator,
                                                  *msg_id);
            return Err(From::from(error));
        }

        // Check there aren't too many full nodes in the close group to this data
        if self.chunk_store.used_space() > (self.chunk_store.max_space() / 100) * MAX_FULL_PERCENT {
            let error = MutationError::NetworkFull;
            let external_error_indicator = try!(serialisation::serialise(&error));
            let _ = routing_node.send_put_failure(response_src,
                                                  response_dst,
                                                  request.clone(),
                                                  external_error_indicator,
                                                  *msg_id);
            return Err(From::from(error));
        }

        if let Err(err) = self.chunk_store
                              .put(&data_identifier, data) {
            trace!("DM failed to store {:?} in chunkstore: {:?}",
                   data_identifier,
                   err);
            let error = MutationError::Unknown;
            let external_error_indicator = try!(serialisation::serialise(&error));
            let _ = routing_node.send_put_failure(response_src,
                                                  response_dst,
                                                  request.clone(),
                                                  external_error_indicator,
                                                  *msg_id);
            Err(From::from(error))
        } else {
            match *data {
                Data::Immutable(_) => self.immutable_data_count += 1,
                Data::Structured(_) => self.structured_data_count += 1,
                _ => unreachable!(),
            }
            trace!("DM sending PutSuccess for data {:?}", data_identifier);
            trace!("{:?}", self);
            let _ = routing_node.send_put_success(response_src,
                                                  response_dst,
                                                  data_identifier.clone(),
                                                  *msg_id);
            self.send_refresh(routing_node, &data_identifier, MessageId::zero());
            Ok(())
        }
    }

    // This function is only for SD
    pub fn handle_post(&mut self,
                       routing_node: &RoutingNode,
                       request: &RequestMessage,
                       new_data: &StructuredData,
                       msg_id: &MessageId)
                       -> Result<(), InternalError> {
        if let Ok(Data::Structured(mut data)) = self.chunk_store.get(&new_data.identifier()) {
            if data.replace_with_other(new_data.clone()).is_ok() {
                if let Ok(()) = self.chunk_store
                                    .put(&data.identifier(), &Data::Structured(data.clone())) {
                    trace!("DM updated for: {:?}", data.identifier());
                    trace!("{:?}", self);
                    let _ = routing_node.send_post_success(request.dst.clone(),
                                                           request.src.clone(),
                                                           data.identifier(),
                                                           *msg_id);
                    self.send_refresh(routing_node, &data.identifier(), MessageId::zero());
                    return Ok(());
                }
            }
        }

        trace!("DM sending post_failure {:?}", new_data.identifier());
        Ok(try!(routing_node.send_post_failure(request.dst.clone(),
                                               request.src.clone(),
                                               request.clone(),
                                               try!(serialisation::serialise(&MutationError::InvalidSuccessor)),
                                               *msg_id)))
    }

    /// The structured_data in the delete request must be a valid updating version of the target
    // This function is only for SD
    pub fn handle_delete(&mut self,
                         routing_node: &RoutingNode,
                         request: &RequestMessage,
                         new_data: &StructuredData,
                         msg_id: &MessageId)
                         -> Result<(), InternalError> {
        if let Ok(Data::Structured(data)) = self.chunk_store.get(&new_data.identifier()) {
            if data.validate_self_against_successor(&new_data).is_ok() {
                if let Ok(()) = self.chunk_store.delete(&data.identifier()) {
                    self.structured_data_count -= 1;
                    trace!("DM deleted {:?}", data.identifier());
                    trace!("{:?}", self);
                    let _ = routing_node.send_delete_success(request.dst.clone(),
                                                             request.src.clone(),
                                                             data.identifier(),
                                                             *msg_id);
                    // TODO: Send a refresh message.
                    return Ok(());
                }
            }
        }
        trace!("DM sending delete_failure for {:?}", new_data.identifier());
        try!(routing_node.send_delete_failure(request.dst.clone(),
                                              request.src.clone(),
                                              request.clone(),
                                              try!(serialisation::serialise(&MutationError::InvalidSuccessor)),
                                              *msg_id));
        Ok(())
    }

    pub fn handle_refresh(&mut self,
                          routing_node: &RoutingNode,
                          serialised_msg: &[u8])
                          -> Result<(), InternalError> {
        let Refresh(data) = try!(serialisation::deserialise::<Refresh>(serialised_msg));
        match routing_node.close_group(data.name()) {
            Ok(None) | Err(_) => return Ok(()),
            Ok(Some(_)) => (),
        }
        let new_data = if let Ok(Data::Structured(struct_data)) = self.chunk_store
                                                                      .get(&data.identifier()) {
            // Make sure we don't 'update' to a lower version due to delayed accumulation.
            // We do accept any greater version, however, in case we missed some update,
            // e. g. because an earlier refresh hasn't accumulated yet. The validity of the
            // new data is not checked here: If the group has reached consensus, a quorum
            // has already been reached by the nodes that checked it.
            let new_struct_data = if let Data::Structured(ref sd) = data {
                sd
            } else {
                unreachable!("Logic Error - Investigate !!");
            };
            if struct_data.get_version() >= new_struct_data.get_version() {
                return Ok(());
            }
            false
        } else {
            !self.chunk_store.has(&data.identifier())
        };
        // chunk_store::put() deletes the old data automatically.
        try!(self.chunk_store.put(&data.identifier(), &data));
        if new_data {
            match data {
                Data::Immutable(_) => self.immutable_data_count += 1,
                Data::Structured(_) => self.structured_data_count += 1,
                _ => unreachable!(),
            }
        }
        trace!("{:?}", self);
        Ok(())
    }

    pub fn handle_node_added(&mut self, routing_node: &RoutingNode, node_name: &XorName) {
        // Only retain data for which we're still in the close group.
        let data_ids = self.chunk_store.keys();
        for data_id in data_ids {
            match routing_node.close_group(data_id.name()) {
                Ok(None) => {
                    match data_id {
                        DataIdentifier::Immutable(_) => self.immutable_data_count -= 1,
                        DataIdentifier::Structured(_, _) => self.structured_data_count -= 1,
                        _ => unreachable!(),
                    }
                    trace!("{} added. No longer a DM for {:?}", node_name, data_id);
                    let _ = self.chunk_store.delete(&data_id);
                }
                Ok(Some(_)) => {
                    self.send_refresh(routing_node,
                                      &data_id,
                                      MessageId::from_added_node(*node_name))
                }
                Err(error) => {
                    error!("Failed to get close group: {:?} for {:?}", error, data_id);
                }
            }
        }
    }

    pub fn handle_node_lost(&mut self, routing_node: &RoutingNode, node_name: &XorName) {
        for data_id in self.chunk_store.keys() {
            self.send_refresh(routing_node,
                              &data_id,
                              MessageId::from_lost_node(*node_name));
        }
    }

    #[cfg(feature = "use-mock-crust")]
    pub fn get_stored_names(&self) -> Vec<DataIdentifier> {
        self.chunk_store.keys()
    }

    fn send_refresh(&self,
                    routing_node: &RoutingNode,
                    data_id: &DataIdentifier,
                    msg_id: MessageId) {
        let data = match self.chunk_store.get(data_id) {
            Ok(data) => data,
            _ => return,
        };

        let src = Authority::NaeManager(data_id.name());
        let refresh = Refresh(data);
        if let Ok(serialised_refresh) = serialisation::serialise(&refresh) {
            trace!("DM sending refresh for {:?}", data_id);
            let _ = routing_node.send_refresh_request(src.clone(), src, serialised_refresh, msg_id);
        }
    }
}



#[cfg(test)]
#[cfg(not(feature="use-mock-crust"))]
mod test_sd {
    use super::*;
    use super::Refresh;

    use std::sync::mpsc;

    use maidsafe_utilities::{log, serialisation};
    use rand::distributions::{IndependentSample, Range};
    use rand::{random, thread_rng};
    use routing::{Authority, Data, DataIdentifier, MessageId, RequestContent, RequestMessage,
                  ResponseContent, ResponseMessage, StructuredData};
    use safe_network_common::client_errors::{GetError, MutationError};
    use sodiumoxide::crypto::sign::{self, PublicKey, SecretKey};
    use utils;
    use vault::RoutingNode;
    use xor_name::XorName;

    pub struct Environment {
        pub routing: RoutingNode,
        pub data_manager: DataManager,
    }

    pub struct PutEnvironment {
        pub keys: (PublicKey, SecretKey),
        pub client: Authority,
        pub client_manager: Authority,
        pub sd_data: StructuredData,
        pub msg_id: MessageId,
        pub request: RequestMessage,
    }

    pub struct GetEnvironment {
        pub client: Authority,
        pub msg_id: MessageId,
        pub request: RequestMessage,
    }

    pub struct PostEnvironment {
        pub keys: (PublicKey, SecretKey),
        pub client: Authority,
        pub sd_data: StructuredData,
        pub msg_id: MessageId,
        pub request: RequestMessage,
    }

    pub struct DeleteEnvironment {
        pub keys: (PublicKey, SecretKey),
        pub client: Authority,
        pub sd_data: StructuredData,
        pub msg_id: MessageId,
        pub request: RequestMessage,
    }

    impl Environment {
        pub fn new() -> Environment {
            let _ = log::init(true);
            let routing = unwrap_result!(RoutingNode::new(mpsc::channel().0, false));
            Environment {
                routing: routing,
                data_manager: unwrap_result!(DataManager::new(322_122_546)),
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
            let msg_id = MessageId::new();
            let content = RequestContent::Put(Data::Structured(sd_data.clone()), msg_id);
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
            let data = Data::Structured(sd_data.clone());
            let _ = self.data_manager.handle_put(&self.routing, &request, &data, &msg_id);
            PutEnvironment {
                keys: keys,
                client: client,
                client_manager: client_manager,
                sd_data: sd_data,
                msg_id: msg_id,
                request: request,
            }
        }

        pub fn get_sd_data(&mut self, sd_data: StructuredData) -> GetEnvironment {
            let msg_id = MessageId::new();
            let content =
                RequestContent::Get(DataIdentifier::Structured(*sd_data.get_identifier(),
                                                               sd_data.get_type_tag()),
                                    msg_id);
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
            let data = Data::Structured(sd_data.clone());
            let _ = self.data_manager
                        .handle_get(&self.routing, &request, &data.identifier(), &msg_id);
            GetEnvironment {
                client: client,
                msg_id: msg_id,
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
            let msg_id = MessageId::new();
            let content = RequestContent::Post(Data::Structured(sd_data.clone()), msg_id);
            let request = RequestMessage {
                src: client.clone(),
                dst: Authority::NaeManager(sd_data.name()),
                content: content.clone(),
            };
            let _ = self.data_manager.handle_post(&self.routing, &request, &sd_data, &msg_id);
            PostEnvironment {
                keys: keys,
                client: client,
                sd_data: sd_data,
                msg_id: msg_id,
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
            let msg_id = MessageId::new();
            let content = RequestContent::Delete(Data::Structured(sd_data.clone()), msg_id);
            let request = RequestMessage {
                src: client.clone(),
                dst: Authority::NaeManager(sd_data.name()),
                content: content.clone(),
            };
            let _ = self.data_manager.handle_delete(&self.routing, &request, &sd_data, &msg_id);
            DeleteEnvironment {
                keys: keys,
                client: client,
                sd_data: sd_data,
                msg_id: msg_id,
                request: request,
            }
        }

        pub fn get_from_chunkstore(&self,
                                   data_identifier: &DataIdentifier)
                                   -> Option<StructuredData> {
            if let Ok(data) = self.data_manager.chunk_store.get(data_identifier) {
                if let Data::Structured(sd) = data {
                    return Some(sd);
                }
            }
            None
        }
    }

    #[test]
    fn handle_put_get_normal_flow() {
        let mut env = Environment::new();
        let put_env = env.put_sd_data();
        assert_eq!(Some(put_env.sd_data.clone()),
                   env.get_from_chunkstore(&put_env.sd_data.identifier()));
        assert_eq!(0, env.routing.put_requests_given().len());
        let put_responses = env.routing.put_successes_given();
        assert_eq!(put_responses.len(), 1);
        if let ResponseContent::PutSuccess(identifier, id) = put_responses[0].content.clone() {
            assert_eq!(put_env.msg_id, id);
            assert_eq!(put_env.sd_data.identifier(), identifier);
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
            assert_eq!(get_env.msg_id, id);
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
            assert_eq!(*id, put_existing_env.msg_id);
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
            assert_eq!(get_env.msg_id, *id);
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
        assert_eq!(None,
                   env.get_from_chunkstore(&post_env.sd_data.identifier()));
        let mut post_failure = env.routing.post_failures_given();
        assert_eq!(post_failure.len(), 1);
        if let ResponseContent::PostFailure { ref external_error_indicator, ref id, .. } =
               post_failure[0].content.clone() {
            assert_eq!(post_env.msg_id, *id);
            let parsed_error = unwrap_result!(serialisation::deserialise::<MutationError>(
                    &external_error_indicator[..]));
            assert_eq!(parsed_error, MutationError::InvalidSuccessor);
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
            assert_eq!(post_incorrect_env.msg_id, *id);
            let parsed_error = unwrap_result!(serialisation::deserialise::<MutationError>(
                    &external_error_indicator[..]));
            assert_eq!(parsed_error, MutationError::InvalidSuccessor);
        } else {
            panic!("Received unexpected response {:?}", post_failure[1]);
        }
        assert_eq!(post_incorrect_env.client, post_failure[1].dst);
        assert_eq!(Authority::NaeManager(post_incorrect_env.sd_data.name()),
                   post_failure[1].src);
        assert_eq!(Some(put_env.sd_data.clone()),
                   env.get_from_chunkstore(&sd_new_bad.identifier()));

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
        if let ResponseContent::PostSuccess(identifier, id) = post_success[0].content.clone() {
            assert_eq!(post_correct_env.msg_id, id);
            assert_eq!(sd_new.identifier(), identifier);
        } else {
            panic!("Received unexpected response {:?}", post_success[0]);
        }
        assert_eq!(post_correct_env.client, post_success[0].dst);
        assert_eq!(Authority::NaeManager(post_correct_env.sd_data.name()),
                   post_success[0].src);
        assert_eq!(Some(sd_new.clone()),
                   env.get_from_chunkstore(&put_env.sd_data.identifier()));

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
            let parsed_error = unwrap_result!(serialisation::deserialise::<MutationError>(
                    &external_error_indicator[..]));
            assert_eq!(parsed_error, MutationError::InvalidSuccessor);
        } else {
            panic!("Received unexpected response {:?}", post_failure[2]);
        }
        assert_eq!(Some(sd_new.clone()),
                   env.get_from_chunkstore(&put_env.sd_data.identifier()));

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
        if let ResponseContent::PostSuccess(identifier, id) = post_success[1].content.clone() {
            assert_eq!(post_correct_env.msg_id, id);
            assert_eq!(sd_new.identifier(), identifier);
        } else {
            panic!("Received unexpected response {:?}", post_success[1]);
        }
        assert_eq!(Some(sd_new.clone()),
                   env.get_from_chunkstore(&put_env.sd_data.identifier()));
    }

    #[test]
    fn handle_delete() {
        let mut env = Environment::new();
        // posting to non-existent data
        let delete_env = env.delete_sd_data();
        assert_eq!(None,
                   env.get_from_chunkstore(&delete_env.sd_data.identifier()));
        let mut delete_failure = env.routing.delete_failures_given();
        assert_eq!(delete_failure.len(), 1);
        if let ResponseContent::DeleteFailure { ref external_error_indicator, ref id, .. } =
               delete_failure[0].content.clone() {
            assert_eq!(delete_env.msg_id, *id);
            let parsed_error = unwrap_result!(serialisation::deserialise::<MutationError>(
                    &external_error_indicator[..]));
            assert_eq!(parsed_error, MutationError::InvalidSuccessor);
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
            let parsed_error = unwrap_result!(serialisation::deserialise::<MutationError>(
                    &external_error_indicator[..]));
            assert_eq!(parsed_error, MutationError::InvalidSuccessor);
        } else {
            panic!("Received unexpected response {:?}", delete_failure[1]);
        }
        assert_eq!(Some(put_env.sd_data.clone()),
                   env.get_from_chunkstore(&sd_new_bad.identifier()));

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
        if let ResponseContent::DeleteSuccess(identifier, id) = delete_success[0].content.clone() {
            assert_eq!(delete_correct_env.msg_id, id);
            assert_eq!(sd_new.identifier(), identifier);
        } else {
            panic!("Received unexpected response {:?}", delete_success[0]);
        }
        assert_eq!(delete_correct_env.client, delete_success[0].dst);
        assert_eq!(Authority::NaeManager(delete_correct_env.sd_data.name()),
                   delete_success[0].src);
        assert_eq!(None, env.get_from_chunkstore(&put_env.sd_data.identifier()));

        // allow put after deletion
        let _ = env.put_existing_sd_data(put_env.sd_data.clone(), put_env.keys.clone());
        assert_eq!(Some(put_env.sd_data.clone()),
                   env.get_from_chunkstore(&put_env.sd_data.identifier()));
    }

    #[test]
    fn handle_churn() {
        let mut env = Environment::new();
        let put_env = env.put_sd_data();
        assert_eq!(env.routing.put_successes_given().len(), 1);

        let lost_node = env.lose_close_node(&put_env.sd_data.name());
        env.routing.remove_node_from_routing_table(&lost_node);
        let _ = env.data_manager.handle_node_lost(&env.routing, &random::<XorName>());

        let refresh_requests = env.routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), 2);
        assert_eq!(refresh_requests[0].src,
                   Authority::NaeManager(put_env.sd_data.identifier().name()));
        assert_eq!(refresh_requests[0].dst,
                   Authority::NaeManager(put_env.sd_data.identifier().name()));
        assert_eq!(refresh_requests[1].src,
                   Authority::NaeManager(put_env.sd_data.identifier().name()));
        assert_eq!(refresh_requests[1].dst,
                   Authority::NaeManager(put_env.sd_data.identifier().name()));
        if let RequestContent::Refresh(received_serialised_refresh, _) = refresh_requests[0]
                                                                             .content
                                                                             .clone() {
            let parsed_refresh = unwrap_result!(serialisation::deserialise::<Refresh>(
                    &received_serialised_refresh[..]));
            assert_eq!(parsed_refresh.0, Data::Structured(put_env.sd_data.clone()));
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
        let refresh = Refresh(Data::Structured(sd_data.clone()));
        let value = unwrap_result!(serialisation::serialise(&refresh));
        let _ = env.data_manager.handle_refresh(&env.routing, &value);
        assert_eq!(Some(sd_data.clone()),
                   env.get_from_chunkstore(&sd_data.identifier()));
        // Refresh an incorrect version new structured_data in
        let sd_bad = unwrap_result!(StructuredData::new(0,
                                                        *sd_data.get_identifier(),
                                                        0,
                                                        sd_data.get_data().clone(),
                                                        vec![keys.0],
                                                        vec![],
                                                        Some(&keys.1)));
        let refresh_bad = Refresh(Data::Structured(sd_bad.clone()));
        let value_bad = unwrap_result!(serialisation::serialise(&refresh_bad));
        let _ = env.data_manager.handle_refresh(&env.routing, &value_bad);
        // Refresh a correct version new structured_data in
        let sd_new = unwrap_result!(StructuredData::new(0,
                                                        *sd_data.get_identifier(),
                                                        3,
                                                        sd_data.get_data().clone(),
                                                        vec![keys.0],
                                                        vec![],
                                                        Some(&keys.1)));
        let refresh_new = Refresh(Data::Structured(sd_new.clone()));
        let value_new = unwrap_result!(serialisation::serialise(&refresh_new));
        let _ = env.data_manager.handle_refresh(&env.routing, &value_new);
        assert_eq!(Some(sd_new.clone()),
                   env.get_from_chunkstore(&sd_data.identifier()));
    }
}


#[cfg(test)]
#[cfg_attr(feature="clippy", allow(indexing_slicing))]
#[cfg(not(feature="use-mock-crust"))]
mod test_im {
    use super::*;
    use super::Refresh;

    use std::sync::mpsc;

    use maidsafe_utilities::{log, serialisation};
    use rand::distributions::{IndependentSample, Range};
    use rand::{random, thread_rng};
    use routing::{Authority, Data, DataIdentifier, ImmutableData, MessageId, RequestContent,
                  RequestMessage, ResponseContent, ResponseMessage};
    use safe_network_common::client_errors::GetError;
    use sodiumoxide::crypto::sign;
    use utils::generate_random_vec_u8;
    use vault::RoutingNode;
    use xor_name::XorName;

    struct PutEnvironment {
        pub client_manager: Authority,
        pub im_data: ImmutableData,
        pub message_id: MessageId,
        pub incoming_request: RequestMessage,
    }

    struct GetEnvironment {
        pub client: Authority,
        pub message_id: MessageId,
        pub request: RequestMessage,
    }

    struct Environment {
        pub routing: RoutingNode,
        pub data_manager: DataManager,
    }

    impl Environment {
        pub fn new() -> Environment {
            let _ = log::init(false);
            Environment {
                routing: unwrap_result!(RoutingNode::new(mpsc::channel().0, false)),
                data_manager: unwrap_result!(DataManager::new(322_122_546)),
            }
        }

        pub fn get_close_data(&self) -> ImmutableData {
            loop {
                let im_data = ImmutableData::new(generate_random_vec_u8(1024));
                if let Ok(Some(_)) = self.routing.close_group(im_data.name()) {
                    return im_data;
                }
            }
        }

        // pub fn get_close_node(&self) -> XorName {
        //     loop {
        //         let name = random::<XorName>();
        //         if let Ok(Some(_)) = self.routing.close_group(name) {
        //             return name;
        //         }
        //     }
        // }

        fn lose_close_node(&self, target: &XorName) -> XorName {
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

        pub fn put_im_data(&mut self) -> PutEnvironment {
            let im_data = self.get_close_data();
            let message_id = MessageId::new();
            let content = RequestContent::Put(Data::Immutable(im_data.clone()), message_id);
            let client_manager = Authority::ClientManager(random());
            let client_request = RequestMessage {
                src: client_manager.clone(),
                dst: Authority::NaeManager(im_data.name()),
                content: content.clone(),
            };
            let data = Data::Immutable(im_data.clone());
            unwrap_result!(self.data_manager
                               .handle_put(&self.routing, &client_request, &data, &message_id));

            PutEnvironment {
                client_manager: client_manager,
                im_data: im_data,
                message_id: message_id,
                incoming_request: client_request,
            }
        }

        pub fn get_im_data(&mut self, data_identifier: DataIdentifier) -> GetEnvironment {
            let message_id = MessageId::new();
            let content = RequestContent::Get(data_identifier.clone(), message_id);
            let keys = sign::gen_keypair();
            let from = random();
            let client = Authority::Client {
                client_key: keys.0,
                peer_id: random(),
                proxy_node_name: from,
            };
            let request = RequestMessage {
                src: client.clone(),
                dst: Authority::NaeManager(data_identifier.name()),
                content: content.clone(),
            };

            let _ = self.data_manager
                        .handle_get(&self.routing, &request, &data_identifier, &message_id);
            GetEnvironment {
                client: client,
                message_id: message_id,
                request: request,
            }
        }

        pub fn get_from_chunkstore(&self,
                                   data_identifier: &DataIdentifier)
                                   -> Option<ImmutableData> {
            if let Ok(data) = self.data_manager.chunk_store.get(data_identifier) {
                if let Data::Immutable(im_data) = data {
                    return Some(im_data);
                }
            }
            None
        }
    }

    #[test]
    fn handle_put() {
        let mut env = Environment::new();
        let put_env = env.put_im_data();

        assert_eq!(Some(put_env.im_data.clone()),
                   env.get_from_chunkstore(&put_env.im_data.identifier()));

        let put_successes = env.routing.put_successes_given();
        assert_eq!(put_successes.len(), 1);
        if let ResponseContent::PutSuccess(identifier, id) = put_successes[0].content.clone() {
            assert_eq!(put_env.message_id, id);
            assert_eq!(put_env.im_data.identifier(), identifier);
        } else {
            panic!("Received unexpected response {:?}", put_successes[0]);
        }
        assert_eq!(put_env.client_manager, put_successes[0].dst);
        assert_eq!(Authority::NaeManager(put_env.im_data.name()),
                   put_successes[0].src);
    }

    #[test]
    fn get_non_existing_data() {
        let mut env = Environment::new();
        let im_data = env.get_close_data();
        let get_env = env.get_im_data(im_data.identifier());
        assert!(env.routing.get_requests_given().is_empty());
        assert!(env.routing.get_successes_given().is_empty());
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
        assert_eq!(Authority::NaeManager(im_data.name()), get_failure[0].src);
    }

    #[test]
    fn get_existing_data() {
        let mut env = Environment::new();
        let put_env = env.put_im_data();

        let get_env = env.get_im_data(put_env.im_data.identifier());
        let get_responses = env.routing.get_successes_given();
        assert_eq!(get_responses.len(), 1);
        if let ResponseMessage { content: ResponseContent::GetSuccess(response_data, id), .. } =
               get_responses[0].clone() {
            assert_eq!(Data::Immutable(put_env.im_data.clone()), response_data);
            assert_eq!(get_env.message_id, id);
        } else {
            panic!("Received unexpected response {:?}", get_responses[0]);
        }
        assert_eq!(get_responses[0].dst, get_env.client);
    }

    #[test]
    fn handle_churn() {
        let mut env = Environment::new();
        let put_env = env.put_im_data();
        assert_eq!(env.routing.put_successes_given().len(), 1);

        let lost_node = env.lose_close_node(&put_env.im_data.name());
        env.routing.remove_node_from_routing_table(&lost_node);
        env.data_manager.handle_node_lost(&env.routing, &random::<XorName>());

        let refresh_requests = env.routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), 2);
        assert_eq!(refresh_requests[0].src,
                   Authority::NaeManager(put_env.im_data.identifier().name()));
        assert_eq!(refresh_requests[0].dst,
                   Authority::NaeManager(put_env.im_data.identifier().name()));
        assert_eq!(refresh_requests[1].src,
                   Authority::NaeManager(put_env.im_data.identifier().name()));
        assert_eq!(refresh_requests[1].dst,
                   Authority::NaeManager(put_env.im_data.identifier().name()));
        if let RequestContent::Refresh(received_serialised_refresh, _) = refresh_requests[0]
                                                                             .content
                                                                             .clone() {
            let parsed_refresh = unwrap_result!(serialisation::deserialise::<Refresh>(
                    &received_serialised_refresh[..]));
            assert_eq!(parsed_refresh.0, Data::Immutable(put_env.im_data.clone()));
        } else {
            panic!("Received unexpected refresh {:?}", refresh_requests[0]);
        }
    }

    #[test]
    fn handle_refresh() {
        let mut env = Environment::new();
        let im_data = env.get_close_data();
        let refresh = Refresh(Data::Immutable(im_data.clone()));
        let value = unwrap_result!(serialisation::serialise(&refresh));
        let _ = env.data_manager.handle_refresh(&env.routing, &value);
        assert_eq!(Some(im_data.clone()),
                   env.get_from_chunkstore(&im_data.identifier()));
    }

}

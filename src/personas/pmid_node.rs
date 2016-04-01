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
        let external_error_indicator = try!(serialisation::serialise(&Vec::<u8>::new()));
        let _ = routing_node.send_put_failure(src, dst, request.clone(), external_error_indicator, *message_id);
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

    #[cfg(feature = "use-mock-crust")]
    pub fn get_stored_names(&self) -> Vec<XorName> {
        self.chunk_store.names()
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


#[cfg(all(test, feature = "use-mock-routing"))]
mod test {
    use super::*;
    use safe_network_common::client_errors::GetError;
    use maidsafe_utilities::serialisation;
    use rand::random;
    use routing::{Authority, Data, DataRequest, ImmutableData, ImmutableDataType, MessageId, RequestContent,
                  RequestMessage, ResponseContent};
    use sodiumoxide::crypto::hash::sha512;
    use std::sync::mpsc;
    use utils::generate_random_vec_u8;
    use vault::RoutingNode;
    use xor_name::XorName;

    struct Environment {
        our_authority: Authority,
        from_authority: Authority,
        routing: RoutingNode,
        pmid_node: PmidNode,
    }

    fn environment_setup(capacity: u64) -> Environment {
        let mut name = random::<XorName>();
        let routing = unwrap_result!(RoutingNode::new(mpsc::channel().0));
        let pmid_node = unwrap_result!(PmidNode::new(capacity));

        loop {
            if let Ok(Some(_)) = routing.close_group(name) {
                break;
            }
            else {
                name = random::<XorName>();
            }
        }

        Environment {
            our_authority: Authority::ManagedNode(name.clone()),
            from_authority: Authority::NodeManager(name.clone()),
            routing: routing,
            pmid_node: pmid_node,
        }
    }

    fn get_close_node(env: &Environment) -> XorName {
        let mut name = random::<XorName>();

        loop {
            if let Ok(Some(_)) = env.routing.close_group(name) {
                return name;
            } else {
                name = random::<XorName>();
            }
        }
    }

    #[test]
    fn put_to_capacity() {
        let mut capacity = 0;
        let value = generate_random_vec_u8(128);
        let immutable_data = ImmutableData::new(ImmutableDataType::Normal, value);
        if let Ok(serialised_data) = serialisation::serialise(&immutable_data) {
            capacity = serialised_data.len() as u64;
        };
        let mut env = environment_setup(capacity);
        let message_id = MessageId::new();
        let request_msg = RequestMessage {
            src: env.from_authority.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(Data::Immutable(immutable_data), message_id),
        };

        assert!(env.pmid_node.handle_put(&env.routing, &request_msg).is_ok());

        let put_failures = env.routing.put_failures_given();

        assert!(put_failures.is_empty());

        let put_successes = env.routing.put_successes_given();

        assert_eq!(put_successes.len(), 1);
        assert_eq!(put_successes[0].src, env.our_authority);
        assert_eq!(put_successes[0].dst, env.from_authority);

        if let ResponseContent::PutSuccess(ref digest, ref id) = put_successes[0].content {
            if let Ok(serialised_request) = serialisation::serialise(&request_msg) {
                assert_eq!(*digest, sha512::hash(&serialised_request[..]));
            }
            assert_eq!(*id, message_id);
        } else {
            unreachable!()
        }
    }

    #[test]
    fn put_past_capacity() {
        let mut capacity = 0;
        let value = generate_random_vec_u8(128);
        let immutable_data = ImmutableData::new(ImmutableDataType::Normal, value);
        if let Ok(serialised_data) = serialisation::serialise(&immutable_data) {
            capacity = serialised_data.len() as u64 - 1;
        };
        let mut env = environment_setup(capacity);
        let message_id = MessageId::new();
        let request_msg = RequestMessage {
            src: env.from_authority.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(Data::Immutable(immutable_data), message_id),
        };

        assert!(env.pmid_node.handle_put(&env.routing, &request_msg).is_ok());

        let put_successes = env.routing.put_successes_given();

        assert!(put_successes.is_empty());

        let put_failures = env.routing.put_failures_given();

        assert_eq!(put_failures.len(), 1);
        assert_eq!(put_failures[0].src, env.our_authority);
        assert_eq!(put_failures[0].dst, env.from_authority);

        if let ResponseContent::PutFailure{ ref id, ref request, ref external_error_indicator } =
               put_failures[0].content {
            assert_eq!(*id, message_id);
            assert_eq!(*request, request_msg);

            if let Ok(error_indicator) = serialisation::serialise(&Vec::<u8>::new()) {
                assert_eq!(*external_error_indicator, error_indicator);
            } else {
                unreachable!()
            }
        } else {
            unreachable!()
        }
    }

    #[test]
    fn get_for_existing_data() {
        let mut capacity = 0;
        let value = generate_random_vec_u8(128);
        let immutable_data = ImmutableData::new(ImmutableDataType::Normal, value);
        if let Ok(serialised_data) = serialisation::serialise(&immutable_data) {
            capacity = serialised_data.len() as u64;
        };
        let mut env = environment_setup(capacity);
        let message_id = MessageId::new();
        let request_msg = RequestMessage {
            src: env.from_authority.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(Data::Immutable(immutable_data.clone()), message_id),
        };

        assert!(env.pmid_node.handle_put(&env.routing, &request_msg).is_ok());

        let put_failures = env.routing.put_failures_given();

        assert!(put_failures.is_empty());

        let put_successes = env.routing.put_successes_given();

        assert_eq!(put_successes.len(), 1);
        assert_eq!(put_successes[0].src, env.our_authority);
        assert_eq!(put_successes[0].dst, env.from_authority);

        if let ResponseContent::PutSuccess(ref digest, ref id) = put_successes[0].content {
            if let Ok(serialised_request) = serialisation::serialise(&request_msg) {
                assert_eq!(*digest, sha512::hash(&serialised_request[..]));
            }
            assert_eq!(*id, message_id);
        } else {
            unreachable!()
        }

        let message_id = MessageId::new();
        let name = if let Authority::ManagedNode(name) = env.our_authority { name } else {
            unreachable!()
        };
        let request_msg = RequestMessage {
            src: Authority::NaeManager(name),
            dst: env.our_authority.clone(),
            content: RequestContent::Get(DataRequest::Immutable(immutable_data.name().clone(),
                                                                ImmutableDataType::Normal),
                                         message_id),
        };

        assert!(env.pmid_node.handle_get(&env.routing, &request_msg).is_ok());

        let get_failures = env.routing.get_failures_given();

        assert!(get_failures.is_empty());

        let get_successes = env.routing.get_successes_given();

        assert_eq!(get_successes.len(), 1);
        assert_eq!(get_successes[0].src, env.our_authority);
        assert_eq!(get_successes[0].dst, Authority::NaeManager(name));

        if let ResponseContent::GetSuccess(ref data, ref id) = get_successes[0].content  {
            assert_eq!(*data, Data::Immutable(immutable_data));
            assert_eq!(*id, message_id);
        } else {
            unreachable!()
        }
    }

    #[test]
    fn get_for_non_existing_data() {
        let mut capacity = 0;
        let value = generate_random_vec_u8(128);
        let immutable_data = ImmutableData::new(ImmutableDataType::Normal, value);
        if let Ok(serialised_data) = serialisation::serialise(&immutable_data) {
            capacity = serialised_data.len() as u64;
        };
        let mut env = environment_setup(capacity);

        let message_id = MessageId::new();
        let name = if let Authority::ManagedNode(name) = env.our_authority { name } else {
            unreachable!()
        };
        let request_msg = RequestMessage {
            src: Authority::NaeManager(name),
            dst: env.our_authority.clone(),
            content: RequestContent::Get(DataRequest::Immutable(immutable_data.name().clone(),
                                                                ImmutableDataType::Normal),
                                         message_id),
        };

        assert!(env.pmid_node.handle_get(&env.routing, &request_msg).is_ok());

        let get_successes = env.routing.get_successes_given();

        assert!(get_successes.is_empty());

        let get_failures = env.routing.get_failures_given();

        assert_eq!(get_failures.len(), 1);
        assert_eq!(get_failures[0].src, env.our_authority);
        assert_eq!(get_failures[0].dst, Authority::NaeManager(name));

        if let ResponseContent::GetFailure{ ref id, ref request, ref external_error_indicator } =
               get_failures[0].content {
            assert_eq!(*id, message_id);
            assert_eq!(*request, request_msg);
            let error = unwrap_result!(serialisation::deserialise(external_error_indicator));
            if let GetError::NoSuchData = error {} else { unreachable!() }
        } else {
            unreachable!()
        }
    }

    #[test]
    fn churn() {
        let mut capacity = 0;
        let value = generate_random_vec_u8(128);
        let immutable_data = ImmutableData::new(ImmutableDataType::Normal, value);
        if let Ok(serialised_data) = serialisation::serialise(&immutable_data) {
            capacity = serialised_data.len() as u64;
        };
        let mut env = environment_setup(capacity);
        let message_id = MessageId::new();
        let request_msg = RequestMessage {
            src: env.from_authority.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(Data::Immutable(immutable_data.clone()), message_id),
        };

        assert!(env.pmid_node.handle_put(&env.routing, &request_msg).is_ok());

        let put_failures = env.routing.put_failures_given();

        assert!(put_failures.is_empty());

        let put_successes = env.routing.put_successes_given();

        assert_eq!(put_successes.len(), 1);
        assert_eq!(put_successes[0].src, env.our_authority);
        assert_eq!(put_successes[0].dst, env.from_authority);

        if let ResponseContent::PutSuccess(ref digest, ref id) = put_successes[0].content {
            if let Ok(serialised_request) = serialisation::serialise(&request_msg) {
                assert_eq!(*digest, sha512::hash(&serialised_request[..]));
            }
            assert_eq!(*id, message_id);
        } else {
            unreachable!()
        }

        let name = get_close_node(&env);

        env.routing.node_added_event(name);
        env.pmid_node.handle_churn(&env.routing);

        let message_id = MessageId::new();
        let name = if let Authority::ManagedNode(name) = env.our_authority { name } else {
            unreachable!()
        };
        let request_msg = RequestMessage {
            src: Authority::NaeManager(name),
            dst: env.our_authority.clone(),
            content: RequestContent::Get(DataRequest::Immutable(immutable_data.name().clone(),
                                                                ImmutableDataType::Normal),
                                         message_id),
        };

        assert!(env.pmid_node.handle_get(&env.routing, &request_msg).is_ok());

        if let Ok(Some(_)) = env.routing.close_group(immutable_data.name().clone()) {
            let get_failures = env.routing.get_failures_given();

            assert!(get_failures.is_empty());

            let get_successes = env.routing.get_successes_given();

            assert_eq!(get_successes.len(), 1);
            assert_eq!(get_successes[0].src, env.our_authority);
            assert_eq!(get_successes[0].dst, Authority::NaeManager(name));

            if let ResponseContent::GetSuccess(ref data, ref id) = get_successes[0].content  {
                assert_eq!(*data, Data::Immutable(immutable_data));
                assert_eq!(*id, message_id);
            } else {
                unreachable!()
            }
        } else {
            let get_successes = env.routing.get_successes_given();

            assert!(get_successes.is_empty());

            let get_failures = env.routing.get_failures_given();

            assert_eq!(get_failures.len(), 1);
            assert_eq!(get_failures[0].src, env.our_authority);
            assert_eq!(get_failures[0].dst, Authority::NaeManager(name));

            if let ResponseContent::GetFailure{ ref id, ref request, ref external_error_indicator } =
                   get_failures[0].content {
                assert_eq!(*id, message_id);
                assert_eq!(*request, request_msg);
                let error = unwrap_result!(serialisation::deserialise(external_error_indicator));
                if let GetError::NoSuchData = error {} else { unreachable!() }
            } else {
                unreachable!()
            }
        }
    }
}

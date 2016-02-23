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

use error::{ClientError, InternalError};
use lru_time_cache::LruCache;
use maidsafe_utilities::serialisation;
use routing::{Authority, Data, MessageId, RequestContent, RequestMessage};
use sodiumoxide::crypto::hash::sha512;
use std::collections::HashMap;
use time::Duration;
use types::{Refresh, RefreshValue};
use utils;
use vault::RoutingNode;
use xor_name::XorName;

const DEFAULT_ACCOUNT_SIZE: u64 = 1_073_741_824;  // 1 GB
const DEFAULT_PAYMENT: u64 = 1_048_576;  // 1 MB

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct Account {
    data_stored: u64,
    space_available: u64,
}

impl Default for Account {
    fn default() -> Account {
        Account {
            data_stored: 0,
            space_available: DEFAULT_ACCOUNT_SIZE,
        }
    }
}

impl Account {
    fn put_data(&mut self, size: u64) -> Result<(), ClientError> {
        if size > self.space_available {
            return Err(ClientError::LowBalance);
        }
        self.data_stored += size;
        self.space_available -= size;
        Ok(())
    }

    fn delete_data(&mut self, size: u64) {
        if self.data_stored < size {
            self.space_available += self.data_stored;
            self.data_stored = 0;
        } else {
            self.data_stored -= size;
            self.space_available += size;
        }
    }
}



pub struct MaidManager {
    accounts: HashMap<XorName, Account>,
    request_cache: LruCache<MessageId, RequestMessage>,
}

impl MaidManager {
    pub fn new() -> MaidManager {
        MaidManager {
            accounts: HashMap::new(),
            request_cache: LruCache::with_expiry_duration_and_capacity(Duration::minutes(5), 1000),
        }
    }

    pub fn handle_put(&mut self,
                      routing_node: &RoutingNode,
                      request: &RequestMessage)
                      -> Result<(), InternalError> {
        match request.content {
            RequestContent::Put(Data::Immutable(_), _) => {
                self.handle_put_immutable_data(routing_node, request)
            }
            RequestContent::Put(Data::Structured(_), _) => {
                self.handle_put_structured_data(routing_node, request)
            }
            _ => unreachable!("Error in vault demuxing"),
        }
    }

    pub fn handle_put_success(&mut self,
                              routing_node: &RoutingNode,
                              message_id: &MessageId)
                              -> Result<(), InternalError> {
        match self.request_cache.remove(message_id) {
            Some(client_request) => {
                // Send success response back to client
                let message_hash =
                    sha512::hash(&try!(serialisation::serialise(&client_request))[..]);
                let src = client_request.dst;
                let dst = client_request.src;
                let _ = routing_node.send_put_success(src, dst, message_hash, message_id.clone());
                Ok(())
            }
            None => Err(InternalError::FailedToFindCachedRequest(message_id.clone())),
        }
    }

    pub fn handle_put_failure(&mut self,
                              routing_node: &RoutingNode,
                              message_id: &MessageId,
                              external_error_indicator: &Vec<u8>)
                              -> Result<(), InternalError> {
        match self.request_cache.remove(message_id) {
            Some(client_request) => {
                // Refund account
                match self.accounts.get_mut(client_request.dst.name()) {
                    Some(account) => {
                        account.delete_data(DEFAULT_PAYMENT /* data.payload_size() as u64 */)
                    }
                    None => return Ok(()),
                }

                // Send failure response back to client
                let error =
                    try!(serialisation::deserialise::<ClientError>(external_error_indicator));
                self.reply_with_put_failure(routing_node,
                                            client_request,
                                            message_id.clone(),
                                            &error)
            }
            None => Err(InternalError::FailedToFindCachedRequest(message_id.clone())),
        }
    }

    pub fn handle_refresh(&mut self, name: XorName, account: Account) {
        let _ = self.accounts.insert(name, account);
    }

    pub fn handle_churn(&mut self, routing_node: &RoutingNode) {
        for (maid_name, account) in self.accounts.iter() {
            let src = Authority::ClientManager(maid_name.clone());
            let refresh = Refresh::new(maid_name, RefreshValue::MaidManagerAccount(account.clone()));
            if let Ok(serialised_refresh) = serialisation::serialise(&refresh) {
                debug!("MaidManager sending refresh for account {:?}", src.name());
                let _ = routing_node.send_refresh_request(src, serialised_refresh);
            }
        }
    }

    fn handle_put_immutable_data(&mut self,
                                 routing_node: &RoutingNode,
                                 request: &RequestMessage)
                                 -> Result<(), InternalError> {
        // Take a hash of the message anticipating sending this as a success response to the client.
        let message_hash = sha512::hash(&try!(serialisation::serialise(request))[..]);

        let (data, message_id) = match request.content {
            RequestContent::Put(Data::Immutable(ref data), ref message_id) => {
                (Data::Immutable(data.clone()), message_id.clone())
            }
            _ => unreachable!("Logic error"),
        };

        // Account must already exist to Put ImmutableData.  If so, then try to add the data to the
        // account
        let client_name = utils::client_name(&request.src);
        let result = self.accounts
                         .get_mut(&client_name)
                         .ok_or(ClientError::NoSuchAccount)
                         .and_then(|account| {
                             account.put_data(DEFAULT_PAYMENT /* data.payload_size() as u64 */)
                         });
        if let Err(error) = result {
            try!(self.reply_with_put_failure(routing_node, request.clone(), message_id, &error));
            return Err(InternalError::Client(error));
        }

        {
            // Send data on to NAE Manager
            let src = request.dst.clone();
            let dst = Authority::NaeManager(data.name());
            let _ = routing_node.send_put_request(src, dst, data.clone(), message_id.clone());
        }

        // Send success response back to client but log client request in case SD Put fails at SDMs
        let src = request.dst.clone();
        let dst = request.src.clone();
        let _ = routing_node.send_put_success(src, dst, message_hash, message_id);
        Ok(())
    }

    fn handle_put_structured_data(&mut self,
                                  routing_node: &RoutingNode,
                                  request: &RequestMessage)
                                  -> Result<(), InternalError> {
        let (data, type_tag, message_id) = match request.content {
            RequestContent::Put(Data::Structured(ref data), ref message_id) => {
                (Data::Structured(data.clone()),
                 data.get_type_tag(),
                 message_id.clone())
            }
            _ => unreachable!("Logic error"),
        };

        // If the type_tag is 0, the account must not exist, else it must exist.
        let client_name = utils::client_name(&request.src);
        if type_tag == 0 {
            if self.accounts.contains_key(&client_name) {
                let error = ClientError::AccountExists;
                try!(self.reply_with_put_failure(routing_node,
                                                 request.clone(),
                                                 message_id,
                                                 &error));
                return Err(InternalError::Client(error));
            }

            // Create the account
            let _ = self.accounts.insert(client_name, Account::default());
        } else {
            // Update the account
            let result = self.accounts
                             .get_mut(&client_name)
                             .ok_or(ClientError::NoSuchAccount)
                             .and_then(|account| {
                                 account.put_data(DEFAULT_PAYMENT /* data.payload_size() as u64 */)
                             });
            if let Err(error) = result {
                try!(self.reply_with_put_failure(routing_node,
                                                 request.clone(),
                                                 message_id,
                                                 &error));
                return Err(InternalError::Client(error));
            }
        };

        {
            // Send data on to NAE Manager
            let src = request.dst.clone();
            let dst = Authority::NaeManager(data.name());
            let _ = routing_node.send_put_request(src, dst, data.clone(), message_id.clone());
        }

        if let Some(prior_request) = self.request_cache
                                         .insert(message_id.clone(), request.clone()) {
            error!("Overwrote existing cached request: {:?}", prior_request);
        }
        Ok(())
    }

    fn reply_with_put_failure(&self,
                              routing_node: &RoutingNode,
                              request: RequestMessage,
                              message_id: MessageId,
                              error: &ClientError)
                              -> Result<(), InternalError> {
        let src = request.dst.clone();
        let dst = request.src.clone();
        let external_error_indicator = try!(serialisation::serialise(error));
        let _ = routing_node.send_put_failure(src,
                                              dst,
                                              request,
                                              external_error_indicator,
                                              message_id);
        Ok(())
    }
}


#[cfg(all(test, feature = "use-mock-routing"))]
mod test {
    use super::*;
    use error::{ClientError, InternalError};
    use maidsafe_utilities::serialisation;
    use rand::random;
    use routing::{Authority, Data, ImmutableData, ImmutableDataType, MessageId, RequestContent,
                  RequestMessage, ResponseContent};
    use sodiumoxide::crypto::sign;
    use std::sync::mpsc;
    use utils::generate_random_vec_u8;
    use vault::RoutingNode;
    use xor_name::XorName;

    struct Environment {
        our_authority: Authority,
        client: Authority,
        routing: RoutingNode,
        maid_manager: MaidManager,
    }

    fn environment_setup() -> Environment {
        let from = random::<XorName>();
        let keys = sign::gen_keypair();
        Environment {
            our_authority: Authority::ClientManager(from.clone()),
            client: Authority::Client {
                client_key: keys.0,
                proxy_node_name: from.clone(),
            },
            routing: unwrap_result!(RoutingNode::new(mpsc::channel().0)),
            maid_manager: MaidManager::new(),
        }
    }

    #[test]
    fn handle_put_without_account() {
        let mut env = environment_setup();

        // Try with valid ImmutableData before account is created
        let immutable_data = ImmutableData::new(ImmutableDataType::Normal,
                                                generate_random_vec_u8(1024));
        let message_id = MessageId::new();
        let valid_request = RequestMessage {
            src: env.client.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(Data::Immutable(immutable_data), message_id.clone()),
        };

        match env.maid_manager.handle_put(&env.routing, &valid_request) {
            Err(InternalError::Client(ClientError::NoSuchAccount)) => (),
            _ => unreachable!(),
        }
        let put_requests = env.routing.put_requests_given();
        assert!(put_requests.is_empty());
        let put_failures = env.routing.put_failures_given();
        assert_eq!(put_failures.len(), 1);
        assert_eq!(put_failures[0].src, env.our_authority);
        assert_eq!(put_failures[0].dst, env.client);
        match &put_failures[0].content {
            &ResponseContent::PutFailure{ ref id, ref request, ref external_error_indicator } => {
                assert_eq!(*id, message_id);
                assert_eq!(*request, valid_request);
                match unwrap_result!(serialisation::deserialise::<ClientError>(external_error_indicator)) {
                    ClientError::NoSuchAccount => (),
                    _ => unreachable!(),
                }

            }
            _ => unreachable!(),
        }

        // assert_eq!(::utils::HANDLED,
        //            maid_manager.handle_put(&our_authority,
        //                                    &client,
        //                                    &::routing::data::Data::Immutable(data.clone()),
        //                                    &None));
        // let put_requests = routing.put_requests_given();
        // assert_eq!(put_requests.len(), 1);
        // assert_eq!(put_requests[0].our_authority, our_authority);
        // assert_eq!(put_requests[0].location, Authority::NaeManager(data.name()));
        // assert_eq!(put_requests[0].data, Data::Immutable(data));
    }

    // #[test]
    // fn handle_churn_and_account_transfer() {
    //     let churn_node = random();
    //     let (our_authority, routing, mut maid_manager, client, data) = env_setup();
    //     assert_eq!(::utils::HANDLED,
    //                maid_manager.handle_put(&our_authority,
    //                                        &client,
    //                                        &::routing::data::Data::Immutable(data.clone()),
    //                                        &None));
    //     maid_manager.handle_churn(&churn_node);
    //     let refresh_requests = routing.refresh_requests_given();
    //     assert_eq!(refresh_requests.len(), 1);
    //     assert_eq!(refresh_requests[0].type_tag, ACCOUNT_TAG);
    //     assert_eq!(refresh_requests[0].our_authority.name(),
    //                client.name());

    //     let mut d = ::cbor::Decoder::from_bytes(&refresh_requests[0].content[..]);
    //     if let Some(mm_account) = d.decode().next().and_then(|result| result.ok()) {
    //         maid_manager.database.handle_account_transfer(mm_account);
    //     }
    //     maid_manager.handle_churn(&churn_node);
    //     let refresh_requests = routing.refresh_requests_given();
    //     assert_eq!(refresh_requests.len(), 2);
    //     assert_eq!(refresh_requests[0], refresh_requests[1]);
    // }
}

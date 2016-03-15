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

use std::collections::HashMap;
use std::mem;

use error::InternalError;
use maidsafe_utilities::serialisation;
use routing::{Authority, Data, MessageId, RequestContent, RequestMessage};
use sodiumoxide::crypto::hash::sha512;
use time::{Duration, SteadyTime};
use types::{Refresh, RefreshValue};
use vault::RoutingNode;
use xor_name::XorName;

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct Account {
    stored_total_size: u64,
    lost_total_size: u64,
}

impl Default for Account {
    // FIXME: Account Creation process required https://maidsafe.atlassian.net/browse/MAID-1191
    //   To bypass the the process for a simple network, allowance is granted by default
    fn default() -> Account {
        Account {
            stored_total_size: 0,
            lost_total_size: 0,
        }
    }
}

impl Account {
    // Always return true to allow pmid_node carry out removal of Sacrificial copies
    // Otherwise Account need to remember storage info of Primary, Backup and Sacrificial
    // copies separately to trigger an early alert
    fn put_data(&mut self, size: u64) {
        // if (self.stored_total_size + size) > self.offered_space {
        //   return false;
        // }
        self.stored_total_size += size;
    }

    fn delete_data(&mut self, size: u64) {
        if self.stored_total_size < size {
            self.stored_total_size = 0;
        } else {
            self.stored_total_size -= size;
        }
    }

    #[allow(dead_code)]
    fn handle_lost_data(&mut self, size: u64) {
        self.delete_data(size);
        self.lost_total_size += size;
    }

    #[allow(dead_code)]
    fn handle_falure(&mut self, size: u64) {
        self.handle_lost_data(size);
    }

    #[allow(dead_code)]
    fn update_account(&mut self, diff_size: u64) {
        if self.stored_total_size < diff_size {
            self.stored_total_size = 0;
        } else {
            self.stored_total_size -= diff_size;
        }
        self.lost_total_size += diff_size;
    }
}



#[derive(Clone, PartialEq, Eq, Debug)]
struct MetadataForPutRequest {
    pub request: RequestMessage,
    pub creation_timestamp: SteadyTime,
}

impl MetadataForPutRequest {
    pub fn new(request: RequestMessage) -> MetadataForPutRequest {
        MetadataForPutRequest {
            request: request,
            creation_timestamp: SteadyTime::now(),
        }
    }
}



pub struct PmidManager {
    accounts: HashMap<XorName, Account>,
    // key -- (message_id, targeted pmid_node)
    ongoing_puts: HashMap<(MessageId, XorName), MetadataForPutRequest>,
}

impl PmidManager {
    pub fn new() -> PmidManager {
        PmidManager {
            accounts: HashMap::new(),
            ongoing_puts: HashMap::new(),
        }
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
        // Put data always being allowed, i.e. no early alert
        self.accounts
            .entry(*request.dst.name())
            .or_insert_with(Account::default)
            .put_data(data.payload_size() as u64);
        let src = Authority::NodeManager(*request.dst.name());
        let dst = Authority::ManagedNode(*request.dst.name());
        trace!("PM forwarding put request of data {} targeting PN {}",
               data.name(),
               dst.name());
        let _ = routing_node.send_put_request(src, dst, Data::Immutable(data.clone()), *message_id);
        let _ = self.ongoing_puts.insert((*message_id, *request.dst.name()),
                                         MetadataForPutRequest::new(request.clone()));
        Ok(())
    }

    pub fn check_timeout(&mut self, routing_node: &RoutingNode) {
        let time_limit = Duration::minutes(1);
        let mut timed_out_puts = Vec::<(MessageId, XorName)>::new();
        for (key, metadata_for_put) in &self.ongoing_puts {
            if metadata_for_put.creation_timestamp + time_limit < SteadyTime::now() {
                timed_out_puts.push(*key);
            }
        }
        for key in &timed_out_puts {
            match self.ongoing_puts.remove(key) {
                Some(metadata_for_put) => {
                    // The put_failure notification shall only be sent out to the NAE when this
                    // PM is still in the close_group to the pmid_node.
                    // There is chance the timeout is reached due to the fact that this PM is
                    // no longer in the close_group of target pmid_node anymore.
                    // Checking it in churn will be costly and improper as the request cache
                    // is not refreshed out. This leaves a chance if this PM churned out then
                    // churned in, the record will be lost.
                    if routing_node.close_group(*metadata_for_put.request.dst.name())
                                   .ok()
                                   .is_some() {
                        let _ = self.handle_put_failure(routing_node, &metadata_for_put.request);
                    }
                }
                None => continue,
            }
        }
    }

    pub fn handle_put_success(&mut self,
                              routing_node: &RoutingNode,
                              pmid_node: &XorName,
                              message_id: &MessageId)
                              -> Result<(), InternalError> {
        if let Some(metadata_for_put) = self.ongoing_puts.remove(&(*message_id, *pmid_node)) {
            let message_hash =
                sha512::hash(&try!(serialisation::serialise(&metadata_for_put.request))[..]);
            let src = metadata_for_put.request.dst.clone();
            let dst = metadata_for_put.request.src.clone();
            trace!("As {:?} sending put success to {:?}", src, dst);
            let _ = routing_node.send_put_success(src, dst, message_hash, *message_id);
        } else {}
        Ok(())
    }

    // The `request` is the original request from NAE to PM
    pub fn handle_put_failure(&mut self,
                              routing_node: &RoutingNode,
                              request: &RequestMessage)
                              -> Result<(), InternalError> {
        let (data, message_id) = if let RequestContent::Put(Data::Immutable(ref data),
                                                            ref message_id) = request.content {
            (data.clone(), message_id)
        } else {
            unreachable!("Error in vault demuxing")
        };

        let src = request.dst.clone();
        let dst = request.src.clone();
        trace!("As {:?} sending Put failure to {:?} of data {}",
               src,
               dst,
               data.name());
        let _ = routing_node.send_put_failure(src, dst, request.clone(), vec![], *message_id);

        if let Some(account) = self.accounts.get_mut(request.dst.name()) {
            account.delete_data(data.payload_size() as u64);
        }

        Ok(())
    }

    pub fn handle_refresh(&mut self, name: XorName, account: Account) {
        let _ = self.accounts.insert(name, account);
    }

    pub fn handle_churn(&mut self, routing_node: &RoutingNode) {
        // Only retain accounts for which we're still in the close group
        let accounts = mem::replace(&mut self.accounts, HashMap::new());
        self.accounts = accounts.into_iter()
                                .filter(|&(ref pmid_node, ref account)| {
                                    match routing_node.close_group(*pmid_node) {
                                        Ok(None) => {
                                            trace!("No longer a PM for {}", pmid_node);
                                            false
                                        }
                                        Ok(Some(_)) => {
                                            self.send_refresh(routing_node, pmid_node, account);
                                            true
                                        }
                                        Err(error) => {
                                            error!("Failed to get close group: {:?} for {}",
                                                   error,
                                                   pmid_node);
                                            false
                                        }
                                    }
                                })
                                .collect();
    }

    fn send_refresh(&self, routing_node: &RoutingNode, pmid_node: &XorName, account: &Account) {
        let src = Authority::NodeManager(*pmid_node);
        let refresh = Refresh::new(pmid_node, RefreshValue::PmidManagerAccount(account.clone()));
        if let Ok(serialised_refresh) = serialisation::serialise(&refresh) {
            trace!("PM sending refresh for account {}", src.name());
            let _ = routing_node.send_refresh_request(src, serialised_refresh);
        }
    }
}

impl Default for PmidManager {
    fn default() -> PmidManager {
        PmidManager::new()
    }
}


#[cfg(all(test, feature = "use-mock-routing"))]
mod test {
    use super::*;
    use maidsafe_utilities::serialisation;
    use rand::{thread_rng, random};
    use rand::distributions::{IndependentSample, Range};
    use routing::{Authority, Data, ImmutableData, ImmutableDataType, MessageId, RequestContent, RequestMessage,
                  ResponseContent};
    use sodiumoxide::crypto::hash::sha512;
    use std::sync::mpsc;
    use std::thread::sleep;
    use std::time::Duration;
    use types::Refresh;
    use utils::generate_random_vec_u8;
    use vault::RoutingNode;
    use xor_name::XorName;


    struct Environment {
        our_authority: Authority,
        from_authority: Authority,
        routing: RoutingNode,
        pmid_manager: PmidManager,
    }

    fn environment_setup() -> Environment {
        let routing = unwrap_result!(RoutingNode::new(mpsc::channel().0));
        let mut our_name = random::<XorName>();
        let mut from_name = random::<XorName>();

        loop {
            if let Ok(Some(_)) = routing.close_group(our_name) {
                break;
            } else {
                our_name = random::<XorName>();
            }
        }

        loop {
            if let Ok(Some(_)) = routing.close_group(from_name) {
                break;
            } else {
                from_name = random::<XorName>();
            }
        }

        Environment {
            our_authority: Authority::NodeManager(our_name),
            from_authority: Authority::NaeManager(from_name),
            routing: routing,
            pmid_manager: PmidManager::default(),
        }
    }

    fn get_close_data(env: &Environment) -> ImmutableData {
        let mut data = ImmutableData::new(ImmutableDataType::Normal, generate_random_vec_u8(1024));

        loop {
            if let Ok(Some(_)) = env.routing.close_group(data.name()) {
                return data
            } else {
                data = ImmutableData::new(ImmutableDataType::Normal, generate_random_vec_u8(1024));
            }
        }
    }

    fn get_close_node(env: &Environment) -> XorName {
        let mut name = random::<XorName>();

        loop {
            if let Ok(Some(_)) = env.routing.close_group(name) {
                return name
            } else {
                name = random::<XorName>();
            }
        }
    }

    #[cfg_attr(feature="clippy", allow(indexing_slicing))]
    fn lose_close_node(env: &Environment) -> XorName {
        loop {
            if let Ok(Some(close_group)) = env.routing.close_group(*env.our_authority.name()) {
                let mut rng = thread_rng();
                let range = Range::new(0, close_group.len());
                let our_name = if let Ok(ref name) = env.routing.name() {
                    *name
                } else {
                    unreachable!()
                };
                loop {
                    let index = range.ind_sample(&mut rng);
                    if close_group[index] != our_name {
                        return close_group[index]
                    }
                }
            }
        }
    }

    #[test]
    #[cfg_attr(feature="clippy", allow(indexing_slicing))]
    fn handle_put() {
        let mut env = environment_setup();
        let immutable_data = get_close_data(&env);
        let message_id = MessageId::new();
        let valid_request = RequestMessage {
            src: env.from_authority.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(Data::Immutable(immutable_data.clone()), message_id),
        };

        if let Ok(()) = env.pmid_manager.handle_put(&env.routing, &valid_request) {} else {
            unreachable!()
        }

        let put_requests = env.routing.put_requests_given();

        assert_eq!(put_requests.len(), 1);
        assert_eq!(put_requests[0].src, env.our_authority);
        assert_eq!(put_requests[0].dst, Authority::ManagedNode(env.our_authority.name().clone()));

        if let RequestContent::Put(Data::Immutable(ref data), ref id) = put_requests[0].content {
            assert_eq!(*data, immutable_data);
            assert_eq!(*id, message_id);
        } else {
            unreachable!()
        }
    }

    #[test]
    #[cfg_attr(feature="clippy", allow(indexing_slicing))]
    fn check_timeout() {
        let mut env = environment_setup();
        let immutable_data = get_close_data(&env);
        let message_id = MessageId::new();
        let valid_request = RequestMessage {
            src: env.from_authority.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(Data::Immutable(immutable_data.clone()), message_id),
        };

        if let Ok(()) = env.pmid_manager.handle_put(&env.routing, &valid_request) {} else {
            unreachable!()
        }

        let put_requests = env.routing.put_requests_given();

        assert_eq!(put_requests.len(), 1);
        assert_eq!(put_requests[0].src, env.our_authority);
        assert_eq!(put_requests[0].dst, Authority::ManagedNode(env.our_authority.name().clone()));

        if let RequestContent::Put(Data::Immutable(ref data), ref id) = put_requests[0].content {
            assert_eq!(*data, immutable_data);
            assert_eq!(*id, message_id);
        } else {
            unreachable!()
        }

        sleep(Duration::from_millis(60000));

        env.pmid_manager.check_timeout(&env.routing);

        let put_failures = env.routing.put_failures_given();

        assert_eq!(put_failures.len(), 1);
        assert_eq!(put_failures[0].src, env.our_authority);
        assert_eq!(put_failures[0].dst, env.from_authority);

        if let ResponseContent::PutFailure{ ref id, ref request, ref external_error_indicator } =
               put_failures[0].content {
            assert_eq!(*id, message_id);
            assert_eq!(*request, valid_request);
            assert_eq!(*external_error_indicator, Vec::<u8>::new());
        } else {
            unreachable!()
        }
    }

    #[test]
    #[cfg_attr(feature="clippy", allow(indexing_slicing, shadow_unrelated))]
    fn handle_put_success() {
        let mut env = environment_setup();
        let immutable_data = get_close_data(&env);
        let message_id = MessageId::new();
        let valid_request = RequestMessage {
            src: env.from_authority.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(Data::Immutable(immutable_data.clone()), message_id),
        };

        if let Ok(()) = env.pmid_manager.handle_put(&env.routing, &valid_request) {} else {
            unreachable!()
        }

        let put_requests = env.routing.put_requests_given();

        assert_eq!(put_requests.len(), 1);
        assert_eq!(put_requests[0].src, env.our_authority);
        assert_eq!(put_requests[0].dst, Authority::ManagedNode(env.our_authority.name().clone()));

        if let RequestContent::Put(Data::Immutable(ref data), ref id) = put_requests[0].content {
            assert_eq!(*data, immutable_data);
            assert_eq!(*id, message_id);
        } else {
            unreachable!()
        }

        // Valid case.
        let pmid_node = *env.our_authority.name();
        if let Ok(()) = env.pmid_manager.handle_put_success(&env.routing, &pmid_node, &message_id) {} else {
            unreachable!()
        }

        let put_successes = env.routing.put_successes_given();

        assert_eq!(put_successes.len(), 1);
        assert_eq!(put_successes[0].src, env.our_authority);
        assert_eq!(put_successes[0].dst, env.from_authority);

        if let ResponseContent::PutSuccess(ref digest, ref id) = put_successes[0].content {
            if let Ok(serialised_request) = serialisation::serialise(&valid_request) {
                assert_eq!(*digest, sha512::hash(&serialised_request[..]));
            }
            assert_eq!(*id, message_id);
        } else {
            unreachable!()
        }

        // Invalid case.
        let pmid_node = get_close_node(&env);
        let message_id = MessageId::new();

        if let Ok(()) = env.pmid_manager.handle_put_success(&env.routing, &pmid_node, &message_id) {} else {
            unreachable!()
        }

        let put_successes = env.routing.put_successes_given();
        // unchanged...
        assert_eq!(put_successes.len(), 1);
    }

    #[test]
    #[cfg_attr(feature="clippy", allow(indexing_slicing))]
    fn handle_put_failure() {
        let mut env = environment_setup();
        let immutable_data = get_close_data(&env);
        let message_id = MessageId::new();
        let valid_request = RequestMessage {
            src: env.from_authority.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(Data::Immutable(immutable_data.clone()), message_id),
        };

        if let Ok(()) = env.pmid_manager.handle_put(&env.routing, &valid_request) {} else {
            unreachable!()
        }

        let put_requests = env.routing.put_requests_given();

        assert_eq!(put_requests.len(), 1);
        assert_eq!(put_requests[0].src, env.our_authority);
        assert_eq!(put_requests[0].dst, Authority::ManagedNode(env.our_authority.name().clone()));

        if let RequestContent::Put(Data::Immutable(ref data), ref id) = put_requests[0].content {
            assert_eq!(*data, immutable_data);
            assert_eq!(*id, message_id);
        } else {
            unreachable!()
        }

        if let Ok(()) = env.pmid_manager.handle_put_failure(&env.routing, &valid_request) {} else {
            unreachable!()
        }

        let put_failures = env.routing.put_failures_given();

        assert_eq!(put_failures.len(), 1);
        assert_eq!(put_failures[0].src, env.our_authority);
        assert_eq!(put_failures[0].dst, env.from_authority);

        if let ResponseContent::PutFailure{ ref id, ref request, ref external_error_indicator } =
               put_failures[0].content {
            assert_eq!(*id, message_id);
            assert_eq!(*request, valid_request);
            assert_eq!(*external_error_indicator, Vec::<u8>::new());
        } else {
            unreachable!()
        }
    }

    #[test]
    #[cfg_attr(feature="clippy", allow(indexing_slicing, shadow_unrelated))]
    fn churn_refresh() {
        let mut env = environment_setup();
        let immutable_data = get_close_data(&env);
        let message_id = MessageId::new();
        let valid_request = RequestMessage {
            src: env.from_authority.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(Data::Immutable(immutable_data.clone()), message_id),
        };

        if let Ok(()) = env.pmid_manager.handle_put(&env.routing, &valid_request) {} else {
            unreachable!()
        }

        let put_requests = env.routing.put_requests_given();

        assert_eq!(put_requests.len(), 1);
        assert_eq!(put_requests[0].src, env.our_authority);
        assert_eq!(put_requests[0].dst, Authority::ManagedNode(env.our_authority.name().clone()));

        if let RequestContent::Put(Data::Immutable(ref data), ref id) = put_requests[0].content {
            assert_eq!(*data, immutable_data);
            assert_eq!(*id, message_id);
        } else {
            unreachable!()
        }

        env.routing.node_added_event(get_close_node(&env));
        env.pmid_manager.handle_churn(&env.routing);

        let mut refresh_count = 0;
        let refresh_requests = env.routing.refresh_requests_given();

        if let Ok(Some(_)) = env.routing.close_group(*env.our_authority.name()) {
            assert_eq!(refresh_requests.len(), 1);
            assert_eq!(refresh_requests[0].src, env.our_authority);
            assert_eq!(refresh_requests[0].dst, env.our_authority);

            if let RequestContent::Refresh(ref serialised_refresh) = refresh_requests[0].content {
               if let Ok(refresh) = serialisation::deserialise(&serialised_refresh) {
                    let refresh: Refresh = refresh;
                    assert_eq!(refresh.name, *env.our_authority.name());
                } else {
                    unreachable!()
                }
            } else {
                unreachable!()
            }
            refresh_count += 1;
        } else {
            assert_eq!(refresh_requests.len(), 0);
        }

        env.routing.node_lost_event(lose_close_node(&env));
        env.pmid_manager.handle_churn(&env.routing);

        let refresh_requests = env.routing.refresh_requests_given();

        if let Ok(Some(_)) = env.routing.close_group(*env.our_authority.name()) {
            assert_eq!(refresh_requests.len(), refresh_count + 1);
            assert_eq!(refresh_requests[refresh_count].src, env.our_authority);
            assert_eq!(refresh_requests[refresh_count].dst, env.our_authority);

            if let RequestContent::Refresh(ref serialised_refresh) = refresh_requests[refresh_count].content {
               if let Ok(refresh) = serialisation::deserialise(&serialised_refresh) {
                    let refresh: Refresh = refresh;
                    assert_eq!(refresh.name, *env.our_authority.name());
                } else {
                    unreachable!()
                }
            } else {
                unreachable!()
            }
            // refresh_count += 1;
        } else {
            assert_eq!(refresh_requests.len(), refresh_count);
        }
    }
}

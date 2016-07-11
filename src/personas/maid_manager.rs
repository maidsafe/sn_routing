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
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::rc::Rc;

use error::InternalError;
use safe_network_common::client_errors::{GetError, MutationError};
use itertools::Itertools;
use kademlia_routing_table::RoutingTable;
use maidsafe_utilities::serialisation;
use routing::{Authority, Data, DataIdentifier, GROUP_SIZE, ImmutableData, MessageId,
              StructuredData, XorName};
use utils;
use vault::RoutingNode;

// 100 units, max 100MB for immutable_data (1MB per chunk)
const DEFAULT_ACCOUNT_SIZE: u64 = 100;

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
struct Refresh(XorName, Account);

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct Account {
    data_stored: u64,
    space_available: u64,
    version: u64,
}

impl Default for Account {
    fn default() -> Account {
        Account {
            data_stored: 0,
            space_available: DEFAULT_ACCOUNT_SIZE,
            version: 0,
        }
    }
}

impl Account {
    fn add_entry(&mut self) -> Result<(), MutationError> {
        if self.space_available < 1 {
            return Err(MutationError::LowBalance);
        }
        self.data_stored += 1;
        self.space_available -= 1;
        self.version += 1;
        Ok(())
    }

    fn remove_entry(&mut self) {
        self.data_stored -= 1;
        self.space_available += 1;
        self.version += 1;
    }
}



pub struct MaidManager {
    routing_node: Rc<RoutingNode>,
    accounts: HashMap<XorName, Account>,
    request_cache: HashMap<MessageId, (Authority, Authority)>,
}

impl MaidManager {
    pub fn new(routing_node: Rc<RoutingNode>) -> MaidManager {
        MaidManager {
            routing_node: routing_node,
            accounts: HashMap::new(),
            request_cache: HashMap::new(),
        }
    }

    pub fn handle_put(&mut self,
                      src: Authority,
                      dst: Authority,
                      data: Data,
                      msg_id: MessageId)
                      -> Result<(), InternalError> {
        match data {
            Data::Immutable(immut_data) => {
                self.handle_put_immutable_data(src, dst, immut_data, msg_id)
            }
            Data::Structured(struct_data) => {
                self.handle_put_structured_data(src, dst, struct_data, msg_id)
            }
            _ => {
                self.reply_with_put_failure(src,
                                            dst,
                                            data.identifier(),
                                            msg_id,
                                            &MutationError::InvalidOperation)
            }
        }
    }

    pub fn handle_put_success(&mut self,
                              data_id: DataIdentifier,
                              msg_id: MessageId)
                              -> Result<(), InternalError> {
        match self.request_cache.remove(&msg_id) {
            Some((src, dst)) => {
                // Send success response back to client
                let client_name = utils::client_name(&src);
                self.send_refresh(&client_name,
                                  self.accounts.get(&client_name).expect("Account not found."),
                                  MessageId::zero());
                let _ = self.routing_node.send_put_success(dst, src, data_id, msg_id);
                Ok(())
            }
            None => Err(InternalError::FailedToFindCachedRequest(msg_id)),
        }
    }

    pub fn handle_put_failure(&mut self,
                              msg_id: MessageId,
                              data_id: DataIdentifier,
                              external_error_indicator: &[u8])
                              -> Result<(), InternalError> {
        match self.request_cache.remove(&msg_id) {
            Some((src, dst)) => {
                // Refund account
                match self.accounts.get_mut(&utils::client_name(&src)) {
                    Some(account) => account.remove_entry(),
                    None => return Ok(()),
                }
                let client_name = utils::client_name(&src);
                self.send_refresh(&client_name,
                                  self.accounts.get(&client_name).expect("Account not found."),
                                  MessageId::zero());
                // Send failure response back to client
                let error =
                    try!(serialisation::deserialise::<MutationError>(external_error_indicator));
                self.reply_with_put_failure(src, dst, data_id, msg_id, &error)
            }
            None => Err(InternalError::FailedToFindCachedRequest(msg_id)),
        }
    }

    pub fn handle_get_account_info(&mut self,
                                   src: Authority,
                                   dst: Authority,
                                   msg_id: MessageId)
                                   -> Result<(), InternalError> {
        let client_name = utils::client_name(&src);
        if let Some(account) = self.accounts.get(&client_name) {
            let _ = self.routing_node.send_get_account_info_success(dst,
                                                                    src,
                                                                    account.data_stored,
                                                                    account.space_available,
                                                                    msg_id);
        } else {
            let external_error_indicator = try!(serialisation::serialise(&GetError::NoSuchAccount));
            let _ = self.routing_node
                .send_get_account_info_failure(dst, src, external_error_indicator, msg_id);
        }
        Ok(())
    }

    pub fn handle_refresh(&mut self, serialised_msg: &[u8]) -> Result<(), InternalError> {
        let Refresh(maid_name, account) =
            try!(serialisation::deserialise::<Refresh>(serialised_msg));

        match self.routing_node.close_group(maid_name) {
            Ok(None) | Err(_) => return Ok(()),
            Ok(Some(_)) => (),
        }
        let account_count = self.accounts.len();
        match self.accounts.entry(maid_name) {
            Entry::Vacant(entry) => {
                let _ = entry.insert(account);
                info!("Stats - {} client accounts.", account_count + 1);
            }
            Entry::Occupied(mut entry) => {
                if entry.get().version < account.version {
                    trace!("Client account {:?}: {:?}", maid_name, account);
                    let _ = entry.insert(account);
                }
            }
        }
        Ok(())
    }

    pub fn handle_node_added(&mut self,
                             node_name: &XorName,
                             routing_table: &RoutingTable<XorName>) {
        // Remove all accounts which we are no longer responsible for.
        let not_close = |name: &&XorName| !routing_table.is_close(*name, GROUP_SIZE);
        let accounts_to_delete = self.accounts.keys().filter(not_close).cloned().collect_vec();
        // Remove all requests from the cache that we are no longer responsible for.
        let msg_ids_to_delete = self.request_cache
            .iter()
            .filter(|&(_, &(ref src, _))| accounts_to_delete.contains(src.name()))
            .map(|(msg_id, _)| *msg_id)
            .collect_vec();
        for msg_id in msg_ids_to_delete {
            let _ = self.request_cache.remove(&msg_id);
        }
        if !accounts_to_delete.is_empty() {
            info!("Stats - {} client accounts.",
                  self.accounts.len() - accounts_to_delete.len());
        }
        for maid_name in accounts_to_delete {
            trace!("No longer a MM for {}", maid_name);
            let _ = self.accounts.remove(&maid_name);
        }
        // Send refresh messages for the remaining accounts.
        for (maid_name, account) in &self.accounts {
            self.send_refresh(maid_name, account, MessageId::from_added_node(*node_name));
        }
    }

    pub fn handle_node_lost(&mut self, node_name: &XorName) {
        for (maid_name, account) in &self.accounts {
            self.send_refresh(maid_name, account, MessageId::from_lost_node(*node_name));
        }
    }

    fn send_refresh(&self, maid_name: &XorName, account: &Account, msg_id: MessageId) {
        let src = Authority::ClientManager(*maid_name);
        let refresh = Refresh(*maid_name, account.clone());
        if let Ok(serialised_refresh) = serialisation::serialise(&refresh) {
            trace!("MM sending refresh for account {}", src.name());
            let _ = self.routing_node
                .send_refresh_request(src.clone(), src.clone(), serialised_refresh, msg_id);
        }
    }

    #[cfg_attr(feature="clippy", allow(cast_possible_truncation, cast_precision_loss,
                                       cast_sign_loss))]
    fn handle_put_immutable_data(&mut self,
                                 src: Authority,
                                 dst: Authority,
                                 data: ImmutableData,
                                 msg_id: MessageId)
                                 -> Result<(), InternalError> {
        let client_name = utils::client_name(&src);
        let immutable_data = Data::Immutable(data);
        self.forward_put_request(src, dst, client_name, immutable_data, msg_id)
    }

    fn handle_put_structured_data(&mut self,
                                  src: Authority,
                                  dst: Authority,
                                  data: StructuredData,
                                  msg_id: MessageId)
                                  -> Result<(), InternalError> {
        // If the type_tag is 0, the account must not exist, else it must exist.
        let client_name = utils::client_name(&src);
        if data.get_type_tag() == 0 {
            if self.accounts.contains_key(&client_name) {
                let error = MutationError::AccountExists;
                try!(self.reply_with_put_failure(src, dst, data.identifier(), msg_id, &error));
                return Err(From::from(error));
            }

            // Create the account, the SD incurs charge later on
            let _ = self.accounts.insert(client_name, Account::default());
            info!("Stats - {} client accounts.", self.accounts.len());
        }
        let structured_data = Data::Structured(data);
        self.forward_put_request(src, dst, client_name, structured_data, msg_id)
    }

    fn forward_put_request(&mut self,
                           src: Authority,
                           dst: Authority,
                           client_name: XorName,
                           data: Data,
                           msg_id: MessageId)
                           -> Result<(), InternalError> {
        // Account must already exist to Put Data.
        let result = self.accounts
            .get_mut(&client_name)
            .ok_or(MutationError::NoSuchAccount)
            .and_then(|account| {
                let result = account.add_entry();
                trace!("Client account {:?}: {:?}", client_name, account);
                result
            });
        if let Err(error) = result {
            trace!("MM responds put_failure of data {}, due to error {:?}",
                   data.name(),
                   error);
            try!(self.reply_with_put_failure(src, dst, data.identifier(), msg_id, &error));
            return Err(From::from(error));
        }
        {
            // forwarding data_request to NAE Manager
            let src = dst.clone();
            let dst = Authority::NaeManager(*data.name());
            trace!("MM forwarding put request to {:?}", dst);
            let _ = self.routing_node.send_put_request(src, dst, data, msg_id);
        }

        if let Some((prior_src, prior_dst)) = self.request_cache.insert(msg_id, (src, dst)) {
            error!("Overwrote existing cached request with {:?} from {:?} to {:?}",
                   msg_id,
                   prior_src,
                   prior_dst);
        }

        Ok(())
    }

    fn reply_with_put_failure(&self,
                              src: Authority,
                              dst: Authority,
                              data_id: DataIdentifier,
                              msg_id: MessageId,
                              error: &MutationError)
                              -> Result<(), InternalError> {
        let external_error_indicator = try!(serialisation::serialise(error));
        let _ = self.routing_node
            .send_put_failure(dst, src, data_id, external_error_indicator, msg_id);
        Ok(())
    }

    #[cfg(feature = "use-mock-crust")]
    pub fn get_put_count(&self, client_name: &XorName) -> Option<u64> {
        self.accounts.get(client_name).map(|account| account.data_stored)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn account_struct_normal_updates() {
        let mut account = Account::default();

        assert_eq!(0, account.data_stored);
        assert_eq!(super::DEFAULT_ACCOUNT_SIZE, account.space_available);
        for _ in 0..super::DEFAULT_ACCOUNT_SIZE {
            assert!(account.add_entry().is_ok());
        }
        assert_eq!(super::DEFAULT_ACCOUNT_SIZE, account.data_stored);
        assert_eq!(0, account.space_available);

        for _ in 0..super::DEFAULT_ACCOUNT_SIZE {
            account.remove_entry();
        }
        assert_eq!(0, account.data_stored);
        assert_eq!(super::DEFAULT_ACCOUNT_SIZE, account.space_available);
    }

    #[test]
    fn account_struct_error_updates() {
        let mut account = Account::default();

        assert_eq!(0, account.data_stored);
        assert_eq!(super::DEFAULT_ACCOUNT_SIZE, account.space_available);
        for _ in 0..super::DEFAULT_ACCOUNT_SIZE {
            assert!(account.add_entry().is_ok());
        }
        assert_eq!(super::DEFAULT_ACCOUNT_SIZE, account.data_stored);
        assert_eq!(0, account.space_available);
        assert!(account.add_entry().is_err());
        assert_eq!(super::DEFAULT_ACCOUNT_SIZE, account.data_stored);
        assert_eq!(0, account.space_available);
    }

}

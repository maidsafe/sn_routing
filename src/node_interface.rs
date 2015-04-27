// Copyright 2015 MaidSafe.net limited
//
// This Safe Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the Safe Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://maidsafe.net/network-platform-licensing
//
// Unless required by applicable law or agreed to in writing, the Safe Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations relating to
// use of the Safe Network Software.

use generic_sendable_type;
use name_type::NameType;
use types::{Authority, DestinationAddress};
use super::{Action, RoutingError};

pub trait Interface : Sync + Send {
    /// if reply is data then we send back the response message (ie get_response )
    fn handle_get(&mut self,
                  type_id: u64,
                  name: NameType,
                  our_authority: Authority,
                  from_authority: Authority,
                  from_address: NameType) -> Result<Action, RoutingError>;

    /// data: Vec<u8> is serialised maidsafe_types::Payload which holds typetag and content
    fn handle_put(&mut self,
                  our_authority: Authority,
                  from_authority: Authority,
                  from_address: NameType,
                  dest_address: DestinationAddress,
                  data: Vec<u8>) -> Result<Action, RoutingError>;

    fn handle_post(&mut self,
                   our_authority: Authority,
                   from_authority: Authority,
                   from_address: NameType,
                   data: Vec<u8>) -> Result<Action, RoutingError>;

    fn handle_get_response(&mut self,
                           from_address: NameType,
                           response: Result<Vec<u8>, RoutingError>);

    fn handle_put_response(&mut self,
                           from_authority: Authority,
                           from_address: NameType,
                           response: Result<Vec<u8>, RoutingError>);

    fn handle_post_response(&mut self,
                            from_authority: Authority,
                            from_address: NameType,
                            response: Result<Vec<u8>, RoutingError>);

    fn handle_churn(&mut self, close_group: Vec<NameType>) -> Vec<(NameType, generic_sendable_type::GenericSendableType)>;

    fn handle_cache_get(&mut self,
                        type_id: u64,
                        name: NameType,
                        from_authority: Authority,
                        from_address: NameType) -> Result<Action, RoutingError>;

    fn handle_cache_put(&mut self,
                        from_authority: Authority,
                        from_address: NameType,
                        data: Vec<u8>) -> Result<Action, RoutingError>;
}

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

use sendable::Sendable;
use name_type::NameType;
use types::DestinationAddress;
use authority::Authority;
use types::MessageAction;
use error::{InterfaceError, ResponseError};

/// MethodCall denotes a specific request to be carried out by routing.
pub enum MethodCall {
    /// request for no action
    None,
    /// request to have `destination` to handle put for the `content`
    Put { destination: NameType, content: Box<Sendable>, },
    /// request to retreive data of particular type and name from network
    Get { type_id: u64, name: NameType, },
    /// request to post
    Post,
    /// request to refresh
    Refresh { content: Box<Sendable>, },
    /// request to send on the request to destination
    SendOn { destination: NameType },
}

#[deny(missing_docs)]
/// The Interface trait introduces the methods expected to be implemented by the user
/// of RoutingNode
pub trait Interface : Sync + Send {
    /// the public key or address of the node potentially storing data is returned on success.
    fn handle_get_key(&mut self,
                      type_id: u64,
                      name: NameType,
                      our_authority: Authority,
                      from_authority: Authority,
                      from_address: NameType) -> Result<MessageAction, InterfaceError>;

    /// data or address of the node potentially storing data is returned on success.
    fn handle_get(&mut self,
                  type_id: u64,
                  name: NameType,
                  our_authority: Authority,
                  from_authority: Authority,
                  from_address: NameType) -> Result<MessageAction, InterfaceError>;

    /// success indicates store is done, or an address to store data is provided
    fn handle_put(&mut self,
                  our_authority: Authority,
                  from_authority: Authority,
                  from_address: NameType,
                  dest_address: DestinationAddress,
                  data: Vec<u8>) -> Result<MessageAction, InterfaceError>;

    /// to handle post request. The requested data or potential address to find it is provided on
    /// success
    fn handle_post(&mut self,
                   our_authority: Authority,
                   from_authority: Authority,
                   from_address: NameType,
                   name : NameType,
                   data: Vec<u8>) -> Result<MessageAction, InterfaceError>;

    /// consumes data in response or handles the error
    fn handle_get_response(&mut self,
                           from_address: NameType,
                           response: Result<Vec<u8>, ResponseError>) -> MethodCall;

    /// handles the result of a put request
    fn handle_put_response(&mut self,
                           from_authority: Authority,
                           from_address: NameType,
                           response: Result<Vec<u8>, ResponseError>) -> MethodCall;

    /// handles the result of a post request
    fn handle_post_response(&mut self,
                            from_authority: Authority,
                            from_address: NameType,
                            response: Result<Vec<u8>, ResponseError>);

    /// handles the actions to be carried out in the event of a churn
    fn handle_churn(&mut self, close_group: Vec<NameType>) -> Vec<MethodCall>;

    /// attempts to provide data from cache. On success data is returned
    fn handle_cache_get(&mut self,
                        type_id: u64,
                        name: NameType,
                        from_authority: Authority,
                        from_address: NameType) -> Result<MessageAction, InterfaceError>;

    /// attempts to stores data in cache
    fn handle_cache_put(&mut self,
                        from_authority: Authority,
                        from_address: NameType,
                        data: Vec<u8>) -> Result<MessageAction, InterfaceError>;
}

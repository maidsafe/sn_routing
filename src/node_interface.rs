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

pub enum MethodCall {
    None,
    Put { destination: NameType, content: Box<Sendable>, },
    Get { type_id: u64, name: NameType, },
    Post,
    Refresh { content: Box<Sendable>, },
    PutResponse { destination: NameType, payload: Vec<u8> },
}

pub trait Interface : Sync + Send {
    /// the public key or address of the node store it is returned on success.
    fn handle_get_key(&mut self,
                      type_id: u64,
                      name: NameType,
                      our_authority: Authority,
                      from_authority: Authority,
                      from_address: NameType) -> Result<MessageAction, InterfaceError>;

    /// if reply is data then we send back the response message (ie get_response )
    fn handle_get(&mut self,
                  type_id: u64,
                  name: NameType,
                  our_authority: Authority,
                  from_authority: Authority,
                  from_address: NameType) -> Result<MessageAction, InterfaceError>;

    /// data: Vec<u8> is serialised maidsafe_types::Payload which holds typetag and content
    fn handle_put(&mut self,
                  our_authority: Authority,
                  from_authority: Authority,
                  from_address: NameType,
                  dest_address: DestinationAddress,
                  data: Vec<u8>) -> Result<MessageAction, InterfaceError>;

    fn handle_post(&mut self,
                   our_authority: Authority,
                   from_authority: Authority,
                   from_address: NameType,
                   name : NameType,
                   data: Vec<u8>) -> Result<MessageAction, InterfaceError>;

    fn handle_get_response(&mut self,
                           from_address: NameType,
                           response: Result<Vec<u8>, ResponseError>) -> MethodCall;

    fn handle_put_response(&mut self,
                           from_authority: Authority,
                           from_address: NameType,
                           response: Result<Vec<u8>, ResponseError>) -> MethodCall;

    fn handle_post_response(&mut self,
                            from_authority: Authority,
                            from_address: NameType,
                            response: Result<Vec<u8>, ResponseError>);

    fn handle_churn(&mut self, close_group: Vec<NameType>) -> Vec<MethodCall>;

    fn handle_cache_get(&mut self,
                        type_id: u64,
                        name: NameType,
                        from_authority: Authority,
                        from_address: NameType) -> Result<MessageAction, InterfaceError>;

    fn handle_cache_put(&mut self,
                        from_authority: Authority,
                        from_address: NameType,
                        data: Vec<u8>) -> Result<MessageAction, InterfaceError>;
}

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

use config_file_handler;
use chunk_store;
use routing::messaging;
use routing::client_errors::{GetError, MutationError};
use maidsafe_utilities::serialisation::SerialisationError;
use routing::{InterfaceError, MessageId, Request, Response, RoutingError};
use std::io;

quick_error! {
    #[derive(Debug)]
    pub enum InternalError {
        ChunkStore(error: chunk_store::Error) {
            from()
        }
        ClientGet(error: GetError) {
            from()
        }
        ClientMutation(error: MutationError) {
            from()
        }
        FailedToFindCachedRequest(message_id: MessageId)
        FileHandler(error: config_file_handler::Error) {
            from()
        }
        Io(error: io::Error) {
            from()
        }
        MpidMessaging(error: messaging::Error) {
            from()
        }
        Routing(error: InterfaceError) {
            from()
        }
        RoutingInternal(error: RoutingError) {
            from()
        }
        Serialisation(error: SerialisationError) {
            from()
        }
        UnknownRequestType(request: Request)
        UnknownResponseType(response: Response)
        InvalidMessage
    }
}

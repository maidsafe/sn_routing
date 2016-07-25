// Copyright 2016 MaidSafe.net limited.
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


use crust::{CrustError, PeerId, PrivConnectionInfo, PubConnectionInfo};
use maidsafe_utilities::serialisation;
use sodiumoxide::crypto::{box_, sign};

use authority::Authority;
use error::RoutingError;
use id::PublicId;
use messages::{DirectMessage, MessageContent, RoutingMessage};
use peer_manager::{ConnectionInfoPreparedResult, ConnectionInfoReceivedResult};
use state_machine::Transition;
use super::{Bootstrapped, GetPeerManager, SendDirectMessage, SendRoutingMessage, StateCommon};
use xor_name::XorName;

// Common functionality for states that need to connect to other nodes.
pub trait Connect
    : Bootstrapped + GetPeerManager + SendDirectMessage + SendRoutingMessage + StateCommon {
    fn handle_node_identify(&mut self, public_id: PublicId, peer_id: PeerId) -> Transition;

    /// Checks whether the given `name` is allowed to be added to our routing table or is already
    /// there. If not, returns an error.
    fn check_address_for_routing_table(&self, _name: &XorName) -> Result<(), RoutingError> {
        Ok(())
    }

    fn connect(&mut self,
               encrypted_connection_info: Vec<u8>,
               nonce_bytes: [u8; box_::NONCEBYTES],
               their_public_id: PublicId,
               src: Authority,
               dst: Authority)
               -> Result<Transition, RoutingError> {
        let decipher_result = box_::open(&encrypted_connection_info,
                                         &box_::Nonce(nonce_bytes),
                                         their_public_id.encrypting_public_key(),
                                         self.full_id().encrypting_private_key());

        let serialised_connection_info =
            try!(decipher_result.map_err(|()| RoutingError::AsymmetricDecryptionFailure));
        let their_connection_info: PubConnectionInfo =
            try!(serialisation::deserialise(&serialised_connection_info));
        let peer_id = their_connection_info.id();
        match self.peer_mgr_mut()
            .connection_info_received(src, dst, their_public_id, their_connection_info) {
            Ok(ConnectionInfoReceivedResult::Ready(our_info, their_info)) => {
                debug!("{:?} Received connection info. Trying to connect to {:?} ({:?}).",
                       self,
                       their_public_id.name(),
                       peer_id);
                let _ = self.crust_service().connect(our_info, their_info);
            }
            Ok(ConnectionInfoReceivedResult::Prepare(token)) => {
                self.crust_service().prepare_connection_info(token);
            }
            Ok(ConnectionInfoReceivedResult::IsProxy) |
            Ok(ConnectionInfoReceivedResult::IsClient) => {
                try!(self.send_node_identify(peer_id));
                return Ok(self.handle_node_identify(their_public_id, peer_id));
            }
            Ok(ConnectionInfoReceivedResult::Waiting) |
            Ok(ConnectionInfoReceivedResult::IsConnected) => (),
            Err(error) => {
                warn!("{:?} Failed to insert connection info from {:?} ({:?}): {:?}",
                      self,
                      their_public_id.name(),
                      peer_id,
                      error)
            }
        }

        Ok(Transition::Stay)
    }

    fn handle_connection_info_prepared(&mut self,
                                       result_token: u32,
                                       result: Result<PrivConnectionInfo, CrustError>) {
        let our_connection_info = match result {
            Err(err) => {
                error!("{:?} Failed to prepare connection info: {:?}", self, err);
                return;
            }
            Ok(connection_info) => connection_info,
        };
        let encoded_connection_info =
            match serialisation::serialise(&our_connection_info.to_pub_connection_info()) {
                Err(err) => {
                    error!("{:?} Failed to serialise connection info: {:?}", self, err);
                    return;
                }
                Ok(encoded_connection_info) => encoded_connection_info,
            };

        let (pub_id, src, dst) = match self.peer_mgr_mut()
            .connection_info_prepared(result_token, our_connection_info) {
            Err(error) => {
                // This usually means we have already connected.
                debug!("{:?} Prepared connection info, but no entry found in token map: {:?}",
                       self,
                       error);
                return;
            }
            Ok(ConnectionInfoPreparedResult { pub_id, src, dst, infos }) => {
                match infos {
                    None => {
                        debug!("{:?} Prepared connection info for {:?}.",
                               self,
                               pub_id.name());
                    }
                    Some((our_info, their_info)) => {
                        debug!("{:?} Trying to connect to {:?} as {:?}.",
                               self,
                               their_info.id(),
                               pub_id.name());
                        let _ = self.crust_service().connect(our_info, their_info);
                    }
                }
                (pub_id, src, dst)
            }
        };

        let nonce = box_::gen_nonce();
        let encrypted_connection_info = box_::seal(&encoded_connection_info,
                                                   &nonce,
                                                   pub_id.encrypting_public_key(),
                                                   self.full_id().encrypting_private_key());

        let request_content = MessageContent::ConnectionInfo {
            encrypted_connection_info: encrypted_connection_info,
            nonce_bytes: nonce.0,
            public_id: *self.full_id().public_id(),
        };

        let request_msg = RoutingMessage {
            src: src,
            dst: dst,
            content: request_content,
        };

        if let Err(err) = self.send_routing_message(request_msg) {
            debug!("{:?} Failed to send connection info for {:?}: {:?}.",
                   self,
                   pub_id.name(),
                   err);
        }
    }

    // TODO: check whether these two methods can be merged into one.
    fn handle_connection_info_from_client(&mut self,
                                          encrypted_connection_info: Vec<u8>,
                                          nonce_bytes: [u8; box_::NONCEBYTES],
                                          src: Authority,
                                          dst_name: XorName,
                                          their_public_id: PublicId)
                                          -> Result<Transition, RoutingError> {
        try!(self.check_address_for_routing_table(their_public_id.name()));
        self.connect(encrypted_connection_info,
                     nonce_bytes,
                     their_public_id,
                     Authority::ManagedNode(dst_name),
                     src)
    }

    fn handle_connection_info_from_node(&mut self,
                                        encrypted_connection_info: Vec<u8>,
                                        nonce_bytes: [u8; box_::NONCEBYTES],
                                        src_name: XorName,
                                        dst: Authority,
                                        their_public_id: PublicId)
                                        -> Result<Transition, RoutingError> {
        try!(self.check_address_for_routing_table(&src_name));
        self.connect(encrypted_connection_info,
                     nonce_bytes,
                     their_public_id,
                     dst,
                     Authority::ManagedNode(src_name))
    }

    fn send_connection_info(&mut self,
                            their_public_id: PublicId,
                            src: Authority,
                            dst: Authority)
                            -> Result<Transition, RoutingError> {
        let their_name = *their_public_id.name();
        if let Some(peer_id) = self.peer_mgr().get_proxy_or_client_peer_id(&their_public_id) {
            try!(self.send_node_identify(peer_id));
            return Ok(self.handle_node_identify(their_public_id, peer_id));
        } else if self.peer_mgr().allow_connect(&their_name) {
            if let Some(token) = self.peer_mgr_mut()
                .get_connection_token(src, dst, their_public_id) {
                self.crust_service().prepare_connection_info(token);
            } else {
                trace!("{:?} Already sent connection info to {:?}!",
                       self,
                       their_name);
            }
        }

        Ok(Transition::Stay)
    }

    fn send_node_identify(&mut self, peer_id: PeerId) -> Result<(), RoutingError> {
        let serialised_public_id = try!(serialisation::serialise(self.full_id().public_id()));
        let signature = sign::sign_detached(&serialised_public_id,
                                            self.full_id().signing_private_key());
        let direct_message = DirectMessage::NodeIdentify {
            serialised_public_id: serialised_public_id,
            signature: signature,
        };

        self.send_direct_message(&peer_id, direct_message)
    }
}

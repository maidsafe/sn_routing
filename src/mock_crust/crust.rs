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

use maidsafe_utilities::event_sender;
use std::cell::{RefCell, RefMut};
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;

use super::support::{self, Endpoint, Network, ServiceHandle, ServiceImpl};

/// TCP listener port
pub const LISTENER_PORT: u16 = 5485;

/// Mock version of `crust::Service`
pub struct Service(Rc<RefCell<ServiceImpl>>, Network);

impl Service {
    /// Create new mock `Service` using the make_current/get_current mechanism to
    /// get the associated `ServiceHandle`.
    pub fn new(event_sender: CrustEventSender) -> Result<Self, CrustError> {
        Self::with_handle(&support::get_current(), event_sender)
    }

    /// Create new mock `Service` by explicitly passing the mock device to associate
    /// with.
    pub fn with_handle(handle: &ServiceHandle,
                       event_sender: CrustEventSender)
                       -> Result<Self, CrustError> {
        let network = handle.0.borrow().network.clone();
        let service = Service(handle.0.clone(), network);
        service.lock_and_poll(|imp| imp.start(event_sender));

        Ok(service)
    }

    /// This method is used instead of dropping the service and creating a new
    /// one, which is the current practice with the real crust.
    pub fn restart(&self, event_sender: CrustEventSender) {
        self.lock_and_poll(|imp| imp.restart(event_sender))
    }

    /// Start the bootstrapping procedure.
    pub fn start_bootstrap(&mut self, blacklist: HashSet<SocketAddr>) -> Result<(), CrustError> {
        self.lock_and_poll(|imp| imp.start_bootstrap(blacklist));
        Ok(())
    }

    /// Stops the ongoing bootstrap.
    /// Note: This currently doesn't do anything, because mock bootstrap is
    /// not interruptible. This might change in the future, if needed.
    pub fn stop_bootstrap(&mut self) -> Result<(), CrustError> {
        // Nothing to do here, as mock bootstrapping is not interruptible.
        Ok(())
    }

    /// Start service discovery (beacon).
    /// Note: beacon is not yet implemented in mock.
    pub fn start_service_discovery(&mut self) {
        trace!("[MOCK] start_service_discovery not implemented in mock");
    }

    /// Enable listening and responding to peers searching for us. This will allow others finding us
    /// by interrogating the network.
    pub fn set_service_discovery_listen(&self, _listen: bool) {
        trace!("[MOCK] set_service_discovery_listen not implemented in mock");
    }

    /// Check if we have peers on LAN
    pub fn has_peers_on_lan(&self) -> bool {
        // This will allow mock crust test to have multiple nodes on the same machine
        false
    }

    /// Start TCP acceptor.
    /// Note: mock doesn't currently differentiate between TCP and UDP. As long
    /// as at least one is enabled, the service will accept any incoming connection.
    pub fn start_listening_tcp(&mut self) -> Result<(), CrustError> {
        self.lock().start_listening_tcp(LISTENER_PORT);
        Ok(())
    }

    /// Request connection info structure used for establishing peer-to-peer
    /// connections.
    pub fn prepare_connection_info(&self, result_token: u32) {
        self.lock_and_poll(|imp| imp.prepare_connection_info(result_token))
    }

    /// Connect to a peer using our and their connection infos. The connection infos must be first
    /// prepared using `prepare_connection_info` on both our and their end.
    pub fn connect(&self,
                   our_info: PrivConnectionInfo,
                   their_info: PubConnectionInfo)
                   -> Result<(), CrustError> {
        self.lock_and_poll(|imp| imp.connect(our_info, their_info));
        Ok(())
    }

    /// Disconnect from the given peer.
    pub fn disconnect(&self, peer_id: PeerId) -> bool {
        self.lock_and_poll(|imp| imp.disconnect(&peer_id))
    }

    /// Send message to the given peer.
    // TODO: Implement tests that drop low-priority messages.
    pub fn send(&self, id: PeerId, data: Vec<u8>, _priority: u8) -> io::Result<()> {
        if self.lock_and_poll(|imp| imp.send_message(&id, data)) {
            Ok(())
        } else {
            let msg = format!("No connection to peer {:?}", id);
            Err(io::Error::new(io::ErrorKind::Other, msg))
        }
    }

    /// Returns `true` if we are currently connected to the given `peer_id`
    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.lock_and_poll(|imp| imp.is_peer_connected(peer_id))
    }

    /// Adds the peer to the whitelist, allowing them to connect to us.
    pub fn whitelist_peer(&self, peer_id: PeerId) {
        self.lock().whitelist_peer(peer_id);
    }

    /// Returns `true` if the specified peer is allowed to connect to us.
    pub fn is_peer_whitelisted(&self, peer_id: &PeerId) -> bool {
        self.lock().is_peer_whitelisted(peer_id)
    }

    /// Our `PeerId`.
    pub fn id(&self) -> PeerId {
        self.lock().peer_id
    }

    fn lock(&self) -> RefMut<ServiceImpl> {
        self.0.borrow_mut()
    }

    fn lock_and_poll<F, R>(&self, f: F) -> R
        where F: FnOnce(&mut ServiceImpl) -> R
    {
        let result = f(&mut *self.lock());
        self.1.poll();
        result
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.lock_and_poll(|imp| imp.disconnect_all());
    }
}

/// Mock version of `crust::PeerId`.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, RustcEncodable, RustcDecodable)]
pub struct PeerId(pub usize);

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PeerId({})", self.0)
    }
}

/// Mock version of `crust::Event`.
#[derive(Debug)]
pub enum Event {
    /// Invoked when a bootstrap peer connects to us
    BootstrapAccept(PeerId),
    /// Invoked when we get a bootstrap connection to a new peer.
    BootstrapConnect(PeerId, SocketAddr),
    /// Invoked when we failed to connect to all bootstrap contacts.
    BootstrapFailed,
    /// Invoked when we are ready to listen for incomming connection. Contains
    /// the listening port.
    ListenerStarted(u16),
    /// Invoked when listener failed to start.
    ListenerFailed,
    /// Invoked as a result to the call of `Service::prepare_contact_info`.
    ConnectionInfoPrepared(ConnectionInfoResult),
    /// Invoked when connection to a new peer has been established.
    ConnectSuccess(PeerId),
    /// Invoked when connection to a new peer has failed.
    ConnectFailure(PeerId),
    /// Invoked when a peer is lost or having read/write error.
    LostPeer(PeerId),
    /// Invoked when a new message is received.  Passes the message.
    NewMessage(PeerId, Vec<u8>),
    /// Invoked when trying to sending a too large data.
    WriteMsgSizeProhibitive(PeerId, Vec<u8>),
}

/// Mock version of `CrustEventSender`.
pub type CrustEventSender = event_sender::MaidSafeObserver<Event>;

/// Mock version of `PrivConnectionInfo`, generated by a call to
/// `Service::prepare_contact_info`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivConnectionInfo(pub PeerId, pub Endpoint);

impl PrivConnectionInfo {
    /// Convert our connection info to theirs so that we can give it to them.
    pub fn to_pub_connection_info(&self) -> PubConnectionInfo {
        PubConnectionInfo(self.0, self.1)
    }
}

/// Mock version of `PubConnectionInfo`, used to connect to another peer.
#[derive(Clone, Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
pub struct PubConnectionInfo(pub PeerId, pub Endpoint);

impl PubConnectionInfo {
    /// The peer's Crust ID.
    pub fn id(&self) -> PeerId {
        self.0
    }
}

/// The result of a `Service::prepare_contact_info` call.
#[derive(Debug)]
pub struct ConnectionInfoResult {
    /// The token that was passed to `prepare_connection_info`.
    pub result_token: u32,
    /// The new contact info, if successful.
    pub result: Result<PrivConnectionInfo, CrustError>,
}

/// Mock version of `crust::CrustError`.
#[derive(Debug)]
pub struct CrustError;

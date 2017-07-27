// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::support::{Endpoint, Network, ServiceHandle, ServiceImpl};
pub use super::support::Config;
use maidsafe_utilities::event_sender;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::{fmt, thread};
use std::cell::{RefCell, RefMut};
use std::collections::HashSet;
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;

/// TCP listener port
pub const LISTENER_PORT: u16 = 5485;

/// Mock version of config reader
pub fn read_config_file() -> Result<Config, CrustError> {
    Ok(Config::new())
}

/// Mock version of `crust::Service`
pub struct Service<UID: Uid>(Rc<RefCell<ServiceImpl<UID>>>, Network<UID>);

impl<UID: Uid> Service<UID> {
    /// Create new mock `Service` using the make_current/get_current mechanism to get the associated
    /// `ServiceHandle`.
    pub fn new(
        handle: ServiceHandle<UID>,
        event_sender: CrustEventSender<UID>,
        uid: UID,
    ) -> Result<Self, CrustError> {
        Self::with_handle(&handle, event_sender, uid)
    }

    /// Create a new mock `Service` using the make_current/get_current mechanism to get the
    /// associated `ServiceHandle`. Ignores configuration.
    pub fn with_config(
        handle: ServiceHandle<UID>,
        event_sender: CrustEventSender<UID>,
        _config: Config,
        uid: UID,
    ) -> Result<Self, CrustError> {
        Self::with_handle(&handle, event_sender, uid)
    }

    /// Create new mock `Service` by explicitly passing the mock device to associate with.
    pub fn with_handle(
        handle: &ServiceHandle<UID>,
        event_sender: CrustEventSender<UID>,
        uid: UID,
    ) -> Result<Self, CrustError> {
        let network = handle.0.borrow().network.clone();
        let service = Service(handle.0.clone(), network);
        service.lock().start(event_sender, uid);

        Ok(service)
    }

    /// This method is used instead of dropping the service and creating a new one, which is the
    /// current practice with the real crust.
    pub fn restart(&self, event_sender: CrustEventSender<UID>, uid: UID) {
        self.lock().restart(event_sender, uid)
    }

    /// Start the bootstrapping procedure.
    pub fn start_bootstrap(
        &mut self,
        blacklist: HashSet<SocketAddr>,
        user: CrustUser,
    ) -> Result<(), CrustError> {
        self.lock().start_bootstrap(blacklist, user);
        Ok(())
    }

    /// Stops the ongoing bootstrap. Note: This currently doesn't do anything, because mock
    /// bootstrap is not interruptible. This might change in the future, if needed.
    pub fn stop_bootstrap(&mut self) -> Result<(), CrustError> {
        // Nothing to do here, as mock bootstrapping is not interruptible.
        Ok(())
    }

    /// Start service discovery (beacon). Note: beacon is not yet implemented in mock.
    pub fn start_service_discovery(&mut self) {
        trace!(target: "crust", "[MOCK] start_service_discovery not implemented in mock.");
    }

    /// Enable listening and responding to peers searching for us. This will allow others finding us
    /// by interrogating the network. Note: `set_service_discovery_listen` is not yet implemented in
    /// mock.
    pub fn set_service_discovery_listen(&self, _listen: bool) {
        trace!(target: "crust", "[MOCK] set_service_discovery_listen not implemented in mock.");
    }

    /// Allow (or disallow) peers from bootstrapping off us.
    pub fn set_accept_bootstrap(&mut self, accept: bool) -> Result<(), CrustError> {
        self.lock().set_accept_bootstrap(accept);
        Ok(())
    }

    /// Check if we have peers on LAN.
    pub fn has_peers_on_lan(&self) -> bool {
        // This will allow mock crust test to have multiple nodes on the same machine
        false
    }

    /// Start TCP acceptor. Note: mock doesn't currently differentiate between TCP and UDP. As long
    /// as at least one is enabled, the service will accept any incoming connection.
    pub fn start_listening_tcp(&mut self) -> Result<(), CrustError> {
        self.lock().start_listening_tcp(LISTENER_PORT);
        Ok(())
    }

    /// Stops Listener explicitly and stops accepting TCP connections. Note: `stop_tcp_listener` is
    /// not yet implemented in mock.
    pub fn stop_tcp_listener(&mut self) -> Result<(), CrustError> {
        trace!(target: "crust", "[MOCK] stop_tcp_listener not implemented in mock.");
        Err(CrustError)
    }

    /// Request connection info structure used for establishing peer-to-peer connections.
    pub fn prepare_connection_info(&self, result_token: u32) {
        self.lock().prepare_connection_info(result_token)
    }

    /// Connect to a peer using our and their connection infos. The connection infos must be first
    /// prepared using `prepare_connection_info` on both our and their end.
    pub fn connect(
        &self,
        our_info: PrivConnectionInfo<UID>,
        their_info: PubConnectionInfo<UID>,
    ) -> Result<(), CrustError> {
        self.lock().connect(our_info, their_info);
        Ok(())
    }

    /// Disconnect from the given peer.
    pub fn disconnect(&self, uid: &UID) -> bool {
        self.lock().disconnect(uid)
    }

    /// Send message to the given peer.
    // TODO: Implement tests that drop low-priority messages.
    pub fn send(&self, uid: &UID, data: Vec<u8>, _priority: u8) -> Result<(), CrustError> {
        if self.lock().send_message(uid, data) {
            Ok(())
        } else {
            Err(CrustError)
        }
    }

    /// Return the IP address of the peer.
    pub fn get_peer_ip_addr(&self, uid: &UID) -> Result<IpAddr, CrustError> {
        self.lock().get_peer_ip_addr(uid).ok_or(CrustError)
    }

    /// Returns `true` if we are currently connected to the given `uid`.
    pub fn is_connected(&self, uid: &UID) -> bool {
        self.lock().is_peer_connected(uid)
    }

    /// Returns `true` if the specified peer's IP is hard-coded. (Always `true` in mock Crust.)
    pub fn is_peer_hard_coded(&self, _uid: &UID) -> bool {
        true
    }

    /// Our `UID`.
    pub fn id(&self) -> UID {
        unwrap!(self.lock().uid)
    }

    fn lock(&self) -> RefMut<ServiceImpl<UID>> {
        self.0.borrow_mut()
    }
}

impl<UID: Uid> Drop for Service<UID> {
    fn drop(&mut self) {
        if !thread::panicking() {
            self.lock().disconnect_all();
        }
    }
}

/// Mock version of `crust::Event`.
#[derive(Debug)]
pub enum Event<UID: Uid> {
    /// Invoked when a bootstrap peer connects to us
    BootstrapAccept(UID, CrustUser),
    /// Invoked when we bootstrap to a new peer.
    BootstrapConnect(UID, SocketAddr),
    /// Invoked when we failed to connect to all bootstrap contacts.
    BootstrapFailed,
    /// Invoked when we are ready to listen for incoming connection. Contains the listening port.
    ListenerStarted(u16),
    /// Invoked when listener failed to start.
    ListenerFailed,
    /// Invoked as a result to the call of `Service::prepare_contact_info`.
    ConnectionInfoPrepared(ConnectionInfoResult<UID>),
    /// Invoked when connection to a new peer has been established.
    ConnectSuccess(UID),
    /// Invoked when connection to a new peer has failed.
    ConnectFailure(UID),
    /// Invoked when a peer disconnects or can no longer be contacted.
    LostPeer(UID),
    /// Invoked when a new message is received. Passes the message.
    NewMessage(UID, CrustUser, Vec<u8>),
    /// Invoked when trying to sending a too large data.
    WriteMsgSizeProhibitive(UID, Vec<u8>),
}

/// Mock version of `CrustEventSender`.
pub type CrustEventSender<UID> = event_sender::MaidSafeObserver<Event<UID>>;

/// Trait for specifying a unique identifier for a Crust peer
pub trait Uid
    : 'static
    + Send
    + fmt::Debug
    + Clone
    + Copy
    + Eq
    + PartialEq
    + Ord
    + PartialOrd
    + Hash
    + Serialize
    + DeserializeOwned {
}

/// Mock version of `PrivConnectionInfo`, generated by a call to
/// `Service::prepare_contact_info`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivConnectionInfo<UID> {
    #[doc(hidden)]
    pub id: UID,
    #[doc(hidden)]
    pub endpoint: Endpoint,
}

impl<UID: Uid> PrivConnectionInfo<UID> {
    /// Convert our connection info to theirs so that we can give it to them.
    pub fn to_pub_connection_info(&self) -> PubConnectionInfo<UID> {
        PubConnectionInfo {
            id: self.id,
            endpoint: self.endpoint,
        }
    }
}

/// Mock version of `PubConnectionInfo`, used to connect to another peer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PubConnectionInfo<UID> {
    #[doc(hidden)]
    pub id: UID,
    #[doc(hidden)]
    pub endpoint: Endpoint,
}

impl<UID: Uid> PubConnectionInfo<UID> {
    /// The peer's Crust ID.
    pub fn id(&self) -> UID {
        self.id
    }
}

/// The result of a `Service::prepare_contact_info` call.
#[derive(Debug)]
pub struct ConnectionInfoResult<UID: Uid> {
    /// The token that was passed to `prepare_connection_info`.
    pub result_token: u32,
    /// The new contact info, if successful.
    pub result: Result<PrivConnectionInfo<UID>, CrustError>,
}

/// Mock version of `crust::CrustError`.
#[derive(Debug)]
pub struct CrustError;

/// Specify crust user. Behaviour (for example in bootstrap phase) will be different for different
/// variants. Node will request the Bootstrapee to connect back to this crust failing which it
/// would mean it's not reachable from outside and hence should be rejected bootstrap attempts.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CrustUser {
    /// Crust user is a Node and should not be allowed to bootstrap if it's not reachable from
    /// outside.
    Node,
    /// Crust user is a Client and should be allowed to bootstrap even if it's not reachable from
    /// outside.
    Client,
}

// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub use super::support::ConfigFile;
use super::support::{Endpoint, Network, ServiceHandle, ServiceImpl};
use maidsafe_utilities::event_sender;
use safe_crypto::{PublicKeys, SecretKeys};
use std::cell::{RefCell, RefMut};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::{fmt, thread};

/// TCP listener port
pub const LISTENER_PORT: u16 = 5485;

/// Mock version of config reader
pub fn read_config_file() -> Result<ConfigFile, CrustError> {
    Ok(ConfigFile::new())
}

/// Crust's compat API
pub mod compat {
    use super::*;

    /// Mock version of `crust::Service`
    pub struct Service(Rc<RefCell<ServiceImpl>>, Network);

    impl Service {
        /// Create new mock `Service` using the make_current/get_current mechanism to get the associated
        /// `ServiceHandle`.
        pub fn new(
            handle: ServiceHandle,
            event_sender: CrustEventSender,
            full_id: SecretKeys,
        ) -> Result<Self, CrustError> {
            Self::with_handle(&handle, event_sender, full_id)
        }

        /// Create a new mock `Service` using the make_current/get_current mechanism to get the
        /// associated `ServiceHandle`. Ignores configuration.
        pub fn with_config(
            handle: ServiceHandle,
            event_sender: CrustEventSender,
            _config: ConfigFile,
            full_id: SecretKeys,
        ) -> Result<Self, CrustError> {
            Self::with_handle(&handle, event_sender, full_id)
        }

        /// Create new mock `Service` by explicitly passing the mock device to associate with.
        pub fn with_handle(
            handle: &ServiceHandle,
            event_sender: CrustEventSender,
            full_id: SecretKeys,
        ) -> Result<Self, CrustError> {
            let network = handle.0.borrow().network.clone();
            let service = Service(Rc::clone(&handle.0), network);
            service.lock().start(event_sender, full_id);

            Ok(service)
        }

        /// This method is used instead of dropping the service and creating a new one, which is the
        /// current practice with the real crust.
        pub fn restart(&self, event_sender: CrustEventSender, full_id: SecretKeys) {
            self.lock().restart(event_sender, full_id)
        }

        /// Start the bootstrapping procedure.
        pub fn start_bootstrap(
            &self,
            blacklist: HashSet<PaAddr>,
            user: CrustUser,
        ) -> Result<(), CrustError> {
            self.lock().start_bootstrap(blacklist, user);
            Ok(())
        }

        /// Stops the ongoing bootstrap. Note: This currently doesn't do anything, because mock
        /// bootstrap is not interruptible. This might change in the future, if needed.
        pub fn stop_bootstrap(&self) -> Result<(), CrustError> {
            // Nothing to do here, as mock bootstrapping is not interruptible.
            Ok(())
        }

        /// Start service discovery (beacon). Note: beacon is not yet implemented in mock.
        pub fn start_service_discovery(&self) {
            trace!(target: "crust", "[MOCK] start_service_discovery not implemented in mock.");
        }

        /// Enable listening and responding to peers searching for us. This will allow others finding us
        /// by interrogating the network. Note: `set_service_discovery_listen` is not yet implemented in
        /// mock.
        pub fn set_service_discovery_listen(&self, _listen: bool) {
            trace!(target: "crust", "[MOCK] set_service_discovery_listen not implemented in mock.");
        }

        /// Allow (or disallow) peers from bootstrapping off us.
        pub fn set_accept_bootstrap(&self, accept: bool) -> Result<(), CrustError> {
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
        pub fn start_listening(&self) -> Result<(), CrustError> {
            self.lock().start_listening();
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
            our_info: PubConnectionInfo,
            their_info: PubConnectionInfo,
        ) -> Result<(), CrustError> {
            self.lock().connect(our_info, their_info);
            Ok(())
        }

        /// Disconnect from the given peer.
        pub fn disconnect(&self, pub_id: &PublicKeys) -> bool {
            self.lock().disconnect(pub_id)
        }

        /// Send message to the given peer.
        // TODO: Implement tests that drop low-priority messages.
        pub fn send(
            &self,
            pub_id: &PublicKeys,
            data: Vec<u8>,
            _priority: u8,
        ) -> Result<(), CrustError> {
            if self.lock().send_message(pub_id, data) {
                Ok(())
            } else {
                Err(CrustError)
            }
        }

        /// Return the IP address of the peer.
        pub fn get_peer_ip_addr(&self, pub_id: &PublicKeys) -> Result<IpAddr, CrustError> {
            self.lock().get_peer_ip_addr(pub_id).ok_or(CrustError)
        }

        /// Returns `true` if we are currently connected to the given `pub_id`.
        pub fn is_connected(&self, pub_id: &PublicKeys) -> bool {
            self.lock().is_peer_connected(pub_id)
        }

        /// Returns `true` if the specified peer's IP is hard-coded. (Always `true` in mock Crust.)
        pub fn is_peer_hard_coded(&self, _pub_id: &PublicKeys) -> bool {
            true
        }

        /// Our `PublicKeys`.
        pub fn public_id(&self) -> PublicKeys {
            unwrap!(self.lock().full_id.as_ref()).public_keys().clone()
        }

        fn lock(&self) -> RefMut<ServiceImpl> {
            self.0.borrow_mut()
        }
    }

    impl Drop for Service {
        fn drop(&mut self) {
            if !thread::panicking() {
                self.lock().disconnect_all();
            }
        }
    }

    /// Mock version of `crust::Event`.
    #[derive(Debug)]
    pub enum Event {
        /// Invoked when a bootstrap peer connects to us
        BootstrapAccept(PublicKeys, CrustUser),
        /// Invoked when we bootstrap to a new peer.
        BootstrapConnect(PublicKeys, PaAddr),
        /// Invoked when we failed to connect to all bootstrap contacts.
        BootstrapFailed,
        /// Invoked when we are ready to listen for incoming connection. Contains the listening address.
        ListenerStarted(PaAddr),
        /// Invoked when listener failed to start.
        ListenerFailed,
        /// Invoked as a result to the call of `Service::prepare_contact_info`.
        ConnectionInfoPrepared(ConnectionInfoResult),
        /// Invoked when connection to a new peer has been established.
        ConnectSuccess(PublicKeys),
        /// Invoked when connection to a new peer has failed.
        ConnectFailure(PublicKeys),
        /// Invoked when a peer disconnects or can no longer be contacted.
        LostPeer(PublicKeys),
        /// Invoked when a new message is received. Passes the message.
        NewMessage(PublicKeys, CrustUser, Vec<u8>),
        /// Invoked when trying to sending a too large data.
        WriteMsgSizeProhibitive(PublicKeys, Vec<u8>),
    }

    /// Mock version of `CrustEventSender`.
    pub type CrustEventSender = event_sender::MaidSafeObserver<Event>;

    /// The result of a `Service::prepare_contact_info` call.
    #[derive(Debug)]
    pub struct ConnectionInfoResult {
        /// The token that was passed to `prepare_connection_info`.
        pub result_token: u32,
        /// The new contact info, if successful.
        pub result: Result<PubConnectionInfo, CrustError>,
    }
}

/// Mock version of `PrivConnectionInfo`, generated by a call to
/// `Service::prepare_contact_info`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivConnectionInfo {
    #[doc(hidden)]
    pub id: PublicKeys,
    #[doc(hidden)]
    pub endpoint: Endpoint,
}

impl PrivConnectionInfo {
    /// Convert our connection info to theirs so that we can give it to them.
    pub fn to_pub_connection_info(&self) -> PubConnectionInfo {
        PubConnectionInfo {
            id: self.id.clone(),
            endpoint: self.endpoint,
        }
    }
}

/// Mock version of `PubConnectionInfo`, used to connect to another peer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PubConnectionInfo {
    #[doc(hidden)]
    pub id: PublicKeys,
    #[doc(hidden)]
    pub endpoint: Endpoint,
}

impl PubConnectionInfo {
    /// The peer's Crust ID.
    pub fn id(&self) -> PublicKeys {
        self.id.clone()
    }
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

/// Protocol agnostic address.
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum PaAddr {
    /// TCP socket address.
    Tcp(SocketAddr),
    /// uTP socket address.
    Utp(SocketAddr),
}

impl fmt::Display for PaAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PaAddr::Tcp(ref addr) => write!(f, "tcp://{}", addr),
            PaAddr::Utp(ref addr) => write!(f, "utp://{}", addr),
        }
    }
}

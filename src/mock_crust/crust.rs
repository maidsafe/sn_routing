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
use rand::{Rand, Rng};
use std::cell::{RefCell, RefMut};
use std::fmt;
use std::io;
use std::rc::Rc;

use super::support::{self, Endpoint, Network, ServiceHandle, ServiceImpl};

/// Default beacon (service discovery) port.
pub const DEFAULT_BEACON_PORT: u16 = 5484;

/// Mock version of crust::Service
pub struct Service(Rc<RefCell<ServiceImpl>>, Network);

impl Service {
    /// Create new mock Service using the make_current/get_current mechanism to
    /// get the associated ServiceHandle.
    pub fn new(event_sender: CrustEventSender) -> Result<Self, Error> {
        Self::with_handle(&support::get_current(), event_sender, DEFAULT_BEACON_PORT)
    }

    /// Create new mock Service by explicitly passing the mock device to associate
    /// with.
    pub fn with_handle(handle: &ServiceHandle,
                       event_sender: CrustEventSender,
                       beacon_port: u16)
                       -> Result<Self, Error> {
        let network = handle.0.borrow().network.clone();
        let service = Service(handle.0.clone(), network);
        service.lock_and_poll(|imp| imp.start(event_sender, beacon_port));

        Ok(service)
    }

    /// This method is used instead of dropping the service and creating a new
    /// one, which is the current practice with the real crust.
    pub fn restart(&self, event_sender: CrustEventSender) {
        self.lock_and_poll(|imp| imp.restart(event_sender, DEFAULT_BEACON_PORT))
    }

    /// Stops the ongoing bootstrap.
    /// Note: This currently doesn't do anything, because mock bootstrap is
    /// not interruptible. This might change in the future, if needed.
    pub fn stop_bootstrap(&self) {
        // Nothing to do here, as mock bootstrapping is not interruptible.
    }

    /// Start service discovery (beacon).
    /// Note: beacon is not yet implemented in mock.
    pub fn start_service_discovery(&mut self) {
        trace!("[MOCK] start_service_discovery not implemented in mock");
    }

    /// Start TCP acceptor.
    /// Note: mock doesn't currently differentiate between TCP and UDP. As long
    /// as at least one is enabled, the service will accept any incomming
    /// connection.
    pub fn start_listening_tcp(&mut self) -> io::Result<()> {
        self.lock().listening_tcp = true;
        Ok(())
    }

    /// Start uTP acceptor.
    /// Note: mock doesn't currently differentiate between TCP and UDP. As long
    /// as at least one is enabled, the service will accept any incomming
    /// connection.
    pub fn start_listening_utp(&mut self) -> io::Result<()> {
        self.lock().listening_udp = true;
        Ok(())
    }

    /// Request connection info structure used for establishing peer-to-peer
    /// connections.
    pub fn prepare_connection_info(&mut self, result_token: u32) {
        self.lock_and_poll(|imp| imp.prepare_connection_info(result_token))
    }

    /// Connect to a peer using our and their connection infos. The connection
    /// infos must be first prepared using `prepare_connection_info` on both
    /// our and their end.
    pub fn connect(&self, our_info: OurConnectionInfo, their_info: TheirConnectionInfo) {
        self.lock_and_poll(|imp| imp.connect(our_info, their_info))
    }

    /// Disconnect from the given peer.
    pub fn disconnect(&self, peer_id: &PeerId) -> bool {
        self.lock_and_poll(|imp| imp.disconnect(peer_id))
    }

    /// Send message to the given peer.
    pub fn send(&self, id: &PeerId, data: Vec<u8>) -> io::Result<()> {
        if self.lock_and_poll(|imp| imp.send_message(id, data)) {
            Ok(())
        } else {
            let msg = format!("No connection to peer {:?}", id);
            Err(io::Error::new(io::ErrorKind::Other, msg))
        }
    }

    /// Out PeerId.
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

/// Mock version of crust::PeerId.
///
/// First element is the endpoint number of the peer (for easier log
/// diagnostics), second one is some random number so the PeerId is different
/// after restart.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, RustcEncodable, RustcDecodable)]
pub struct PeerId(pub usize, pub u64);

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Ignore the random number, as it would only clutter the debug output.
        write!(f, "PeerId({})", self.0)
    }
}

impl Rand for PeerId {
    fn rand<R: Rng>(rng: &mut R) -> PeerId {
        PeerId(Rand::rand(rng), Rand::rand(rng))
    }
}

/// Mock version of crust::Event.
#[derive(Debug)]
pub enum Event {
    /// Invoked when a new message is received.  Passes the message.
    NewMessage(PeerId, Vec<u8>),
    /// Invoked when we get a bootstrap connection to a new peer.
    BootstrapConnect(PeerId),
    /// Invoked when a bootstrap peer connects to us
    BootstrapAccept(PeerId),
    /// Invoked when a connection to a new peer is established.
    NewPeer(io::Result<()>, PeerId),
    /// Invoked when a peer is lost.
    LostPeer(PeerId),
    /// Invoked once the list of bootstrap contacts is exhausted.
    BootstrapFinished,
    /// Invoked as a result to the call of `Service::prepare_contact_info`.
    ConnectionInfoPrepared(ConnectionInfoResult),
}

/// Mock version of CrustEventSender.
pub type CrustEventSender = event_sender::MaidSafeObserver<Event>;

/// Mock version of OurConnectionInfo, generated by a call to
/// `Service::prepare_contact_info`.
#[derive(Debug)]
pub struct OurConnectionInfo(pub PeerId, pub Endpoint);

impl OurConnectionInfo {
    /// Convert our connection info to theirs so that we can give it to them.
    pub fn to_their_connection_info(&self) -> TheirConnectionInfo {
        TheirConnectionInfo(self.0, self.1)
    }
}

/// Mock version of TheirConnectionInfo, used to connect to another peer.
#[derive(Debug, RustcEncodable, RustcDecodable)]
pub struct TheirConnectionInfo(pub PeerId, pub Endpoint);

impl TheirConnectionInfo {
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
    pub result: io::Result<OurConnectionInfo>,
}

/// Mock version of crust::Error.
#[derive(Debug)]
pub struct Error;

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
use std::fmt;
use std::io;
use std::rc::Rc;

use super::support::{self, Endpoint, Network, ServiceHandle, ServiceImpl};

/// Mock version of crust::Service
pub struct Service(Rc<RefCell<ServiceImpl>>, Network);

impl Service {
    /// Create new mock Service using the make_current/get_current mechanism to
    /// get the associated ServiceHandle.
    pub fn new(event_sender: CrustEventSender, beacon_port: u16) -> Result<Self, Error> {
        Self::with_handle(&support::get_current(), event_sender, beacon_port)
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
    pub fn restart(&self, event_sender: CrustEventSender, beacon_port: u16) {
        self.lock_and_poll(|imp| imp.restart(event_sender, beacon_port))
    }

    pub fn stop_bootstrap(&self) {
        // Nothing to do here, as mock bootstrapping is not interruptible.
    }

    pub fn start_service_discovery(&mut self) {
        trace!("[MOCK] start_service_discovery not implemented in mock");
    }

    pub fn start_listening_tcp(&mut self) -> io::Result<()> {
        self.lock().listening_tcp = true;
        Ok(())
    }

    pub fn start_listening_utp(&mut self) -> io::Result<()> {
        self.lock().listening_udp = true;
        Ok(())
    }

    pub fn prepare_connection_info(&mut self, result_token: u32) {
        self.lock_and_poll(|imp| imp.prepare_connection_info(result_token))
    }

    pub fn connect(&self, our_info: OurConnectionInfo, their_info: TheirConnectionInfo) {
        self.lock_and_poll(|imp| imp.connect(our_info, their_info))
    }

    pub fn disconnect(&self, peer_id: &PeerId) -> bool {
        self.lock_and_poll(|imp| imp.disconnect(peer_id))
    }

    pub fn send(&self, id: &PeerId, data: Vec<u8>) -> io::Result<()> {
        if self.lock_and_poll(|imp| imp.send_message(id, data)) {
            Ok(())
        } else {
            let msg = format!("No connection to peer {:?}", id);
            Err(io::Error::new(io::ErrorKind::Other, msg))
        }
    }

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

#[derive(Debug)]
pub enum Event {
    NewMessage(PeerId, Vec<u8>),
    BootstrapConnect(PeerId),
    BootstrapAccept(PeerId),
    NewPeer(io::Result<()>, PeerId),
    LostPeer(PeerId),
    BootstrapFinished,
    ConnectionInfoPrepared(ConnectionInfoResult),
}

pub type CrustEventSender = event_sender::MaidSafeObserver<Event>;

#[derive(Debug)]
pub struct OurConnectionInfo(pub PeerId, pub Endpoint);

impl OurConnectionInfo {
    pub fn to_their_connection_info(&self) -> TheirConnectionInfo {
        TheirConnectionInfo(self.0, self.1)
    }
}

#[derive(Debug, RustcEncodable, RustcDecodable)]
pub struct TheirConnectionInfo(pub PeerId, pub Endpoint);

impl TheirConnectionInfo {
    pub fn id(&self) -> PeerId {
        self.0
    }
}

#[derive(Debug)]
pub struct ConnectionInfoResult {
    pub result_token: u32,
    pub result: io::Result<OurConnectionInfo>,
}

#[derive(Debug)]
pub struct Error;

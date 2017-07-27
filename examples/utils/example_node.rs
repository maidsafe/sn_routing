// Copyright 2015 MaidSafe.net limited.
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

use lru_time_cache::LruCache;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Authority, ClientError, Event, EventStream, ImmutableData, MessageId, MutableData,
              Node, Prefix, Request, Response, XorName};
use std::collections::HashMap;
use std::time::Duration;

/// A simple example node implementation for a network based on the Routing library.
pub struct ExampleNode {
    /// The node interface to the Routing library.
    node: Node,
    idata_store: HashMap<XorName, ImmutableData>,
    mdata_store: HashMap<(XorName, u64), MutableData>,
    client_accounts: HashMap<XorName, u64>,
    request_cache: LruCache<MessageId, (Authority<XorName>, Authority<XorName>)>,
}

impl ExampleNode {
    /// Creates a new node and attempts to establish a connection to the network.
    pub fn new(first: bool) -> ExampleNode {
        let node = unwrap!(Node::builder().first(first).create());

        ExampleNode {
            node: node,
            idata_store: HashMap::new(),
            mdata_store: HashMap::new(),
            client_accounts: HashMap::new(),
            request_cache: LruCache::with_expiry_duration(Duration::from_secs(60 * 10)),
        }
    }

    /// Runs the event loop, handling events raised by the Routing library.
    pub fn run(&mut self) {
        while let Ok(event) = self.node.next_ev() {
            match event {
                Event::Request { request, src, dst } => self.handle_request(request, src, dst),
                Event::Response { response, src, dst } => self.handle_response(response, src, dst),
                Event::NodeAdded(name, _routing_table) => {
                    trace!(
                        "{} Received NodeAdded event {:?}",
                        self.get_debug_name(),
                        name
                    );
                    self.handle_node_added(name);
                }
                Event::NodeLost(name, _routing_table) => {
                    trace!(
                        "{} Received NodeLost event {:?}",
                        self.get_debug_name(),
                        name
                    );
                }
                Event::Connected => {
                    trace!("{} Received connected event", self.get_debug_name());
                }
                Event::Terminate => {
                    info!("{} Received Terminate event", self.get_debug_name());
                    break;
                }
                Event::RestartRequired => {
                    info!("{} Received RestartRequired event", self.get_debug_name());
                    self.node = unwrap!(Node::builder().create());
                }
                Event::SectionSplit(prefix) => {
                    trace!(
                        "{} Received SectionSplit event {:?}",
                        self.get_debug_name(),
                        prefix
                    );
                    self.handle_split(prefix);
                }
                Event::SectionMerge(prefix) => {
                    trace!(
                        "{} Received SectionMerge event {:?}",
                        self.get_debug_name(),
                        prefix
                    );
                    let pfx = Prefix::new(prefix.bit_count() + 1, *unwrap!(self.node.id()).name());
                    self.send_refresh(MessageId::from_lost_node(pfx.lower_bound()));
                }
                event => {
                    trace!("{} Received {:?} event", self.get_debug_name(), event);
                }
            }
        }
    }

    fn handle_request(
        &mut self,
        request: Request,
        src: Authority<XorName>,
        dst: Authority<XorName>,
    ) {
        match request {
            Request::Refresh(payload, msg_id) => self.handle_refresh(payload, msg_id),
            Request::GetIData { name, msg_id } => {
                self.handle_get_idata_request(src, dst, name, msg_id)
            }
            Request::PutIData { data, msg_id } => {
                self.handle_put_idata_request(src, dst, data, msg_id)
            }
            Request::GetMDataShell { name, tag, msg_id } => {
                self.handle_get_mdata_shell_request(src, dst, name, tag, msg_id)
            }
            Request::ListMDataEntries { name, tag, msg_id } => {
                self.handle_list_mdata_entries_request(src, dst, name, tag, msg_id)
            }
            Request::GetMDataValue {
                name,
                tag,
                key,
                msg_id,
            } => self.handle_get_mdata_value_request(src, dst, name, tag, key, msg_id),
            _ => {
                warn!(
                    "{:?} ExampleNode: handle for {:?} unimplemented.",
                    self.get_debug_name(),
                    request
                );
            }
        }
    }

    fn handle_response(
        &mut self,
        response: Response,
        _src: Authority<XorName>,
        dst: Authority<XorName>,
    ) {
        match (response, dst) {
            (Response::PutIData { res, msg_id }, Authority::ClientManager(_)) => {
                if let Some((src, dst)) = self.request_cache.remove(&msg_id) {
                    unwrap!(self.node.send_put_idata_response(src, dst, res, msg_id));
                }
            }
            (Response::PutMData { res, msg_id }, Authority::ClientManager(_)) => {
                if let Some((src, dst)) = self.request_cache.remove(&msg_id) {
                    unwrap!(self.node.send_put_mdata_response(src, dst, res, msg_id));
                }
            }
            _ => unreachable!(),
        }
    }

    fn handle_get_idata_request(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        name: XorName,
        msg_id: MessageId,
    ) {
        match (src, dst) {
            (src @ Authority::Client { .. }, dst @ Authority::NaeManager(_)) => {
                let res = if let Some(data) = self.idata_store.get(&name) {
                    Ok(data.clone())
                } else {
                    trace!(
                        "{:?} GetIData request failed for {:?}.",
                        self.get_debug_name(),
                        name
                    );
                    Err(ClientError::NoSuchData)
                };

                unwrap!(self.node.send_get_idata_response(dst, src, res, msg_id))
            }
            (src, dst) => unreachable!("Wrong Src and Dest Authority {:?} - {:?}", src, dst),
        }
    }

    fn handle_put_idata_request(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        data: ImmutableData,
        msg_id: MessageId,
    ) {
        match dst {
            Authority::NaeManager(_) => {
                trace!(
                    "{:?} Storing : key {:?}, value {:?}",
                    self.get_debug_name(),
                    data.name(),
                    data
                );
                let _ = self.idata_store.insert(*data.name(), data);
                let _ = self.node.send_put_idata_response(dst, src, Ok(()), msg_id);
            }
            Authority::ClientManager(_) => {
                trace!(
                    "{:?} Put Request: Updating ClientManager: key {:?}, value {:?}",
                    self.get_debug_name(),
                    data.name(),
                    data
                );
                if self.request_cache.insert(msg_id, (dst, src)).is_none() {
                    let src = dst;
                    let dst = Authority::NaeManager(*data.name());
                    unwrap!(self.node.send_put_idata_request(src, dst, data, msg_id));
                } else {
                    warn!("Attempt to reuse message ID {:?}.", msg_id);
                    unwrap!(self.node.send_put_idata_response(
                        dst,
                        src,
                        Err(ClientError::InvalidOperation),
                        msg_id,
                    ));
                }

            }
            _ => unreachable!("ExampleNode: Unexpected dst ({:?})", dst),
        }
    }

    fn handle_get_mdata_shell_request(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) {
        match (src, dst) {
            (src @ Authority::Client { .. }, dst @ Authority::NaeManager(_)) => {
                let res = if let Some(data) = self.mdata_store.get(&(name, tag)) {
                    Ok(data.shell())
                } else {
                    trace!("{:?} GetMDataShell request failed for {:?}.",
                           self.get_debug_name(),
                           (name, tag));
                    Err(ClientError::NoSuchData)
                };

                unwrap!(self.node.send_get_mdata_shell_response(
                    dst,
                    src,
                    res,
                    msg_id,
                ))
            }
            (src, dst) => unreachable!("Wrong Src and Dest Authority {:?} - {:?}", src, dst),
        }
    }

    fn handle_list_mdata_entries_request(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) {
        match (src, dst) {
            (src @ Authority::Client { .. }, dst @ Authority::NaeManager(_)) => {
                let res = if let Some(data) = self.mdata_store.get(&(name, tag)) {
                    Ok(data.entries().clone())
                } else {
                    trace!("{:?} ListMDataEntries request failed for {:?}.",
                           self.get_debug_name(),
                           (name, tag));
                    Err(ClientError::NoSuchData)
                };

                unwrap!(self.node.send_list_mdata_entries_response(
                    dst,
                    src,
                    res,
                    msg_id,
                ))
            }
            (src, dst) => unreachable!("Wrong Src and Dest Authority {:?} - {:?}", src, dst),
        }
    }

    fn handle_get_mdata_value_request(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        key: Vec<u8>,
        msg_id: MessageId,
    ) {
        match (src, dst) {
            (src @ Authority::Client { .. }, dst @ Authority::NaeManager(_)) => {
                let res = self.mdata_store
                    .get(&(name, tag))
                    .ok_or(ClientError::NoSuchData)
                    .and_then(|data| {
                        data.get(&key).cloned().ok_or(ClientError::NoSuchEntry)
                    })
                    .map_err(|error| {
                        trace!("{:?} GetMDataValue request failed for {:?}.",
                                        self.get_debug_name(),
                                        (name, tag));
                        error
                    });

                unwrap!(self.node.send_get_mdata_value_response(
                    dst,
                    src,
                    res,
                    msg_id,
                ))
            }
            (src, dst) => unreachable!("Wrong Src and Dest Authority {:?} - {:?}", src, dst),
        }
    }

    fn handle_node_added(&mut self, name: XorName) {
        self.send_refresh(MessageId::from_added_node(name));
    }

    fn handle_split(&mut self, prefix: Prefix<XorName>) {
        let deleted_clients: Vec<_> = self.client_accounts
            .iter()
            .filter(|&(client_name, _)| !prefix.matches(client_name))
            .map(|(client_name, _)| *client_name)
            .collect();
        for client in &deleted_clients {
            let _ = self.client_accounts.remove(client);
        }

        let deleted_data: Vec<_> = self.idata_store
            .iter()
            .filter(|&(name, _)| !prefix.matches(name))
            .map(|(name, _)| *name)
            .collect();
        for id in &deleted_data {
            let _ = self.idata_store.remove(id);
        }

        let deleted_data: Vec<_> = self.mdata_store
            .iter()
            .filter(|&(&(ref name, _), _)| !prefix.matches(name))
            .map(|(id, _)| *id)
            .collect();
        for id in &deleted_data {
            let _ = self.mdata_store.remove(id);
        }
    }

    fn send_refresh(&mut self, msg_id: MessageId) {
        for (client_name, stored) in &self.client_accounts {
            let content = RefreshContent::Account {
                client_name: *client_name,
                data: *stored,
            };
            let content = unwrap!(serialise(&content));
            let auth = Authority::ClientManager(*client_name);
            unwrap!(self.node.send_refresh_request(auth, auth, content, msg_id));
        }

        for data in self.idata_store.values() {
            let refresh_content = RefreshContent::ImmutableData(data.clone());
            let content = unwrap!(serialise(&refresh_content));
            let auth = Authority::NaeManager(*data.name());
            unwrap!(self.node.send_refresh_request(auth, auth, content, msg_id));
        }

        for data in self.mdata_store.values() {
            let content = RefreshContent::MutableData(data.clone());
            let content = unwrap!(serialise(&content));
            let auth = Authority::NaeManager(*data.name());
            unwrap!(self.node.send_refresh_request(auth, auth, content, msg_id));
        }
    }

    /// Receiving a refresh message means that a quorum has been reached: Enough other members in
    /// the section agree, so we need to update our data accordingly.
    fn handle_refresh(&mut self, content: Vec<u8>, _id: MessageId) {
        match unwrap!(deserialise(&content)) {
            RefreshContent::Account { client_name, data } => {
                trace!(
                    "{:?} handle_refresh for account. client name: {:?}",
                    self.get_debug_name(),
                    client_name
                );
                let _ = self.client_accounts.insert(client_name, data);
            }
            RefreshContent::ImmutableData(data) => {
                trace!(
                    "{:?} handle_refresh for immutable data. name: {:?}",
                    self.get_debug_name(),
                    data.name()
                );
                let _ = self.idata_store.insert(*data.name(), data);
            }
            RefreshContent::MutableData(data) => {
                trace!(
                    "{:?} handle_refresh for mutable data. name: {:?}, tag: {}",
                    self.get_debug_name(),
                    data.name(),
                    data.tag()
                );
                let _ = self.mdata_store.insert((*data.name(), data.tag()), data);
            }
        }
    }

    fn get_debug_name(&self) -> String {
        match self.node.id() {
            Ok(id) => format!("Node({:?})", id.name()),
            Err(err) => {
                error!("Could not get node name - {:?}", err);
                "Node(unknown)".to_owned()
            }
        }
    }
}

/// Refresh messages.
#[derive(Serialize, Deserialize)]
enum RefreshContent {
    Account { client_name: XorName, data: u64 },
    ImmutableData(ImmutableData),
    MutableData(MutableData),
}

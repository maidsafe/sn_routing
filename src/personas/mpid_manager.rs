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

use std::collections::HashMap;

use chunk_store::ChunkStore;
use default_chunk_store;
use error::{ClientError, InternalError};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use mpid_messaging::{MAX_INBOX_SIZE, MAX_OUTBOX_SIZE, MpidHeader, MpidMessage, MpidMessageWrapper};
use routing::{Authority, Data, PlainData, RequestContent, RequestMessage};
use sodiumoxide::crypto::sign::PublicKey;
use sodiumoxide::crypto::hash::sha512;
use types::{Refresh, RefreshValue};
use utils;
use vault::RoutingNode;
use xor_name::XorName;

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
struct MailBox {
    allowance: u64,
    used_space: u64,
    space_available: u64,
    // key: msg or header's name; value: sender's public key
    mail_box: HashMap<XorName, Option<PublicKey>>,
}

impl MailBox {
    fn new(allowance: u64) -> MailBox {
        MailBox {
            allowance: allowance,
            used_space: 0,
            space_available: allowance,
            mail_box: HashMap::new(),
        }
    }


    fn put(&mut self, size: u64, entry: &XorName, public_key: &Option<PublicKey>) -> bool {
        if size > self.space_available {
            return false;
        }

        match self.mail_box.insert(entry.clone(), public_key.clone()) {
            Some(_) => false,
            None => {
                self.used_space += size;
                self.space_available -= size;
                true
            }
        }
    }

    fn remove(&mut self, size: u64, entry: &XorName) -> bool {
        match self.mail_box.remove(entry) {
            Some(_) => {
                self.used_space -= size;
                self.space_available += size;
                true
            }
            None => false,
        }
    }

    fn contains_key(&self, entry: &XorName) -> bool {
        self.mail_box.contains_key(entry)
    }

    fn names(&self) -> Vec<XorName> {
        self.mail_box.iter().map(|pair| pair.0.clone()).collect()
    }
}

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct Account {
    // account owners' registered client proxies
    clients: Vec<Authority>,
    inbox: MailBox,
    outbox: MailBox,
}

impl Default for Account {
    // FIXME: Account Creation process required
    //   To bypass the the process for a simple network, allowance is granted by default
    fn default() -> Account {
        Account {
            clients: Vec::new(),
            inbox: MailBox::new(MAX_INBOX_SIZE as u64),
            outbox: MailBox::new(MAX_OUTBOX_SIZE as u64),
        }
    }
}

impl Account {
    fn put_into_outbox(&mut self,
                       size: u64,
                       entry: &XorName,
                       public_key: &Option<PublicKey>)
                       -> bool {
        self.outbox.put(size, entry, public_key)
    }

    fn put_into_inbox(&mut self,
                      size: u64,
                      entry: &XorName,
                      public_key: &Option<PublicKey>)
                      -> bool {
        self.inbox.put(size, entry, public_key)
    }

    fn remove_from_outbox(&mut self, size: u64, entry: &XorName) -> bool {
        self.outbox.remove(size, entry)
    }

    fn remove_from_inbox(&mut self, size: u64, entry: &XorName) -> bool {
        self.inbox.remove(size, entry)
    }

    fn has_in_outbox(&self, entry: &XorName) -> bool {
        self.outbox.contains_key(entry)
    }

    fn register_online(&mut self, client: &Authority) {
        match client.clone() {
            Authority::Client { .. } => {
                if self.clients.contains(&client) {
                    warn!("client {:?} already registered", client)
                } else {
                    self.clients.push(client.clone());
                }
            }
            _ => warn!("trying to register non-client {:?} as client", client),
        }
    }

    fn received_headers(&self) -> Vec<XorName> {
        self.inbox.names()
    }

    fn stored_messages(&self) -> Vec<XorName> {
        self.outbox.names()
    }

    fn registered_clients(&self) -> &Vec<Authority> {
        &self.clients
    }
}

pub struct MpidManager {
    accounts: HashMap<XorName, Account>,
    chunk_store_inbox: ChunkStore,
    chunk_store_outbox: ChunkStore,
}

impl MpidManager {
    pub fn new() -> MpidManager {
        MpidManager {
            accounts: HashMap::new(),
            chunk_store_inbox: default_chunk_store::new().unwrap(),
            chunk_store_outbox: default_chunk_store::new().unwrap(),
        }
    }

    // The name of the PlainData is expected to be the mpidheader or mpidmessage name
    // The content of the PlainData is execpted to be the serialised MpidMessageWrapper
    // holding mpidheader or mpidmessage
    pub fn handle_put(&mut self,
                      routing_node: &RoutingNode,
                      request: &RequestMessage)
                      -> Result<(), InternalError> {
        let (data, message_id) = match request.content {
            RequestContent::Put(Data::Plain(ref data), ref message_id) => {
                (data.clone(), message_id.clone())
            }
            _ => unreachable!("Error in vault demuxing"),
        };
        let mpid_message_wrapper: MpidMessageWrapper = try!(deserialise(&data.value()));
        match mpid_message_wrapper {
            MpidMessageWrapper::PutHeader(mpid_header) => {
                if self.chunk_store_inbox.has_chunk(&data.name()) {
                    return Err(InternalError::Client(ClientError::DataExists));
                }

                let serialised_header = try!(serialise(&mpid_header));
                if let Some(ref mut account) = self.accounts.get_mut(&request.dst.name().clone()) {
                    // Client is online.
                    // TODO: how the sender's public key get retained?
                    if account.put_into_inbox(serialised_header.len() as u64, &data.name(), &None) {
                        try!(self.chunk_store_inbox.put(&data.name(), &serialised_header[..]));
                        let dst = Authority::ClientManager(mpid_header.sender().clone());
                        let wrapper = MpidMessageWrapper::GetMessage(mpid_header.clone());
                        let value = try!(serialise(&wrapper));
                        let name = try!(mpid_header.name());
                        let data = Data::Plain(PlainData::new(name, value));
                        try!(routing_node.send_post_request(request.dst.clone(),
                                                            dst,
                                                            data,
                                                            message_id.clone()));
                        return Ok(());
                    } else {
                        try!(routing_node.send_put_failure(request.dst.clone(),
                                                           request.src.clone(),
                                                           request.clone(),
                                                           Vec::new(),
                                                           message_id));
                        return Ok(());
                    }
                }

                if self.accounts
                       .entry(request.dst.name().clone())
                       .or_insert(Account::default())
                       .put_into_inbox(serialised_header.len() as u64, &data.name(), &None) {
                    try!(self.chunk_store_inbox.put(&data.name(), &serialised_header[..]));
                } else {
                    try!(routing_node.send_put_failure(request.dst.clone(),
                                                       request.src.clone(),
                                                       request.clone(),
                                                       Vec::new(),
                                                       message_id));
                }
            }
            MpidMessageWrapper::PutMessage(mpid_message) => {
                if let Some(ref mut account) = self.accounts.get_mut(&request.dst.name().clone()) {
                    if self.chunk_store_outbox.has_chunk(&data.name()) {
                        return Err(InternalError::Client(ClientError::DataExists));
                    }
                    let serialised_message = try!(serialise(&mpid_message));
                    if let Authority::Client { client_key, .. } = request.src {
                        if !account.put_into_outbox(serialised_message.len() as u64,
                                                    &data.name(),
                                                    &Some(client_key)) {
                            try!(routing_node.send_put_failure(request.dst.clone(),
                                                               request.src.clone(),
                                                               request.clone(),
                                                               Vec::new(),
                                                               message_id));
                            return Ok(());
                        }
                    };
                    try!(self.chunk_store_outbox.put(&data.name(), &serialised_message[..]));
                    // Send notification to receiver's MpidManager
                    let src = request.dst.clone();
                    let dst = Authority::ClientManager(mpid_message.recipient().clone());
                    let wrapper = MpidMessageWrapper::PutHeader(mpid_message.header().clone());
                    let serialised_wrapper = try!(serialise(&wrapper));
                    let name = try!(mpid_message.header().name());
                    let notification = Data::Plain(PlainData::new(name, serialised_wrapper));
                    try!(routing_node.send_put_request(src, dst, notification, message_id.clone()));
                    // Send put success to Client.
                    let src = request.dst.clone();
                    let dst = request.src.clone();
                    let digest = sha512::hash(&try!(serialise(request))[..]);
                    let _ = routing_node.send_put_success(src, dst, digest, message_id);
                } else {
                    // Client not registered online.
                    try!(routing_node.send_put_failure(request.dst.clone(),
                                                       request.src.clone(),
                                                       request.clone(),
                                                       Vec::new(),
                                                       message_id));
                }
            }
            _ => unreachable!("Error in vault demuxing"),
        }

        Ok(())
    }

    // PutFailure only happens from receiver's MpidManager to sender's MpidManager to
    // indicate an inbox full.
    // The request in the put_failure response is the original request from sender's MpidManager
    // to receiver's MpidManager, i.e. MpidMessageWrapper::PutHeader(mpid_header)
    pub fn handle_put_failure(&mut self,
                              routing_node: &RoutingNode,
                              request: &RequestMessage)
                              -> Result<(), InternalError> {
        let (data, message_id) = match request.content {
            RequestContent::Put(Data::Plain(ref data), ref message_id) => {
                (data.clone(), message_id.clone())
            }
            _ => unreachable!("Error in vault demuxing"),
        };
        let mpid_message_wrapper: MpidMessageWrapper = try!(deserialise(&data.value()));
        match mpid_message_wrapper {
            MpidMessageWrapper::PutHeader(mpid_header) => {
                if mpid_header.sender() == request.src.name() {
                    if let Some(ref account) = self.accounts.get(&request.src.name().clone()) {
                        let ori_msg_name = try!(mpid_header.name());
                        if account.has_in_outbox(&ori_msg_name) {
                            let clients = account.registered_clients();
                            for client in clients.iter() {
                                let _ = routing_node.send_put_failure(request.src.clone(),
                                                                      client.clone(),
                                                                      request.clone(),
                                                                      Vec::new(),
                                                                      message_id.clone());
                            }
                        }
                    }
                }
            }
            _ => unreachable!("Error in vault demuxing"),
        }
        Ok(())
    }

    pub fn handle_post(&mut self,
                       routing_node: &RoutingNode,
                       request: &RequestMessage)
                       -> Result<(), InternalError> {
        let (data, message_id) = match request.content {
            RequestContent::Post(Data::Plain(ref data), ref message_id) => {
                (data.clone(), message_id.clone())
            }
            _ => unreachable!("Error in vault demuxing"),
        };
        let mpid_message_wrapper: MpidMessageWrapper = try!(deserialise(&data.value()));
        match mpid_message_wrapper {
            MpidMessageWrapper::Online => {
                let account = self.accounts
                                  .entry(request.dst.name().clone())
                                  .or_insert(Account::default());
                account.register_online(&request.src);
                // Send post success to client.
                let src = request.dst.clone();
                let dst = request.src.clone();
                let digest = sha512::hash(&try!(serialise(request))[..]);
                let _ = routing_node.send_post_success(src, dst, digest, message_id.clone());
                // For each received header in the inbox, fetch the full message from the sender
                let received_headers = account.received_headers();
                for header in received_headers.iter() {
                    match self.chunk_store_inbox.get(&header) {
                        Ok(serialised_header) => {
                            let mpid_header: MpidHeader = try!(deserialise(&serialised_header));
                            // fetch full message from the sender
                            let target = Authority::ClientManager(mpid_header.sender().clone());
                            let request_wrapper =
                                MpidMessageWrapper::GetMessage(mpid_header.clone());
                            let serialised_request = match serialise(&request_wrapper) {
                                Ok(encoded) => encoded,
                                Err(error) => {
                                    error!("Failed to serialise GetMessage wrapper: {:?}", error);
                                    continue;
                                }
                            };
                            let name = try!(mpid_header.name());
                            let data = Data::Plain(PlainData::new(name, serialised_request));
                            let _ = routing_node.send_post_request(request.dst.clone(),
                                                                   target,
                                                                   data,
                                                                   message_id.clone());
                        }
                        Err(_) => {}
                    }
                }
            }
            MpidMessageWrapper::GetMessage(mpid_header) => {
                let header_name = try!(mpid_header.name());
                match self.chunk_store_outbox.get(&header_name) {
                    Ok(serialised_message) => {
                        let mpid_message: MpidMessage = try!(deserialise(&serialised_message));
                        let message_name = try!(mpid_message.header().name());
                        if (message_name == header_name) &&
                           (mpid_message.recipient() == request.src.name()) {
                            let wrapper = MpidMessageWrapper::PutMessage(mpid_message);
                            let serialised_wrapper = try!(serialise(&wrapper));
                            let data = Data::Plain(PlainData::new(message_name,
                                                                      serialised_wrapper));
                            try!(routing_node.send_post_request(request.dst.clone(),
                                                                request.src.clone(),
                                                                data,
                                                                message_id.clone()));
                        }
                    }
                    _ => {
                        try!(routing_node.send_post_failure(request.dst.clone(),
                                                            request.src.clone(),
                                                            request.clone(),
                                                            Vec::new(),
                                                            message_id))
                    }
                }
            }
            MpidMessageWrapper::PutMessage(mpid_message) => {
                match self.accounts.get(request.dst.name()) {
                    Some(receiver) => {
                        if mpid_message.recipient() == request.dst.name() {
                            let clients = receiver.registered_clients();
                            for client in clients.iter() {
                                let _ =
                                    routing_node.send_post_request(request.dst.clone(),
                                                                   client.clone(),
                                                                   Data::Plain(data.clone()),
                                                                   message_id.clone());
                            }
                        }
                    }
                    None => warn!("can not find the account {:?}", request.dst.name().clone()),
                }
            }
            MpidMessageWrapper::OutboxHas(header_names) => {
                if let Some(ref account) = self.accounts.get(&request.dst.name().clone()) {
                    if account.registered_clients()
                              .iter()
                              .any(|authority| *authority == request.src) {
                        let names_in_outbox = header_names.iter()
                                                          .filter(|name| {
                                                              account.has_in_outbox(name)
                                                          })
                                                          .cloned()
                                                          .collect::<Vec<XorName>>();
                        let mut mpid_headers = vec![];

                        for name in names_in_outbox.iter() {
                            if let Ok(data) = self.chunk_store_outbox.get(name) {
                                let mpid_message: MpidMessage = try!(deserialise(&data));
                                mpid_headers.push(mpid_message.header().clone());
                            }
                        }

                        let src = request.dst.clone();
                        let dst = request.src.clone();
                        let wrapper = MpidMessageWrapper::OutboxHasResponse(mpid_headers);
                        let serialised_wrapper = try!(serialise(&wrapper));
                        let data = Data::Plain(PlainData::new(request.dst.name().clone(),
                                                              serialised_wrapper));
                        try!(routing_node.send_post_request(src, dst, data, message_id.clone()));
                    }
                }
            }
            MpidMessageWrapper::GetOutboxHeaders => {
                if let Some(ref account) = self.accounts.get(&request.dst.name().clone()) {
                    if account.registered_clients()
                              .iter()
                              .any(|authority| *authority == request.src) {
                        let mut mpid_headers = vec![];

                        for name in account.stored_messages().iter() {
                            if let Ok(data) = self.chunk_store_outbox.get(name) {
                                let mpid_message: MpidMessage = try!(deserialise(&data));
                                mpid_headers.push(mpid_message.header().clone());
                            }
                        }

                        let src = request.dst.clone();
                        let dst = request.src.clone();
                        let wrapper = MpidMessageWrapper::GetOutboxHeadersResponse(mpid_headers);
                        let serialised_wrapper = try!(serialise(&wrapper));
                        let data = Data::Plain(PlainData::new(request.dst.name().clone(), serialised_wrapper));
                        try!(routing_node.send_post_request(src, dst, data, message_id.clone()));
                    }
                }
            }
            _ => unreachable!("Error in vault demuxing"),
        }

        Ok(())
    }

    pub fn handle_delete(&mut self,
                         routing_node: &RoutingNode,
                         request: &RequestMessage)
                         -> Result<(), InternalError> {
        let (data, message_id) = match request.content {
            RequestContent::Delete(Data::Plain(ref data), ref message_id) => {
                (data.clone(), message_id.clone())
            }
            _ => unreachable!("Error in vault demuxing"),
        };
        let mpid_message_wrapper: MpidMessageWrapper = try!(deserialise(&data.value()));
        match mpid_message_wrapper {
            MpidMessageWrapper::DeleteMessage(message_name) => {
                if let Some(ref mut account) = self.accounts.get_mut(&request.dst.name().clone()) {
                    let mut registered = false;

                    if account.registered_clients()
                              .iter()
                              .any(|authority| *authority == request.src) {
                        registered = true;
                    }

                    if let Ok(data) = self.chunk_store_outbox.get(&message_name) {
                        if !registered {
                            let mpid_message: MpidMessage = try!(deserialise(&data));
                            if *mpid_message.recipient() != utils::client_name(&request.src) {
                                return Ok(()); // !
                            }
                        }

                        let data_size = data.len() as u64;
                        try!(self.chunk_store_outbox.delete(&message_name));
                        if !account.remove_from_outbox(data_size, &message_name) {
                            warn!("Failed to remove message name from outbox.");
                        }
                    } else {
                        error!("Failed to get from chunk store.");
                        try!(routing_node.send_delete_failure(request.dst.clone(),
                                                              request.src.clone(),
                                                              request.clone(),
                                                              Vec::new(),
                                                              message_id))
                    }
                }
            }
            MpidMessageWrapper::DeleteHeader(header_name) => {
                if let Some(ref mut account) = self.accounts.get_mut(&request.dst.name().clone()) {
                    if account.registered_clients()
                              .iter()
                              .any(|authority| *authority == request.src) {
                        if let Ok(data) = self.chunk_store_inbox.get(&header_name) {
                            let data_size = data.len() as u64;
                            try!(self.chunk_store_inbox.delete(&header_name));
                            if !account.remove_from_inbox(data_size, &header_name) {
                                warn!("Failed to remove header name from inbox.");
                            }
                        } else {
                            error!("Failed to get from chunk store.");
                            try!(routing_node.send_delete_failure(request.dst.clone(),
                                                                  request.src.clone(),
                                                                  request.clone(),
                                                                  Vec::new(),
                                                                  message_id))
                        }
                    }
                }
            }
            _ => unreachable!("Error in vault demuxing"),
        }

        Ok(())
    }

    pub fn handle_refresh(&mut self,
                          name: XorName,
                          account: &Account,
                          stored_messages: &Vec<PlainData>,
                          received_headers: &Vec<PlainData>) {
        let _ = self.accounts.insert(name.clone(), account.clone());
        Self::insert_chunks(&mut self.chunk_store_outbox, stored_messages);
        Self::insert_chunks(&mut self.chunk_store_inbox, received_headers);
    }

    pub fn handle_churn(&mut self, routing_node: &RoutingNode) {
        for (mpid_name, account) in self.accounts.iter() {
            let received_headers = Self::fetch_chunks(&self.chunk_store_inbox,
                                                      &account.received_headers());
            let stored_messages = Self::fetch_chunks(&self.chunk_store_outbox,
                                                     &account.stored_messages());

            let src = Authority::ClientManager(mpid_name.clone());
            let refresh = Refresh::new(mpid_name,
                                       RefreshValue::MpidManagerAccount(account.clone(),
                                                                        stored_messages,
                                                                        received_headers));
            if let Ok(serialised_refresh) = serialise(&refresh) {
                debug!("MpidManager sending refresh for account {:?}", src.name());
                let _ = routing_node.send_refresh_request(src, serialised_refresh);
            }
        }
    }

    fn fetch_chunks(storage: &ChunkStore, names: &Vec<XorName>) -> Vec<PlainData> {
        let mut datas = Vec::new();
        for name in names.iter() {
            if let Ok(data) = storage.get(name) {
                datas.push(PlainData::new(name.clone(), data));
            }
        }
        datas
    }

    fn insert_chunks(storage: &mut ChunkStore, datas: &Vec<PlainData>) {
        for data in datas.iter() {
            if !storage.has_chunk(&data.name()) {
                let _ = storage.put(&data.name(), data.value());
            }
        }
    }
}



#[cfg(all(test, feature = "use-mock-routing"))]
mod test {
    use super::*;
    use error::{ClientError, InternalError};
    use maidsafe_utilities::serialisation;
    use rand;
    use routing::{Authority, Data, MessageId, PlainData, RequestContent, RequestMessage,
                  ResponseContent};
    use sodiumoxide::crypto::sign;
    use std::sync::mpsc;
    use utils::generate_random_vec_u8;
    use vault::RoutingNode;
    use xor_name::XorName;
    use mpid_messaging::{MpidHeader, MpidMessage, MpidMessageWrapper};

    struct Environment {
        our_authority: Authority,
        client: Authority,
        routing: RoutingNode,
        mpid_manager: MpidManager,
    }

    fn environment_setup() -> Environment {
        let from = rand::random::<XorName>();
        let keys = sign::gen_keypair();
        Environment {
            our_authority: Authority::ClientManager(from.clone()),
            client: Authority::Client {
                client_key: keys.0,
                proxy_node_name: from.clone(),
            },
            routing: unwrap_result!(RoutingNode::new(mpsc::channel().0)),
            mpid_manager: MpidManager::new(),
        }
    }

    fn register_online(env: &mut Environment, src: &Authority, dst: &Authority) {
        let wrapper = MpidMessageWrapper::Online;
        let name = src.name().clone();
        let value = unwrap_result!(serialisation::serialise(&wrapper));
        let plain_data = PlainData::new(name, value);
        let message_id = MessageId::new();
        let request = RequestMessage {
            src: src.clone(),
            dst: dst.clone(),
            content: RequestContent::Post(Data::Plain(plain_data.clone()), message_id.clone()),
        };

        match env.mpid_manager.handle_post(&env.routing, &request) {
            Ok(()) => (),
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    fn generate_receiver() -> Authority {
        Authority::Client {
            client_key: sign::gen_keypair().0,
            proxy_node_name: rand::random::<XorName>(),
        }
    }

    fn put_mpid_message(env: &mut Environment, mpid_message: &MpidMessage, id: &MessageId) {
        let wrapper = MpidMessageWrapper::PutMessage(mpid_message.clone());
        let name = unwrap_result!(mpid_message.header().name());
        let value = unwrap_result!(serialisation::serialise(&wrapper));
        let plain_data = PlainData::new(name.clone(), value);
        let request = RequestMessage {
            src: env.client.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(Data::Plain(plain_data.clone()), id.clone()),
        };

        match env.mpid_manager.handle_put(&env.routing, &request) {
            Ok(()) => (),
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    fn put_mpid_header(env: &mut Environment,
                       header: &MpidHeader,
                       src: &Authority,
                       dst: &Authority,
                       id: &MessageId) {
        let wrapper = MpidMessageWrapper::PutHeader(header.clone());
        let name = unwrap_result!(header.name());
        let value = unwrap_result!(serialisation::serialise(&wrapper));
        let plain_data = PlainData::new(name.clone(), value);
        let request = RequestMessage {
            src: src.clone(),
            dst: dst.clone(),
            content: RequestContent::Put(Data::Plain(plain_data.clone()), id.clone()),
        };

        match env.mpid_manager.handle_put(&env.routing, &request) {
            Ok(()) => (),
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    fn get_mpid_message(env: &mut Environment,
                        header: &MpidHeader,
                        src: &Authority,
                        dst: &Authority,
                        id: &MessageId) {
        let wrapper = MpidMessageWrapper::GetMessage(header.clone());
        let name = unwrap_result!(header.name());
        let value = unwrap_result!(serialisation::serialise(&wrapper));
        let plain_data = PlainData::new(name.clone(), value);
        let request = RequestMessage {
            src: src.clone(),
            dst: dst.clone(),
            content: RequestContent::Post(Data::Plain(plain_data.clone()), id.clone()),
        };

        match env.mpid_manager.handle_post(&env.routing, &request) {
            Ok(()) => (),
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    fn delete_mpid_header(env: &mut Environment,
                          name: &XorName,
                          src: &Authority,
                          dst: &Authority,
                          id: &MessageId) {
        let wrapper = MpidMessageWrapper::DeleteHeader(name.clone());
        let value = unwrap_result!(serialisation::serialise(&wrapper));
        let plain_data = PlainData::new(name.clone(), value);
        let request = RequestMessage {
            src: src.clone(),
            dst: dst.clone(),
            content: RequestContent::Delete(Data::Plain(plain_data.clone()), id.clone()),
        };

        match env.mpid_manager.handle_delete(&env.routing, &request) {
            Ok(()) => (),
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    fn delete_mpid_message(env: &mut Environment,
                           name: &XorName,
                           src: &Authority,
                           dst: &Authority,
                           id: &MessageId) {
        let wrapper = MpidMessageWrapper::DeleteMessage(name.clone());
        let value = unwrap_result!(serialisation::serialise(&wrapper));
        let plain_data = PlainData::new(name.clone(), value);
        let request = RequestMessage {
            src: src.clone(),
            dst: dst.clone(),
            content: RequestContent::Delete(Data::Plain(plain_data.clone()), id.clone()),
        };

        match env.mpid_manager.handle_delete(&env.routing, &request) {
            Ok(()) => (),
            Err(error) => panic!("Error: {:?}", error),
        }
    }


    #[test]
    fn put_message() {
        let mut env = environment_setup();
        // register client sender online...
        let src = env.client.clone();
        let dst = env.our_authority.clone();
        register_online(&mut env, &src, &dst);

        // put message...
        let (_public_key, secret_key) = sign::gen_keypair();
        let sender = rand::random::<XorName>();
        let metadata: Vec<u8> = generate_random_vec_u8(128);
        let body: Vec<u8> = generate_random_vec_u8(128);
        let receiver = generate_receiver();
        let receiver_name = receiver.name().clone();
        let mpid_message = unwrap_result!(MpidMessage::new(sender,
                                                           metadata,
                                                           receiver_name.clone(),
                                                           body,
                                                           &secret_key));
        let message_id = MessageId::new();
        put_mpid_message(&mut env, &mpid_message, &message_id);

        let put_failures = env.routing.put_failures_given();
        assert!(put_failures.is_empty());
        let put_requests = env.routing.put_requests_given();
        assert_eq!(put_requests.len(), 1);
        assert_eq!(put_requests[0].src, env.our_authority);
        assert_eq!(put_requests[0].dst, Authority::ClientManager(receiver_name));
        match &put_requests[0].content {
            &RequestContent::Put(ref data, ref id) => {
                let mpid_header = mpid_message.header().clone();
                let wrapper = MpidMessageWrapper::PutHeader(mpid_header.clone());
                let name = unwrap_result!(mpid_header.name());
                let value = unwrap_result!(serialisation::serialise(&wrapper));
                let expected_data = Data::Plain(PlainData::new(name, value));
                assert_eq!(*data, expected_data);
                assert_eq!(*id, message_id);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn put_header() {
        let mut env = environment_setup();
        // put header...
        let (_public_key, secret_key) = sign::gen_keypair();
        let sender = rand::random::<XorName>();
        let metadata: Vec<u8> = generate_random_vec_u8(128);
        let body: Vec<u8> = generate_random_vec_u8(128);
        let receiver = generate_receiver();
        let receiver_name = receiver.name().clone();
        let mpid_message = unwrap_result!(MpidMessage::new(sender,
                                                           metadata,
                                                           receiver_name.clone(),
                                                           body,
                                                           &secret_key));
        let mpid_header = mpid_message.header().clone();
        let src = env.our_authority.clone();
        let dst = Authority::ClientManager(receiver_name.clone());
        let message_id = MessageId::new();
        put_mpid_header(&mut env, &mpid_header, &src, &dst, &message_id);

        let put_failures = env.routing.put_failures_given();
        assert!(put_failures.is_empty());
        let put_requests = env.routing.put_requests_given();
        assert!(put_requests.is_empty());
    }

    #[test]
    fn put_message_and_header_twice() {
        let mut env = environment_setup();
        // register client sender online...
        let src = env.client.clone();
        let dst = env.our_authority.clone();
        register_online(&mut env, &src, &dst);

        // put message...
        let (_public_key, secret_key) = sign::gen_keypair();
        let sender = rand::random::<XorName>();
        let metadata: Vec<u8> = generate_random_vec_u8(128);
        let body: Vec<u8> = generate_random_vec_u8(128);
        let receiver = rand::random::<XorName>();
        let mpid_message = unwrap_result!(MpidMessage::new(sender,
                                                           metadata,
                                                           receiver.clone(),
                                                           body,
                                                           &secret_key));
        let mpid_header = mpid_message.header().clone();
        let mpid_message_wrapper = MpidMessageWrapper::PutMessage(mpid_message.clone());
        let name = unwrap_result!(mpid_message.header().name());
        let value = unwrap_result!(serialisation::serialise(&mpid_message_wrapper));
        let plain_data = PlainData::new(name.clone(), value);
        let message_id = MessageId::new();
        let request = RequestMessage {
            src: env.client.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(Data::Plain(plain_data.clone()), message_id.clone()),
        };

        match env.mpid_manager.handle_put(&env.routing, &request) {
            Ok(()) => (),
            Err(error) => panic!("Error: {:?}", error),
        }

        let put_failures = env.routing.put_failures_given();
        assert!(put_failures.is_empty());
        let put_requests = env.routing.put_requests_given();
        assert_eq!(put_requests.len(), 1);
        assert_eq!(put_requests[0].src, env.our_authority);
        assert_eq!(put_requests[0].dst, Authority::ClientManager(receiver));
        match &put_requests[0].content {
            &RequestContent::Put(ref data, ref id) => {
                let wrapper = MpidMessageWrapper::PutHeader(mpid_header.clone());
                let value = unwrap_result!(serialisation::serialise(&wrapper));
                let expected_data = Data::Plain(PlainData::new(name, value));
                assert_eq!(*data, expected_data);
                assert_eq!(*id, message_id);
            }
            _ => unreachable!(),
        }

        // put message again...
        match env.mpid_manager.handle_put(&env.routing, &request) {
            Ok(_) => panic!("Expected an error."),
            Err(InternalError::Client(ClientError::DataExists)) => (),
            Err(_) => panic!("Unexpected error."),
        }

        // put header...
        let mpid_header_wrapper = MpidMessageWrapper::PutHeader(mpid_header.clone());
        let name = unwrap_result!(mpid_header.name());
        let value = unwrap_result!(serialisation::serialise(&mpid_header_wrapper));
        let plain_data = PlainData::new(name.clone(), value);
        let request = RequestMessage {
            src: env.client.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(Data::Plain(plain_data.clone()),
                                         MessageId::new().clone()),
        };

        match env.mpid_manager.handle_put(&env.routing, &request) {
            Ok(()) => (),
            Err(error) => panic!("Error: {:?}", error),
        }

        let put_failures = env.routing.put_failures_given();
        assert!(put_failures.is_empty());
        let put_requests = env.routing.put_requests_given();
        assert_eq!(put_requests.len(), 1);
        assert_eq!(put_requests[0].src, env.our_authority);
        assert_eq!(put_requests[0].dst, Authority::ClientManager(receiver));
        match &put_requests[0].content {
            &RequestContent::Put(ref data, ref id) => {
                let wrapper = MpidMessageWrapper::PutHeader(mpid_header);
                let value = unwrap_result!(serialisation::serialise(&wrapper));
                let expected_data = Data::Plain(PlainData::new(name, value));
                assert_eq!(*data, expected_data);
                assert_eq!(*id, message_id);
            }
            _ => unreachable!(),
        }

        // put header again...
        match env.mpid_manager.handle_put(&env.routing, &request) {
            Ok(_) => panic!("Expected an error."),
            Err(InternalError::Client(ClientError::DataExists)) => (),
            Err(_) => panic!("Unexpected error."),
        }
    }

    #[test]
    fn get_message() {
        let mut env = environment_setup();
        // register client sender online...
        let src = env.client.clone();
        let dst = env.our_authority.clone();
        register_online(&mut env, &src, &dst);

        // put message...
        let (_public_key, secret_key) = sign::gen_keypair();
        let sender = rand::random::<XorName>();
        let metadata: Vec<u8> = generate_random_vec_u8(128);
        let body: Vec<u8> = generate_random_vec_u8(128);
        let receiver = generate_receiver();
        let receiver_name = receiver.name().clone();
        let mpid_message = unwrap_result!(MpidMessage::new(sender,
                                                           metadata,
                                                           receiver_name.clone(),
                                                           body,
                                                           &secret_key));
        let message_id = MessageId::new();
        put_mpid_message(&mut env, &mpid_message, &message_id);

        let put_failures = env.routing.put_failures_given();
        assert!(put_failures.is_empty());
        let put_requests = env.routing.put_requests_given();
        assert_eq!(put_requests.len(), 1);
        assert_eq!(put_requests[0].src, env.our_authority);
        assert_eq!(put_requests[0].dst,
                   Authority::ClientManager(receiver_name.clone()));
        match &put_requests[0].content {
            &RequestContent::Put(ref data, ref id) => {
                let mpid_header = mpid_message.header().clone();
                let wrapper = MpidMessageWrapper::PutHeader(mpid_header.clone());
                let name = unwrap_result!(mpid_header.name());
                let value = unwrap_result!(serialisation::serialise(&wrapper));
                let expected_data = Data::Plain(PlainData::new(name, value));
                assert_eq!(*data, expected_data);
                assert_eq!(*id, message_id);
            }
            _ => unreachable!(),
        }

        // get message...
        let mpid_header = mpid_message.header().clone();
        let src = Authority::ClientManager(receiver_name.clone());
        let dst = env.our_authority.clone();
        let message_id = MessageId::new();
        get_mpid_message(&mut env, &mpid_header, &src, &dst, &message_id);

        let post_requests = env.routing.post_requests_given();
        assert_eq!(post_requests.len(), 1);
        assert_eq!(post_requests[0].src, env.our_authority);
        assert_eq!(post_requests[0].dst,
                   Authority::ClientManager(receiver_name));
        match &post_requests[0].content {
            &RequestContent::Post(ref data, ref id) => {
                let wrapper = MpidMessageWrapper::PutMessage(mpid_message);
                let name = unwrap_result!(mpid_header.name());
                let value = unwrap_result!(serialisation::serialise(&wrapper));
                let expected_data = Data::Plain(PlainData::new(name, value));
                assert_eq!(*data, expected_data);
                assert_eq!(*id, message_id);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn outbox_has() {
        let mut env = environment_setup();
        let src = env.client.clone();
        let dst = env.our_authority.clone();
        register_online(&mut env, &src, &dst);

        // put message...
        let (_public_key, secret_key) = sign::gen_keypair();
        let sender = rand::random::<XorName>();
        let metadata: Vec<u8> = generate_random_vec_u8(128);
        let body: Vec<u8> = generate_random_vec_u8(128);
        let receiver = generate_receiver();
        let receiver_name = receiver.name().clone();
        let mpid_message = unwrap_result!(MpidMessage::new(sender,
                                                           metadata,
                                                           receiver_name.clone(),
                                                           body,
                                                           &secret_key));
        let message_id = MessageId::new();
        put_mpid_message(&mut env, &mpid_message, &message_id);

        let put_failures = env.routing.put_failures_given();
        assert!(put_failures.is_empty());
        let put_requests = env.routing.put_requests_given();
        assert_eq!(put_requests.len(), 1);
        assert_eq!(put_requests[0].src, env.our_authority);
        assert_eq!(put_requests[0].dst,
                   Authority::ClientManager(receiver_name.clone()));
        match &put_requests[0].content {
            &RequestContent::Put(ref data, ref id) => {
                let mpid_header = mpid_message.header().clone();
                let wrapper = MpidMessageWrapper::PutHeader(mpid_header.clone());
                let name = unwrap_result!(mpid_header.name());
                let value = unwrap_result!(serialisation::serialise(&wrapper));
                let expected_data = Data::Plain(PlainData::new(name, value));
                assert_eq!(*data, expected_data);
                assert_eq!(*id, message_id);
            }
            _ => unreachable!(),
        }

        // outbox has...
        let mpid_header = mpid_message.header().clone();
        let mpid_header_name = unwrap_result!(mpid_header.name());
        let outbox_has_wrapper = MpidMessageWrapper::OutboxHas(vec![mpid_header_name]);
        let name = env.our_authority.name().clone();
        let value = unwrap_result!(serialisation::serialise(&outbox_has_wrapper));
        let plain_data = PlainData::new(name.clone(), value);
        let message_id = MessageId::new();
        let request = RequestMessage {
            src: env.client.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Post(Data::Plain(plain_data.clone()), message_id.clone()),
        };

        match env.mpid_manager.handle_post(&env.routing, &request) {
            Ok(()) => (),
            Err(error) => panic!("Error: {:?}", error),
        }

        let post_requests = env.routing.post_requests_given();
        assert_eq!(post_requests.len(), 1);
        assert_eq!(post_requests[0].src, env.our_authority);
        assert_eq!(post_requests[0].dst, env.client);
        match &post_requests[0].content {
            &RequestContent::Post(ref data, ref id) => {
                let wrapper = MpidMessageWrapper::OutboxHasResponse(vec![mpid_header]);
                let value = unwrap_result!(serialisation::serialise(&wrapper));
                let expected_data = Data::Plain(PlainData::new(name, value));
                assert_eq!(*data, expected_data);
                assert_eq!(*id, message_id);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn get_outbox_headers() {
        let mut env = environment_setup();
        let src = env.client.clone();
        let dst = env.our_authority.clone();
        register_online(&mut env, &src, &dst);

        // put message...
        let (_public_key, secret_key) = sign::gen_keypair();
        let sender = rand::random::<XorName>();
        let metadata: Vec<u8> = generate_random_vec_u8(128);
        let body: Vec<u8> = generate_random_vec_u8(128);
        let receiver = generate_receiver();
        let receiver_name = receiver.name().clone();
        let mpid_message = unwrap_result!(MpidMessage::new(sender,
                                                           metadata,
                                                           receiver_name.clone(),
                                                           body,
                                                           &secret_key));
        let message_id = MessageId::new();
        put_mpid_message(&mut env, &mpid_message, &message_id);

        let put_failures = env.routing.put_failures_given();
        assert!(put_failures.is_empty());
        let put_requests = env.routing.put_requests_given();
        assert_eq!(put_requests.len(), 1);
        assert_eq!(put_requests[0].src, env.our_authority);
        assert_eq!(put_requests[0].dst,
                   Authority::ClientManager(receiver_name.clone()));
        match &put_requests[0].content {
            &RequestContent::Put(ref data, ref id) => {
                let mpid_header = mpid_message.header().clone();
                let wrapper = MpidMessageWrapper::PutHeader(mpid_header.clone());
                let name = unwrap_result!(mpid_header.name());
                let value = unwrap_result!(serialisation::serialise(&wrapper));
                let expected_data = Data::Plain(PlainData::new(name, value));
                assert_eq!(*data, expected_data);
                assert_eq!(*id, message_id);
            }
            _ => unreachable!(),
        }

        // get outbox headers...
        let get_outbox_headers_wrapper = MpidMessageWrapper::GetOutboxHeaders;
        let name = env.our_authority.name().clone();
        let value = unwrap_result!(serialisation::serialise(&get_outbox_headers_wrapper));
        let plain_data = PlainData::new(name.clone(), value);
        let message_id = MessageId::new();
        let request = RequestMessage {
            src: env.client.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Post(Data::Plain(plain_data.clone()), message_id.clone()),
        };

        match env.mpid_manager.handle_post(&env.routing, &request) {
            Ok(()) => (),
            Err(error) => panic!("Error: {:?}", error),
        }

        let post_requests = env.routing.post_requests_given();
        assert_eq!(post_requests.len(), 1);
        assert_eq!(post_requests[0].src, env.our_authority);
        assert_eq!(post_requests[0].dst, env.client);
        match &post_requests[0].content {
            &RequestContent::Post(ref data, ref id) => {
                let mpid_header = mpid_message.header().clone();
                let wrapper = MpidMessageWrapper::GetOutboxHeadersResponse(vec![mpid_header]);
                let value = unwrap_result!(serialisation::serialise(&wrapper));
                let expected_data = Data::Plain(PlainData::new(name, value));
                assert_eq!(*data, expected_data);
                assert_eq!(*id, message_id);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn delete_message() {
        let mut env = environment_setup();
        // register client sender online...
        let src = env.client.clone();
        let dst = env.our_authority.clone();
        register_online(&mut env, &src, &dst);

        // put message...
        let (_public_key, secret_key) = sign::gen_keypair();
        let sender = rand::random::<XorName>();
        let metadata: Vec<u8> = generate_random_vec_u8(128);
        let body: Vec<u8> = generate_random_vec_u8(128);
        let receiver = generate_receiver();
        let receiver_name = receiver.name().clone();
        let mpid_message = unwrap_result!(MpidMessage::new(sender,
                                                           metadata,
                                                           receiver_name.clone(),
                                                           body,
                                                           &secret_key));
        let message_id = MessageId::new();
        put_mpid_message(&mut env, &mpid_message, &message_id);

        let put_failures = env.routing.put_failures_given();
        assert!(put_failures.is_empty());
        let put_requests = env.routing.put_requests_given();
        assert_eq!(put_requests.len(), 1);
        assert_eq!(put_requests[0].src, env.our_authority);
        assert_eq!(put_requests[0].dst,
                   Authority::ClientManager(receiver_name.clone()));
        match &put_requests[0].content {
            &RequestContent::Put(ref data, ref id) => {
                let mpid_header = mpid_message.header().clone();
                let wrapper = MpidMessageWrapper::PutHeader(mpid_header.clone());
                let name = unwrap_result!(mpid_header.name());
                let value = unwrap_result!(serialisation::serialise(&wrapper));
                let expected_data = Data::Plain(PlainData::new(name, value));
                assert_eq!(*data, expected_data);
                assert_eq!(*id, message_id);
            }
            _ => unreachable!(),
        }

        // delete message...
        let mpid_header_name = unwrap_result!(mpid_message.header().name());
        let message_id = MessageId::new();
        delete_mpid_message(&mut env, &mpid_header_name, &src, &dst, &message_id);

        // get message...
        let mpid_header = mpid_message.header().clone();
        let src = Authority::ClientManager(receiver_name.clone());
        let dst = env.our_authority.clone();
        let message_id = MessageId::new();
        get_mpid_message(&mut env, &mpid_header, &src, &dst, &message_id);

        let post_failures = env.routing.post_failures_given();
        assert_eq!(post_failures.len(), 1);
        assert_eq!(post_failures[0].src, env.our_authority);
        assert_eq!(post_failures[0].dst,
                   Authority::ClientManager(receiver_name.clone()));
        match &post_failures[0].content {
            &ResponseContent::PostFailure{ ref id, ref request, ref external_error_indicator } => {
                let wrapper = MpidMessageWrapper::GetMessage(mpid_header.clone());
                let value = unwrap_result!(serialisation::serialise(&wrapper));
                let plain_data = PlainData::new(mpid_header_name, value);
                let get_request = RequestMessage {
                    src: src,
                    dst: dst,
                    content: RequestContent::Post(Data::Plain(plain_data.clone()),
                                                  message_id.clone()),
                };
                assert_eq!(*id, message_id);
                assert_eq!(*request, get_request);
                assert_eq!(*external_error_indicator, vec![]);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn delete_header() {
        let mut env = environment_setup();
        // register client sender online...
        let src = env.client.clone();
        let dst = env.our_authority.clone();
        register_online(&mut env, &src, &dst);

        // put message...
        let (_public_key, secret_key) = sign::gen_keypair();
        let sender = rand::random::<XorName>();
        let metadata: Vec<u8> = generate_random_vec_u8(128);
        let body: Vec<u8> = generate_random_vec_u8(128);
        let receiver = generate_receiver();
        let receiver_name = receiver.name().clone();
        let mpid_message = unwrap_result!(MpidMessage::new(sender,
                                                           metadata,
                                                           receiver_name.clone(),
                                                           body,
                                                           &secret_key));
        let message_id = MessageId::new();
        put_mpid_message(&mut env, &mpid_message, &message_id);

        let put_failures = env.routing.put_failures_given();
        assert!(put_failures.is_empty());
        let put_requests = env.routing.put_requests_given();
        assert_eq!(put_requests.len(), 1);
        assert_eq!(put_requests[0].src, dst.clone());
        assert_eq!(put_requests[0].dst,
                   Authority::ClientManager(receiver_name.clone()));
        match &put_requests[0].content {
            &RequestContent::Put(ref data, ref id) => {
                let mpid_header = mpid_message.header().clone();
                let wrapper = MpidMessageWrapper::PutHeader(mpid_header.clone());
                let name = unwrap_result!(mpid_header.name());
                let value = unwrap_result!(serialisation::serialise(&wrapper));
                let expected_data = Data::Plain(PlainData::new(name, value));
                assert_eq!(*data, expected_data);
                assert_eq!(*id, message_id);
            }
            _ => unreachable!(),
        }

        // register client receiver online...
        let dst = Authority::ClientManager(receiver_name.clone());
        register_online(&mut env, &receiver, &dst);

        // put header...
        let mpid_header = mpid_message.header().clone();
        let src = env.our_authority.clone();
        let dst = Authority::ClientManager(receiver_name.clone());
        let message_id = MessageId::new();
        put_mpid_header(&mut env, &mpid_header, &src, &dst.clone(), &message_id);

        // delete header...
        let mpid_header_name = unwrap_result!(mpid_header.name());
        let message_id = MessageId::new();
        delete_mpid_header(&mut env, &mpid_header_name, &receiver, &dst, &message_id);

        let delete_requests = env.routing.delete_requests_given();
        assert!(delete_requests.is_empty());
        let delete_failures = env.routing.delete_failures_given();
        assert!(delete_failures.is_empty());

        // delete header again...
        let message_id = MessageId::new();
        delete_mpid_header(&mut env, &mpid_header_name, &receiver, &dst, &message_id);

        let delete_requests = env.routing.delete_requests_given();
        assert!(delete_requests.is_empty());
        let delete_failures = env.routing.delete_failures_given();
        assert_eq!(delete_failures.len(), 1);
        assert_eq!(delete_failures[0].src,
                   Authority::ClientManager(receiver_name.clone()));
        assert_eq!(delete_failures[0].dst, receiver);
        match &delete_failures[0].content {
            &ResponseContent::DeleteFailure{ ref id, ref request, ref external_error_indicator } => {
                let mpid_header_wrapper = MpidMessageWrapper::DeleteHeader(mpid_header_name);
                let value = unwrap_result!(serialisation::serialise(&mpid_header_wrapper));
                let plain_data = PlainData::new(mpid_header_name, value);
                let delete_request = RequestMessage {
                    src: receiver.clone(),
                    dst: dst,
                    content: RequestContent::Delete(Data::Plain(plain_data.clone()), message_id.clone()),
                };
                assert_eq!(*id, message_id);
                assert_eq!(*request, delete_request);
                assert_eq!(*external_error_indicator, vec![]);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn post_put_message() {
        let mut env = environment_setup();
        // register client sender online...
        let src = env.client.clone();
        let dst = env.our_authority.clone();
        register_online(&mut env, &src, &dst);

        // put message...
        let (_public_key, secret_key) = sign::gen_keypair();
        let sender = rand::random::<XorName>();
        let metadata: Vec<u8> = generate_random_vec_u8(128);
        let body: Vec<u8> = generate_random_vec_u8(128);
        let receiver = generate_receiver();
        let receiver_name = receiver.name().clone();
        let mpid_message = unwrap_result!(MpidMessage::new(sender,
                                                           metadata,
                                                           receiver_name.clone(),
                                                           body,
                                                           &secret_key));
        let message_id = MessageId::new();
        put_mpid_message(&mut env, &mpid_message, &message_id);

        let put_failures = env.routing.put_failures_given();
        assert!(put_failures.is_empty());
        let put_requests = env.routing.put_requests_given();
        assert_eq!(put_requests.len(), 1);
        assert_eq!(put_requests[0].src, dst.clone());
        assert_eq!(put_requests[0].dst,
                   Authority::ClientManager(receiver_name.clone()));
        match &put_requests[0].content {
            &RequestContent::Put(ref data, ref id) => {
                let mpid_header = mpid_message.header().clone();
                let wrapper = MpidMessageWrapper::PutHeader(mpid_header.clone());
                let name = unwrap_result!(mpid_header.name());
                let value = unwrap_result!(serialisation::serialise(&wrapper));
                let expected_data = Data::Plain(PlainData::new(name, value));
                assert_eq!(*data, expected_data);
                assert_eq!(*id, message_id);
            }
            _ => unreachable!(),
        }

        // register client receiver online...
        let dst = Authority::ClientManager(receiver_name.clone());
        register_online(&mut env, &receiver, &dst);

        // get message...
        let mpid_header = mpid_message.header().clone();
        let src = Authority::ClientManager(receiver_name.clone());
        let dst = env.our_authority.clone();
        let message_id = MessageId::new();
        get_mpid_message(&mut env, &mpid_header, &src, &dst, &message_id);

        let post_requests = env.routing.post_requests_given();
        assert_eq!(post_requests.len(), 1);
        assert_eq!(post_requests[0].src, env.our_authority);
        assert_eq!(post_requests[0].dst,
                   Authority::ClientManager(receiver_name));
        match &post_requests[0].content {
            &RequestContent::Post(ref data, ref id) => {
                let wrapper = MpidMessageWrapper::PutMessage(mpid_message.clone());
                let name = unwrap_result!(mpid_header.name());
                let value = unwrap_result!(serialisation::serialise(&wrapper));
                let expected_data = Data::Plain(PlainData::new(name, value));
                assert_eq!(*data, expected_data);
                assert_eq!(*id, message_id);
            }
            _ => unreachable!(),
        }

        // post put message...
        let wrapper = MpidMessageWrapper::PutMessage(mpid_message.clone());
        let name = unwrap_result!(mpid_message.header().name());
        let value = unwrap_result!(serialisation::serialise(&wrapper));
        let plain_data = PlainData::new(name.clone(), value);
        let message_id = MessageId::new();
        let request = RequestMessage {
            src: Authority::ClientManager(receiver_name.clone()),
            dst: receiver.clone(),
            content: RequestContent::Post(Data::Plain(plain_data.clone()), message_id.clone()),
        };

        match env.mpid_manager.handle_post(&env.routing, &request) {
            Ok(()) => (),
            Err(error) => panic!("Error: {:?}", error),
        }

        let post_requests = env.routing.post_requests_given();
        assert_eq!(post_requests.len(), 2);
        assert_eq!(post_requests[1].src, receiver.clone());
        assert_eq!(post_requests[1].dst, receiver.clone());
        match &post_requests[1].content {
            &RequestContent::Post(ref data, ref id) => {
                let wrapper = MpidMessageWrapper::PutMessage(mpid_message);
                let value = unwrap_result!(serialisation::serialise(&wrapper));
                let expected_data = Data::Plain(PlainData::new(name, value));
                assert_eq!(*data, expected_data);
                assert_eq!(*id, message_id);
            }
            _ => unreachable!(),
        }
    }
}

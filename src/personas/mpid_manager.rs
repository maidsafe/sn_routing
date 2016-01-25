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

use sodiumoxide::crypto::hash::sha512;

use chunk_store::ChunkStore;
use default_chunk_store;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use mpid_messaging::{MpidHeader, MpidMessageWrapper};
use routing::{Authority, Data, DataRequest, MessageId, PlainData, RequestContent, RequestMessage};
use vault::RoutingNode;
use xor_name::XorName;

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
struct MailBox {
    allowance: u64,
    used_space: u64,
    space_available: u64,
    mail_box: Vec<XorName>,
}

impl Default for MailBox {
    // FIXME: Account Creation process required
    //   To bypass the the process for a simple network, allowance is granted by default
    fn default() -> MailBox {
        MailBox {
            allowance: 1073741824,
            used_space: 0,
            space_available: 1073741824,
            mail_box: Vec::<XorName>::new()
        }
    }
}

impl MailBox {
    fn put(&mut self, size: u64, entry: &XorName) -> bool {
        if size > self.space_available {
            return false;
        }
        if self.mail_box.contains(entry) {
            return false;
        }
        self.used_space += size;
        self.space_available -= size;
        self.mail_box.push(entry.clone());
        true
    }

    #[allow(dead_code)]
    fn remove(&mut self, size: u64, entry: &XorName) -> bool {
        if !self.mail_box.contains(entry) {
            return false;
        }
        self.used_space -= size;
        self.space_available += size;
        for i in 0..self.mail_box.len() {
            if self.mail_box.get(i) == Some(entry) {
                let _ = self.mail_box.remove(i);
                break;
            }
        }
        true
    }

    #[allow(dead_code)]
    fn has(&mut self, entry: &XorName) -> bool {
        self.mail_box.contains(entry)
    }
}

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
struct Account {
    inbox: MailBox,
    outbox: MailBox,
}

impl Default for Account {
    // FIXME: Account Creation process required
    //   To bypass the the process for a simple network, allowance is granted by default
    fn default() -> Account {
        Account {
            inbox: MailBox::default(),
            outbox: MailBox::default(),
        }
    }
}

impl Account {
    fn put_into_outbox(&mut self, size: u64,  entry: &XorName) -> bool {
        self.outbox.put(size, entry)
    }

    fn put_into_inbox(&mut self, size: u64,  entry: &XorName) -> bool {
        self.inbox.put(size, entry)
    }

    #[allow(dead_code)]
    fn remove_from_outbox(&mut self, size: u64,  entry: &XorName) -> bool {
        self.outbox.remove(size, entry)
    }

    #[allow(dead_code)]
    fn remove_from_inbox(&mut self, size: u64,  entry: &XorName) -> bool {
        self.inbox.remove(size, entry)
    }
}

pub struct MpidManager {
    accounts: HashMap<XorName, Account>,
    chunk_store: ChunkStore,
}

impl MpidManager {
    pub fn new() -> MpidManager {
        MpidManager {
            accounts: HashMap::new(),
            chunk_store: default_chunk_store::new().unwrap(),
        }
    }

    // The name of the PlainData is expected to be the Hash of its content
    pub fn handle_put(&mut self, routing_node: &RoutingNode, request: &RequestMessage) {
        let (data, message_id) = match request.content {
            RequestContent::Put(Data::PlainData(ref data), ref message_id) => {
                (data.clone(), message_id.clone())
            }
            _ => unreachable!("Error in vault demuxing"),
        };

        if self.chunk_store.has_chunk(&data.name()) {
            return;
        }

        let mpid_message_wrapper = match deserialise::<MpidMessageWrapper>(data.value()) {
            Ok(data) => data,
            Err(_) => {
                warn!("Failed to parse MpidMessageWrapper with name {:?}", data.name());
                return;
            }
        };

        match mpid_message_wrapper {
            MpidMessageWrapper::MpidHeader(mpid_header) => {
                if self.accounts
                       .entry(mpid_header.msg_header.receiver)
                       .or_insert(Account::default())
                       .put_into_inbox(data.payload_size() as u64, &data.name()) {
                    let _ = self.chunk_store.put(&data.name(), data.value());
                }
            }
            MpidMessageWrapper::MpidMessage(mpid_message) => {
                if self.accounts
                       .entry(mpid_message.msg_header.sender)
                       .or_insert(Account::default())
                       .put_into_outbox(data.payload_size() as u64, &data.name()) {
                    match self.chunk_store.put(&data.name(), data.value()) {
                        Err(err) => {
                            error!("Failed to store the full message to disk: {:?}", err);
                            return;
                        }
                        _ => {}
                    }
                    // Send notification to receiver's MpidManager
                    let src = request.dst.clone();
                    let dst = Authority::ClientManager(mpid_message.msg_header.receiver);
                    let mpid_header = MpidMessageWrapper::MpidHeader(MpidHeader {
                        msg_header : mpid_message.msg_header,
                        msg_link : data.name(),
                    });

                    let (serialised_header, header_hash) = match serialise(&mpid_header) {
                        Ok(encoded) => (encoded.clone(), sha512::hash(&encoded[..])),
                        Err(error) => {
                            error!("Failed to serialise Put request: {:?}", error);
                            return;
                        }
                    };
                    let notification = Data::PlainData(
                            PlainData::new(XorName(header_hash.0), serialised_header));
                    let _ = routing_node.send_put_request(src, dst, notification, message_id.clone());
                }
            }
        }
    }

    pub fn handle_get(&mut self, routing_node: &RoutingNode, request: &RequestMessage) {
        let (data_name, message_id) = match &request.content {
            &RequestContent::Get(DataRequest::PlainData(ref data_name), ref message_id) => {
                (data_name.clone(), message_id.clone())
            }
            _ => unreachable!("Error in vault demuxing"),
        };
        if (request.src.get_name() == request.dst.get_name()) &&
           (request.src.get_name() == &data_name) {
            self.handle_get_account(data_name, &message_id, routing_node, request);
        } else {
            self.handle_get_message(data_name, &message_id, routing_node, request);
        }
    }

    fn handle_get_account(&mut self, account_name: XorName, message_id: &MessageId,
                              routing_node: &RoutingNode, request: &RequestMessage) {
        match self.accounts.get(&account_name) {
            Some(account) => {
                let (encoded_account, account_hash) = match serialise(&account) {
                    Ok(encoded) => (encoded.clone(), sha512::hash(&encoded[..])),
                    Err(error) => {
                        error!("Failed to serialise the account of {:?} with error: {:?}",
                               account_name, error);
                        return;
                    }
                };
                let reply = Data::PlainData(PlainData::new(XorName(account_hash.0),
                                                           encoded_account));
                let _ = routing_node.send_put_request(request.dst.clone(),
                        request.src.clone(), reply, message_id.clone());
            }
            None => warn!("cannont find account {:?} in MpidManager", account_name),
        }
    }

    fn handle_get_message(&mut self, message_name: XorName, message_id: &MessageId,
                              routing_node: &RoutingNode, request: &RequestMessage) {
        let content = unwrap_result!(self.chunk_store.get(&message_name));
        let mpid_message_wrapper = match deserialise::<MpidMessageWrapper>(&content[..]) {
            Ok(data) => data,
            Err(_) => {
                warn!("Failed to parse MpidMessageWrapper with name {:?}", message_name);
                return;
            }
        };

        match mpid_message_wrapper {
            MpidMessageWrapper::MpidHeader(mpid_header) => {
                if &mpid_header.msg_header.receiver != request.src.get_name() {
                    return;
                }
            }
            MpidMessageWrapper::MpidMessage(mpid_message) => {
                if (&mpid_message.msg_header.receiver != request.src.get_name()) &&
                   (&mpid_message.msg_header.sender != request.src.get_name()) {
                    return;
                }
            }
        }
        let reply = Data::PlainData(PlainData::new(message_name, content));
        let _ = routing_node.send_put_request(request.dst.clone(),
                request.src.clone(), reply, message_id.clone());
    }

    pub fn handle_delete(&mut self, request: &RequestMessage) {
        let (message, _message_id) = match &request.content {
            &RequestContent::Delete(Data::PlainData(ref data), ref message_id) => {
                (data.clone(), message_id.clone())
            }
            _ => unreachable!("Error in vault demuxing"),
        };
        let mpid_message_wrapper = match deserialise::<MpidMessageWrapper>(message.value()) {
            Ok(data) => data,
            Err(_) => {
                warn!("Failed to parse MpidMessageWrapper with name {:?}", message.name());
                return;
            }
        };

        let account = unwrap_option!(self.accounts.get_mut(request.src.get_name()),
                                     "Failed to get correspondent account");
        match mpid_message_wrapper {
            MpidMessageWrapper::MpidHeader(mpid_header) => {
                // Only the receiver self is allowed to remove the notification
                if &mpid_header.msg_header.receiver != request.src.get_name() {
                    return;
                }
                account.inbox.remove(message.value().len() as u64, &message.name());
            }
            MpidMessageWrapper::MpidMessage(mpid_message) => {
                // Only the receiver or the sender are allowed to remove the full message
                if !(&mpid_message.msg_header.receiver == request.src.get_name() ||
                     &mpid_message.msg_header.sender == request.src.get_name()) {
                    return;
                }
                account.outbox.remove(message.value().len() as u64, &message.name());
            }
        }

        let _ = self.chunk_store.delete(&message.name());
    }

    // // removing message or header on request:
    // // 1, remove_message: delete request from recipient B to sender's MpidManagers(A)
    // //                    delete request from sender A to sender's MpidManagers(A)
    // // 2, remove_header: delete request from recipient B to MpidManagers(B)
    // pub fn handle_delete(from, to, name) {
    //     if remove_message {  // from.name != to.name
    //         remove the message (bearing the name) from sender(to.name)'s account if the message's
    //         specified recipient is the requester (from);
    //     }
    //     if remove_header {  // from.name == to.name
    //         remove the header (bearing the name) from recipient(from.name)'s account;
    //     }
    // }

    // // handle_post:
    // // 1, register_online: client sends a POST request to claim it is online
    // // 2, replying: MpidManager(A) forward full message to MpidManager(B) on request
    // // 3, fetching: MpidManager(B) trying to fetch a message from MpidManager(A)
    // pub fn handle_post(from, to, sd) {
    //     if register_online {
    //         let (mpid_name, mpid_client) = (to.name, from);
    //         let mut recipient_account = inbox.find_account(mpid_name);
    //         recipient_account.register_online(mpid_client);
    //         for header in recipient_account.headers {
    //             send a get request to the sender's MpidManager asking for the full message;
    //         }
    //         let mut sender_account = outbox.find_account(mpid_name);
    //         sender_account.register_online(mpid_client);
    //     }
    //     if replying {  // MpidManager(A) replies to MpidManager(B) with the requested mpid_message
    //         let account = inbox.find_account(to_name);
    //         if account.has_header(mpid_message.name()) {
    //             forward the mpid_message to client via routing.post using (reply_to, token);
    //         }
    //     }
    //     if fetching {
    //         if outbox.has_message(name) {
    //             // recipient's MpidManager asking for a particular message and it exists
    //             if the requester is the recipient, reply message to the requester(from) with
    //             outbox.find_message(name) via routing.post;
    //         } else {
    //             // recipient's MpidManager asking for a particular message but not exists
    //             reply failure to the requester(from);
    //         }
    //     }
    // }

    // // handle_post_response:
    // // 1, no_record: response contains Error msg holding the original get request which has
    // // original_mpid_header_name
    // // 2, inbox_full: response contains Error msg holding the original put request which has
    // // original_mpid_header
    // pub fn handle_post_failure(from, to, response) {
    //     if no_record {
    //         // MpidManager(A) replies to MpidManager(B) that the requested mpid_message doesn't exist remove the header (bearing the original_mpid_header_name) from the account of to.name;
    //     }
    //     if inbox_full {  // MpidManager(B) replies to MpidManager(A) that inbox is full
    //         remove the message (bearing the original_mpid_header.name()) from the account of to.name;
    //         original sender's `reply_to` and `token` will be available in this incoming message
    //         send failure to client via routing.put_failure using (reply_to, token, message);
    //     }
    // }

}

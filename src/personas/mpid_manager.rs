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
use routing::{Authority, Data, PlainData, RequestContent, RequestMessage};
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

        match (mpid_message_wrapper.mpid_header, mpid_message_wrapper.mpid_message) {
            (Some(mpid_header), None) => {
                if self.accounts
                       .entry(mpid_header.msg_header.receiver)
                       .or_insert(Account::default())
                       .put_into_inbox(data.payload_size() as u64, &data.name()) {
                    let _ = self.chunk_store.put(&data.name(), data.value());
                }
            }
            (None, Some(mpid_message)) => {
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
                    let mpid_header = MpidHeader {
                        msg_header : mpid_message.msg_header,
                        msg_link : data.name(),
                    };

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
            (_, _) => {}
        }
    }
    // // sending message:
    // // 1, messaging: put request from sender A to its MpidManagers(A)
    // // 2, notifying: from MpidManagers(A) to MpidManagers(B)
    // pub fn handle_put(from, to, sd, token) {
    //     if messaging {  // sd.data holds MpidMessage
    //         // insert received mpid_message into the outbox_storage
    //         if outbox_storage.insert(from, mpid_message) {
    //             let forward_sd = StructuredData {
    //                 type_tag: MPID_MESSAGE,
    //                 identifier: mpid_message_name(mpid_message),
    //                 data: ::utils::encode(mpid_message.mpid_header),
    //                 previous_owner_keys: vec![],
    //                 version: 0,
    //                 current_owner_keys: vec![my_mpid.public_key],
    //                 previous_owner_signatures: vec![]
    //             }
    //             routing.put_request(::mpid_manager::Authority(mpid_message.recipient), forward_sd);
    //         } else {
    //             // outbox full or other failure
    //             reply failure to the sender (Client);
    //         }
    //     }
    //     if notifying {  // sd.data holds MpidHeader
    //         // insert received mpid_header into the inbox_storage
    //         if inbox_storage.insert(to, mpid_header) {
    //             let recipient_account = inbox_storage.find_account(to);
    //             if recipient_account.recipient_clients.len() > 0 { // indicates there is connected client
    //                 for header in recipient_account.headers {
    //                     get_message(header);
    //                 }
    //             }
    //         } else {
    //             // inbox full or other failure
    //             reply failure to the sender (MpidManagers);
    //         }
    //     }
    // }

    // // get messages or headers on request:
    // pub fn handle_get(from, to, name, token) {
    //     if outbox.has_account(name) {
    //         // sender asking for the headers of existing messages
    //         reply to the requester(from) with outbox.find_account(name).get_headers() via routing.post;
    //     }
    //     if inbox.has_account(name) {
    //         // triggering pushing all existing messages to client, first needs to fetch them
    //         let recipient_account = inbox_storage.find_account(to);
    //         if recipient_account.recipient_clients.len() > 0 { // indicates there is connected client
    //             for header in recipient_account.headers {
    //                 get_message(header);
    //             }
    //         }
    //     }
    // }

    // // removing message or header on request:
    // // 1, remove_message: delete request from recipient B to sender's MpidManagers(A)
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

    // fn get_message(header: (sender_name: ::routing::NameType,
    //                         sender_public_key: ::sodiumoxide::crypto::sign::PublicKey,
    //                         mpid_header: MpidHeader)) {
    //     let request_sd = StructuredData {
    //         type_tag: MPID_MESSAGE,
    //         identifier: header.sender_name,
    //         data: ::utils::encode(MpidMessgeWrapper::GetMessage(mpid_header_name(mpid_header))),
    //         previous_owner_keys: vec![],
    //         version: 0,
    //         current_owner_keys: vec![header.sender_public_key],
    //         previous_owner_signatures: vec![]
    //     }
    //     routing.post_request(::mpid_manager::Authority(header.sender_name), request_sd);
    // }

}

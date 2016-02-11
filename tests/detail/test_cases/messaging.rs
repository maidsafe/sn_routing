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

use super::*;
// use rand;
// use routing::{Data, StructuredData};
// use xor_name::XorName;

// pub fn test(client: &mut Client) {
pub fn test() {
    println!("Running Messaging test");

    let sender = Client::new();
    sender.register_online();

    let receiver = Client::new();
    let metadata = generate_random_vec_u8(128);
    let body = generate_random_vec_u8(128);
    let message_sent = sender.put_message(&metadata, &body, receiver.name());

    receiver.register_online();
    let optional_message = receiver.get_message();
    assert!(optional_message.is_some());
    let message_received = unwrap_option!(optional_message, "");
    assert_eq!(message_received, message_sent);
}

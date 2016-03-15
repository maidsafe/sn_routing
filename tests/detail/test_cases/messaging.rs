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
use std::time::Duration;
use routing::{ResponseContent, ResponseMessage};

pub fn test() {
    let mut test_group = TestGroup::new("Messaging test");

    let sender = Client::new();
    let receiver = Client::new();

    test_group.start_case("Sender not registered yet");
    let (message_sent, request) = sender.generate_mpid_message(receiver.name());
    if let ResponseMessage {
           content: ResponseContent::PutFailure { ref external_error_indicator, .. }, .. } =
           unwrap_option!(sender.put(request.clone()), "") {
        // mpid_manager hasn't implemented a proper external_error_indicator in PutFailure
        assert!(external_error_indicator.is_empty())
    } else {
        panic!("Received unexpected response")
    }

    test_group.start_case("Sender registered and sent a message");
    sender.register_online();
    if let ResponseMessage { content: ResponseContent::PutSuccess(..), .. } =
           unwrap_option!(sender.put(request.clone()), "") {
        trace!("Successfully sent message {:?}", message_sent)
    } else {
        panic!("Failed to send message {:?}", message_sent)
    }

    test_group.start_case("Receiver registered and receiving message");
    receiver.register_online();
    let mut optional_message = receiver.get_mpid_message();
    let message_received = unwrap_option!(optional_message, "");
    assert_eq!(message_received, message_sent);

    test_group.start_case("Query one's outbox");
    let mut sender_mpid_headers = sender.query_outbox();
    assert_eq!(1, sender_mpid_headers.len());
    assert_eq!(message_sent.header().clone(), *unwrap_option!(sender_mpid_headers.first(), ""));
    let receiver_mpid_headers = receiver.query_outbox();
    assert_eq!(0, receiver_mpid_headers.len());

    test_group.start_case("Query particular record in outbox");
    let msg_name = unwrap_result!(message_sent.header().name());
    let mpid_headers = sender.outbox_has(vec![msg_name]);
    assert_eq!(1, mpid_headers.len());
    assert_eq!(message_sent.header().clone(), *unwrap_option!(mpid_headers.first(), ""));

    test_group.start_case("Receiver delete mpid_header from inbox");
    receiver.delete_mpid_header(msg_name);
    receiver.register_online();
    optional_message = receiver.expect_timeout(Duration::from_secs(10));
    assert_eq!(None, optional_message);

    test_group.start_case("Receiver delete message from sender's outbox");
    receiver.delete_mpid_message(*sender.name(), msg_name);
    sender_mpid_headers = sender.query_outbox();
    assert_eq!(0, sender_mpid_headers.len());

    test_group.release();
}

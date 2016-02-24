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
use routing::{ResponseContent, ResponseMessage};

pub fn test(request_count: u32) {
    let mut test_group = TestGroup::new("Messaging churn test");

    let sender = Client::new();
    let receiver = Client::new();
    let (message_sent, request) = sender.generate_mpid_message(receiver.name());

    test_group.start_case("Sender registered and sent a message");
    sender.register_online();
    match unwrap_option!(sender.put(request.clone()), "") {
        ResponseMessage { content: ResponseContent::PutSuccess(..), .. } => {
            trace!("Successfully sent message {:?}", message_sent);
        }
        _ => panic!("Failed to send message {:?}", message_sent),
    }

    test_group.start_case("Receiver registered and receiving message");
    for _i in 0..request_count {
        test_group.start_case("Receiver registered and receiving message");
        receiver.register_online();
        let optional_message = receiver.get_mpid_message();
        let message_received = unwrap_option!(optional_message, "");
        assert_eq!(message_received, message_sent);
    }

    for _i in 0..request_count {
        test_group.start_case("Sender query own outbox");
        let sender_mpid_headers = sender.query_outbox();
        assert_eq!(1, sender_mpid_headers.len());
        assert_eq!(message_sent.header().clone(), sender_mpid_headers[0]);
    }

    test_group.release();
}

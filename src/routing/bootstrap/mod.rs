// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod join;
mod relocate;

pub(crate) use join::join;
pub(crate) use relocate::JoinAsRelocated;

use crate::{
    messages::{RoutingMsgUtils, VerifyStatus},
    routing::comm::{Comm, SendStatus},
};
use sn_messaging::{node::RoutingMsg, MessageType};
use std::net::SocketAddr;
use xor_name::XorName;

// Send message using `comm`.
async fn send_message(comm: &Comm, message: MessageType, recipients: Vec<(XorName, SocketAddr)>) {
    match comm
        .send(&recipients, recipients.len(), message.clone())
        .await
    {
        Ok(SendStatus::AllRecipients) | Ok(SendStatus::MinDeliveryGroupSizeReached(_)) => {}
        Ok(SendStatus::MinDeliveryGroupSizeFailed(recipients)) => {
            error!("Failed to send message {:?} to {:?}", message, recipients)
        }
        Err(err) => error!(
            "Failed to send message {:?} to {:?}: {:?}",
            message, recipients, err
        ),
    }
}

fn verify_message(message: &RoutingMsg, trusted_key: Option<&bls::PublicKey>) -> bool {
    match message.verify(trusted_key) {
        Ok(VerifyStatus::Full) => true,
        Ok(VerifyStatus::Unknown) if trusted_key.is_none() => true,
        Ok(VerifyStatus::Unknown) => {
            // TODO: bounce
            error!("Verification failed - untrusted message: {:?}", message);
            false
        }
        Err(error) => {
            error!("Verification failed - {}: {:?}", error, message);
            false
        }
    }
}

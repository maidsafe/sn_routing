// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
};
use xor_name::{Prefix, XorName};

/// Message from client or bootstrapping node.
#[derive(Debug, Serialize, Deserialize)]
pub enum ExternalMessage {
    /// Generic message from a client.
    Client(Bytes),
    /// Query the closest section to the given name.
    GetSection(XorName),
}

/// Response for `ExternalMessage::GetSection`.
#[derive(Debug, Serialize, Deserialize)]
pub enum GetSectionResponse {
    /// Information about the section closest to the requested name.
    Ok {
        /// Prefix of the section.
        prefix: Prefix,
        /// Public key of the section.
        key: bls::PublicKey,
        /// Section elders.
        elders: BTreeMap<XorName, SocketAddr>,
    },
    /// Addresses of nodes that are closer to the requested name than the current recipient. The
    /// request should be repeated to these addresses.
    Redirect(BTreeSet<SocketAddr>),
}

// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::SocketAddr};
use xor_name::{Prefix, XorName};

/// Message to query the network infrastructure.
#[derive(Debug, Serialize, Deserialize)]
pub enum InfrastructureQuery {
    /// Message to request information about the section that matches the given name.
    GetSectionRequest(XorName),
    /// Successful response to `GetSectionRequest`. Contains information about the requested
    /// section.
    GetSectionSuccess {
        /// Prefix of the section.
        prefix: Prefix,
        /// Public key of the section.
        key: bls::PublicKey,
        /// Section elders.
        elders: BTreeMap<XorName, SocketAddr>,
    },
    /// Response to `GetSectionRequest` containing addresses of nodes that are closer to the
    /// requested name than the recipient. The request should be repeated to these addresses.
    GetSectionRedirect(Vec<SocketAddr>),
}

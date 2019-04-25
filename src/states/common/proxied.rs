// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Utilities for node states that are connected via proxy.

use crate::{
    error::RoutingError,
    id::PublicId,
    peer_manager::{Peer, PeerManager},
    xor_name::XorName,
};
use std::fmt::Display;

pub fn get_proxy_public_id<'a, T: Display>(
    label: &T,
    proxy_pub_id: &'a PublicId,
    proxy_name: &XorName,
) -> Result<&'a PublicId, RoutingError> {
    if proxy_pub_id.name() == proxy_name {
        Ok(proxy_pub_id)
    } else {
        error!("{} Unable to find connection to proxy node.", label);
        Err(RoutingError::ProxyConnectionNotFound)
    }
}

pub fn find_proxy_public_id<'a, T: Display>(
    label: &T,
    peer_mgr: &'a PeerManager,
    proxy_name: &XorName,
) -> Result<&'a PublicId, RoutingError> {
    if let Some(pub_id) = peer_mgr.get_peer_by_name(proxy_name).map(Peer::pub_id) {
        if peer_mgr.is_connected(pub_id) {
            Ok(pub_id)
        } else {
            error!(
                "{} - Unable to find connection to proxy in PeerManager.",
                label
            );
            Err(RoutingError::ProxyConnectionNotFound)
        }
    } else {
        error!("{} - Unable to find proxy in PeerManager.", label);
        Err(RoutingError::ProxyConnectionNotFound)
    }
}

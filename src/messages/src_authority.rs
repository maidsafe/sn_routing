// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    crypto::{self},
    error::{Error, Result},
    peer::PeerUtils,
};
use sn_messaging::{
    node::{Peer, SrcAuthority},
    SrcLocation,
};
use std::net::SocketAddr;
use xor_name::XorName;

/// Source authority of a message.
/// Src of message and authority to send it. Authority is validated by the signature.
/// Messages do not need to sign this field as it is all verifiable (i.e. if the sig validates
/// agains the pub key and we know th epub key then we are good. If the proof is not recognised we
/// ask for a longer chain that can be recognised). Therefore we don't need to sign this field.
pub trait SrcAuthorityUtils {
    fn src_location(&self) -> SrcLocation;

    fn is_section(&self) -> bool;

    fn name(&self) -> XorName;

    // If this location is `Node`, returns the corresponding `Peer` with `addr`. Otherwise error.
    fn peer(&self, addr: SocketAddr) -> Result<Peer>;
}

impl SrcAuthorityUtils for SrcAuthority {
    fn src_location(&self) -> SrcLocation {
        match self {
            SrcAuthority::Node { public_key, .. } => SrcLocation::Node(crypto::name(public_key)),
            SrcAuthority::BlsShare { src_name, .. } => SrcLocation::Section(*src_name),
            SrcAuthority::Section { src_name, .. } => SrcLocation::Section(*src_name),
        }
    }

    fn is_section(&self) -> bool {
        matches!(self, SrcAuthority::Section { .. })
    }

    fn name(&self) -> XorName {
        match self {
            SrcAuthority::Node { public_key, .. } => crypto::name(public_key),
            SrcAuthority::BlsShare { src_name, .. } => *src_name,
            SrcAuthority::Section { src_name, .. } => *src_name,
        }
    }

    // If this location is `Node`, returns the corresponding `Peer` with `addr`. Otherwise error.
    fn peer(&self, addr: SocketAddr) -> Result<Peer> {
        match self {
            SrcAuthority::Node { public_key, .. } => Ok(Peer::new(crypto::name(public_key), addr)),
            SrcAuthority::Section { .. } | SrcAuthority::BlsShare { .. } => {
                Err(Error::InvalidSrcLocation)
            }
        }
    }
}

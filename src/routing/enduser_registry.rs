// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::error::{Error, Result};
use sn_messaging::EndUser;
use std::{
    collections::{btree_map::Entry, BTreeMap},
    net::SocketAddr,
};
use xor_name::{Prefix, XorName};

pub type SocketId = XorName;
pub(crate) struct EndUserRegistry {
    clients: BTreeMap<SocketAddr, EndUser>,
    socket_id_mapping: BTreeMap<SocketId, SocketAddr>,
}

impl EndUserRegistry {
    pub fn new() -> Self {
        Self {
            clients: BTreeMap::default(),
            socket_id_mapping: BTreeMap::default(),
        }
    }

    pub fn get_enduser_by_addr(&self, socketaddr: &SocketAddr) -> Option<&EndUser> {
        self.clients.get(socketaddr)
    }

    pub fn get_socket_addr(&self, socket_id: SocketId) -> Option<&SocketAddr> {
        self.socket_id_mapping.get(&socket_id)
    }

    pub fn try_add(&mut self, sender: SocketAddr, section_prefix: &Prefix) -> Result<EndUser> {
        // create a unique socket id from client socket addr
        let socket_id = XorName::from_content(&[
            &bincode::serialize(&sender).map_err(|_| Error::FailedSignature)?
        ]);

        // assign a XorName to the end user which belongs to this section's prefix
        // so messages directed to this end user are correctly routed back through us
        let user_xorname = section_prefix.substituted_in(socket_id);

        // TODO: we probably should remove the socket_id from the EndUser struct,
        // and pass the socket id separatelly as part of nodes' messages,
        // instead of it being part of the SrcLocation/DstLocation in nodes' messages.
        // Currently each Elder cannot create a different socket id since that breaks
        // aggregation of messages when sent to another section with aggregation AtDestination.
        let end_user = EndUser {
            xorname: user_xorname,
            socket_id,
        };

        match self.socket_id_mapping.entry(socket_id) {
            Entry::Vacant(entry) => {
                let _ = self.clients.insert(sender, end_user);
                let _ = entry.insert(sender);
            }
            Entry::Occupied(_) => (),
        }

        Ok(end_user)
    }
}

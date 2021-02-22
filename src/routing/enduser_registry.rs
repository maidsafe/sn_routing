// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::error::{Error, Result};
use sn_data_types::{PublicKey as EndUserPK, Signature as EndUserSig};
use sn_messaging::EndUser;
use std::{
    collections::{btree_map::Entry, BTreeMap},
    net::SocketAddr,
};
use xor_name::XorName;

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

    pub fn get_enduser_by_addr(&self, socketaddr: &SocketAddr) -> Option<EndUser> {
        self.clients.get(socketaddr).copied()
    }

    pub fn get_socket_addr(&self, socket_id: &SocketId) -> Option<&SocketAddr> {
        self.socket_id_mapping.get(socket_id)
    }

    pub fn try_add(
        &mut self,
        sender: SocketAddr,
        end_user_pk: EndUserPK,
        socketaddr_sig: EndUserSig,
    ) -> Result<()> {
        if let Ok(data) = &bincode::serialize(&sender) {
            end_user_pk
                .verify(&socketaddr_sig, data)
                .map_err(|_e| Error::InvalidState)?;
        } else {
            return Err(Error::InvalidState);
        }
        let socket_id = if let Ok(socket_id_src) = &bincode::serialize(&socketaddr_sig) {
            XorName::from_content(&[socket_id_src])
        } else {
            return Err(Error::InvalidState);
        };
        let end_user = EndUser::Client {
            public_key: end_user_pk,
            socket_id,
        };
        match self.socket_id_mapping.entry(socket_id) {
            Entry::Vacant(_) => {
                let _ = self.clients.insert(sender, end_user);
                let _ = self.socket_id_mapping.insert(socket_id, sender);
            }
            Entry::Occupied(_) => (),
        }
        Ok(())
    }
}

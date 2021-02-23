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

    pub fn get_enduser_by_addr(&self, socketaddr: &SocketAddr) -> Option<&EndUser> {
        self.clients.get(socketaddr)
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
        end_user_pk
            .verify(&socketaddr_sig, &bincode::serialize(&sender)?)
            .map_err(|_e| Error::FailedSignature)?;
        let socket_id = XorName::from_content(&[&bincode::serialize(&socketaddr_sig)?]);
        let end_user = EndUser::Client {
            public_key: end_user_pk,
            socket_id,
        };
        match self.socket_id_mapping.entry(socket_id) {
            Entry::Vacant(entry) => {
                let _ = self.clients.insert(sender, end_user);
                let _ = entry.insert(sender);
            }
            Entry::Occupied(_) => (),
        }
        Ok(())
    }
}

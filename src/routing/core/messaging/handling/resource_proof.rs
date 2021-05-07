// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Core;
use crate::{
    crypto,
    messages::{ResourceProofResponse, Variant},
    peer::Peer,
    routing::{
        command::Command,
        core::{RESOURCE_PROOF_DATA_SIZE, RESOURCE_PROOF_DIFFICULTY},
    },
    Error, Result,
};
use ed25519_dalek::Verifier;
use xor_name::XorName;

// Resource proof
impl Core {
    pub(crate) fn validate_resource_proof_response(
        &self,
        peer_name: &XorName,
        response: ResourceProofResponse,
    ) -> bool {
        let serialized = if let Ok(serialized) = bincode::serialize(&(peer_name, &response.nonce)) {
            serialized
        } else {
            return false;
        };

        if self
            .node
            .keypair
            .public
            .verify(&serialized, &response.nonce_signature)
            .is_err()
        {
            return false;
        }

        self.resource_proof
            .validate_all(&response.nonce, &response.data, response.solution)
    }

    pub(crate) fn send_resource_proof_challenge(&self, peer: &Peer) -> Result<Command> {
        let nonce: [u8; 32] = rand::random();
        let serialized =
            bincode::serialize(&(peer.name(), &nonce)).map_err(|_| Error::InvalidMessage)?;
        let response = Variant::ResourceChallenge {
            data_size: RESOURCE_PROOF_DATA_SIZE,
            difficulty: RESOURCE_PROOF_DIFFICULTY,
            nonce,
            nonce_signature: crypto::sign(&serialized, &self.node.keypair),
        };

        self.send_direct_message(
            (*peer.addr(), *peer.name()),
            response,
            *self.section.chain().last_key(),
        )
    }
}

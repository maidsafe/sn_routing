// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{DstLocation, Message, MessageHash, SrcAuthority, Variant};
use crate::{
    error::Result,
    section::{SectionKeyShare, SectionProofChain},
    xor_space::{Prefix, XorName},
};
use bincode::serialize;
use std::{collections::BTreeSet, mem};

/// Section-source message that is in the process of signature accumulation.
/// When enough signatures are collected, it can be converted into full `Message` by calling
/// `combine_signatures`.
#[allow(missing_docs)]
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub struct AccumulatingMessage {
    pub content: PlainMessage,
    pub proof: SectionProofChain,
    pub public_key_set: bls::PublicKeySet,
    pub signature_shares: BTreeSet<(usize, bls::SignatureShare)>,
}

impl AccumulatingMessage {
    /// Create new `AccumulatingMessage`
    pub fn new(
        content: PlainMessage,
        section_share: &SectionKeyShare,
        public_key_set: bls::PublicKeySet,
        proof: SectionProofChain,
    ) -> Result<Self> {
        let bytes = content.serialize_for_signing()?;
        let mut signature_shares = BTreeSet::new();
        let sig_share = section_share.key.sign(&bytes);
        let _ = signature_shares.insert((section_share.index, sig_share));

        Ok(Self {
            content,
            proof,
            public_key_set,
            signature_shares,
        })
    }

    /// Add the signature shares of `other` into this message.
    /// Note: currently no validation is performed that the messages have the same content.
    pub fn add_signature_shares(&mut self, mut other: Self) {
        self.signature_shares.append(&mut other.signature_shares)
    }

    /// Returns whether there are enough signatures from the sender.
    pub fn check_fully_signed(&mut self) -> bool {
        if !self.has_enough_signatures() {
            return false;
        }

        // Remove invalid signatures, then check again that we have enough.
        // We also check (again) that all messages are from valid senders, because the message
        // may have been sent from another node, and we cannot trust that that node correctly
        // controlled which signatures were added.
        let bytes = match self.content.serialize_for_signing() {
            Ok(bytes) => bytes,
            Err(error) => {
                warn!("Failed to serialise {:?}: {:?}", self, error);
                return false;
            }
        };

        let invalid_signatures = self.remove_invalid_signatures(&bytes);
        if !invalid_signatures.is_empty() {
            debug!("{:?}: invalid signatures: {:?}", self, invalid_signatures);
        }

        self.has_enough_signatures()
    }

    /// Combines the signature shares into a single signature and convert this into full `Message`
    pub fn combine_signatures(self) -> Option<Message> {
        let signature = match self.public_key_set.combine_signatures(
            self.signature_shares
                .iter()
                .map(|(index, sig_share)| (*index, sig_share)),
        ) {
            Ok(signature) => signature,
            Err(error) => {
                log_or_panic!(
                    log::Level::Error,
                    "Combining signatures failed on {:?}: {:?}. \
                     (shares: {:?}, public key set: {:?}, proof: {:?})",
                    self,
                    error,
                    self.signature_shares,
                    self.public_key_set,
                    self.proof,
                );
                return None;
            }
        };

        Some(Message {
            src: SrcAuthority::Section {
                prefix: self.content.src,
                signature,
                proof: self.proof,
            },
            dst: self.content.dst,
            variant: self.content.variant,
        })
    }

    // Computes the cryptographuc hash of this message. Messages with identical `content` have the
    // same hash, regardless of their signature shares and/or proof.
    pub(crate) fn crypto_hash(&self) -> Result<MessageHash> {
        let bytes = serialize(&self.content)?;
        Ok(MessageHash::from_bytes(&bytes))
    }

    fn remove_invalid_signatures(&mut self, bytes: &[u8]) -> Vec<(usize, bls::SignatureShare)> {
        let mut invalid = Vec::new();

        for (index, sig_share) in mem::take(&mut self.signature_shares) {
            if self
                .public_key_set
                .public_key_share(index)
                .verify(&sig_share, bytes)
            {
                let _ = self.signature_shares.insert((index, sig_share));
            } else {
                invalid.push((index, sig_share));
            }
        }

        invalid
    }

    fn has_enough_signatures(&self) -> bool {
        self.signature_shares.len() > self.public_key_set.threshold()
    }
}

/// Section-source message without signature and proof.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub struct PlainMessage {
    /// Prefix of the source section.
    pub src: Prefix<XorName>,
    /// Destination location.
    pub dst: DstLocation,
    /// Message body.
    pub variant: Variant,
}

impl PlainMessage {
    fn serialize_for_signing(&self) -> Result<Vec<u8>> {
        super::serialize_for_section_signing(&self.dst, &self.variant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::generate_bls_threshold_secret_key,
        messages::VerifyStatus,
        rng::{self, MainRng},
        section::SectionKeyInfo,
        unwrap, Prefix,
    };
    use rand::{self, Rng};
    use std::{collections::BTreeMap, iter};

    #[test]
    fn combine_signatures() {
        let mut rng = rng::new();
        let sk_set = generate_bls_threshold_secret_key(&mut rng, 4);
        let pk_set = sk_set.public_keys();

        let sk_share_0 = SectionKeyShare::new_with_position(0, sk_set.secret_key_share(0));
        let sk_share_1 = SectionKeyShare::new_with_position(1, sk_set.secret_key_share(1));

        let content = gen_message(&mut rng);
        let proof = make_proof_chain(&pk_set);
        let their_key_infos = make_their_key_infos(&pk_set);

        let mut msg_0 = unwrap!(AccumulatingMessage::new(
            content.clone(),
            &sk_share_0,
            pk_set.clone(),
            proof.clone(),
        ));
        assert!(!msg_0.check_fully_signed());

        let msg_1 = unwrap!(AccumulatingMessage::new(
            content,
            &sk_share_1,
            pk_set,
            proof
        ));
        msg_0.add_signature_shares(msg_1);
        assert!(msg_0.check_fully_signed());

        let msg = unwrap!(msg_0.combine_signatures());
        assert_eq!(unwrap!(msg.verify(&their_key_infos)), VerifyStatus::Full);
    }

    #[test]
    fn invalid_signatures() {
        let mut rng = rng::new();
        let sk_set = generate_bls_threshold_secret_key(&mut rng, 4);
        let pk_set = sk_set.public_keys();

        let sk_share_0 = SectionKeyShare::new_with_position(0, sk_set.secret_key_share(0));
        let sk_share_1 = SectionKeyShare::new_with_position(1, sk_set.secret_key_share(1));
        let sk_share_2 = SectionKeyShare::new_with_position(2, sk_set.secret_key_share(2));

        let content = gen_message(&mut rng);
        let proof = make_proof_chain(&pk_set);
        let their_key_infos = make_their_key_infos(&pk_set);

        // Message with valid signature
        let mut msg_0 = unwrap!(AccumulatingMessage::new(
            content.clone(),
            &sk_share_0,
            pk_set.clone(),
            proof.clone()
        ));

        // Message with invalid signature
        let invalid_signature_share = sk_share_1.key.sign(b"bad message");
        let msg_1 = AccumulatingMessage {
            content: content.clone(),
            proof: proof.clone(),
            public_key_set: pk_set.clone(),
            signature_shares: iter::once((1, invalid_signature_share)).collect(),
        };

        msg_0.add_signature_shares(msg_1);

        // There is enough signature shares in total, but not enough valid ones, so the message is
        // not fully signed.
        assert!(!msg_0.check_fully_signed());

        // Another valid signature
        let msg_2 = unwrap!(AccumulatingMessage::new(
            content,
            &sk_share_2,
            pk_set,
            proof
        ));
        msg_0.add_signature_shares(msg_2);

        // There are now two valid signatures which is enough.
        assert!(msg_0.check_fully_signed());

        let msg = unwrap!(msg_0.combine_signatures());
        assert_eq!(unwrap!(msg.verify(&their_key_infos)), VerifyStatus::Full);
    }

    fn make_section_key_info(pk_set: &bls::PublicKeySet) -> SectionKeyInfo {
        SectionKeyInfo::new(pk_set.public_key())
    }

    fn make_proof_chain(pk_set: &bls::PublicKeySet) -> SectionProofChain {
        SectionProofChain::new(make_section_key_info(pk_set))
    }

    fn make_their_key_infos(
        pk_set: &bls::PublicKeySet,
    ) -> BTreeMap<Prefix<XorName>, SectionKeyInfo> {
        let key_info = make_section_key_info(pk_set);
        iter::once((Prefix::default(), key_info)).collect()
    }

    fn gen_message(rng: &mut MainRng) -> PlainMessage {
        use rand::distributions::Standard;

        PlainMessage {
            src: gen_prefix(rng),
            dst: DstLocation::Section(rng.gen()),
            variant: Variant::UserMessage(rng.sample_iter(Standard).take(6).collect()),
        }
    }

    fn gen_prefix(rng: &mut MainRng) -> Prefix<XorName> {
        Prefix::new(rng.gen_range(0, 4), rng.gen())
    }
}

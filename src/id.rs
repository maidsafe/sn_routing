// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::ed25519::{Keypair as EDKeypair, PublicKey as EDPublicKey, Signature as EDSignature};
use threshold_crypto::{PublicKey as EncPublicKey, SecretKey as EncSecretKey,
                        PublicKeyShare, SecretKeyShare, SignatureShare, Ciphertext};
use crate::parsec;
use crate::xor_name::XorName;
use rand_os::OsRng;
use std::fmt::{self, Debug, Display, Formatter};
use std::ops::RangeInclusive;
use serde::de::Deserialize;
use serde::{Deserializer, Serialize, Serializer};

/// Network identity component containing name, and public and private keys.
#[allow(unused)] // until bls_emu is refactored
pub struct FullId {
    public_id: PublicId,
    keypair: EDKeypair,
    enc_secret_key: EncSecretKey,
    sec_key_share: Option<SecretKeyShare>,
}

impl FullId {
    /// Construct a `FullId` with newly generated keys.
    pub fn new() -> FullId {
        let mut rand = OsRng::new().expect("Cannot generate random data, unsafe to continue");
        let keypair = EDKeypair::generate(&mut rand);
        let sk = EncSecretKey::random();
        FullId {
            public_id: PublicId::new(keypair.public.clone(), sk.public_key(), None),
            keypair: keypair,
            enc_secret_key: sk,
            sec_key_share : None,
        }
    }

    /// Construct with given keys (client requirement).
    pub fn from_keys(keypair: EDKeypair, enc_secret_key: EncSecretKey) -> FullId {
        FullId {
            public_id: PublicId::new(keypair.public.clone(), enc_secret_key.public_key(), None),
            keypair: keypair,
            enc_secret_key: enc_secret_key,
            sec_key_share: None,
        }
    }

    /// TODO this should be removed when PARSEC uses BLS keys
    pub fn copy(&self) -> Self {
        let a = self.keypair.to_bytes();
        let b: EDKeypair = EDKeypair::from_bytes(&a).expect("invalid keypair, dangerous!");
        // HACK
        FullId::from_keys(b, EncSecretKey::random())
    }

    /// Decrpt a message encrypted with our EncPublicKey
    pub fn decrypt(&self, msg : &Ciphertext) -> Option<Vec<u8>> {
        if !msg.verify() { return None; } // prevent chosen-ciphertext attacks.
        self.enc_secret_key.decrypt(&msg)
    }

    /// Construct a `FullId` whose name is in the interval [start, end] (both endpoints inclusive).
    /// FIXME(Fraser) - time limit this function? Document behaviour
    pub fn within_range(range: &RangeInclusive<XorName>) -> FullId {
        let mut rand = OsRng::new().expect("Cannot generate random data, unsafe to continue");
        let sk = EncSecretKey::random();
        let mut keypair = EDKeypair::generate(&mut rand);
        loop {
            let name = PublicId::name_from_key(&keypair.public);
            if range.contains(&name) {
                let full_id = FullId::from_keys(keypair, sk);
                return full_id;
            }
            keypair = EDKeypair::generate(&mut rand);
        }
    }

    /// Returns public ID reference.
    pub fn public_id(&self) -> &PublicId {
        &self.public_id
    }

    /// Sign with your secret ED key.
    pub fn ed_sign(&self, message: &[u8]) -> EDSignature {
        self.keypair.sign(message)
    }
    /// Sign with the BLS `SecretKeyShare`
    pub fn threshold_sign(&self, message : &[u8]) -> Option<SignatureShare> {
        if let Some(key) = self.sec_key_share.as_ref() { return Some(key.sign(message)); }
        None
    }

}

impl parsec::SecretId for FullId {
    type PublicId = PublicId;

    fn public_id(&self) -> &Self::PublicId {
        self.public_id()
    }

    fn sign_detached(&self, data: &[u8]) -> <Self::PublicId as parsec::PublicId>::Signature {
        self.ed_sign(data)
    }
    // TODO FIME remove
    fn encrypt<M: AsRef<[u8]>>(&self, _to: &Self::PublicId, msg: M) -> Option<Vec<u8>> {
        Some(msg.as_ref().to_vec())
    }

    // TODO FIME remove
    fn decrypt(&self, _from: &Self::PublicId, ct: &[u8]) -> Option<Vec<u8>> {
        Some(ct.as_ref().to_vec())
    }
}

impl Default for FullId {
    fn default() -> FullId {
        FullId::new()
    }
}

/// Network identity component containing name and public key.
/// The name feild is memoized
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
pub struct PublicId {
    public_key: EDPublicKey,
    name: XorName,
    enc_public_key: EncPublicKey,
    pub_key_share: Option<PublicKeyShare>,
}

impl Debug for PublicId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicId(name: {})", self.name)
    }
}

impl Display for PublicId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl parsec::PublicId for PublicId {
    type Signature = EDSignature;
    fn verify_signature(&self, signature: &Self::Signature, data: &[u8]) -> bool {
        self.verify(data, signature)
    }
}

impl Serialize for PublicId {
    fn serialize<S: Serializer>(&self, serialiser: S) -> Result<S::Ok, S::Error> {
        (&self.public_key, &self.enc_public_key, &self.pub_key_share).serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for PublicId {
    fn deserialize<D: Deserializer<'de>>(deserialiser: D) -> Result<Self, D::Error> {
        let (public_key, enc_public_key, pub_key_share) : (EDPublicKey, EncPublicKey, Option<PublicKeyShare>) =

            Deserialize::deserialize(deserialiser)?;
        Ok(PublicId::new(public_key, enc_public_key, pub_key_share))
    }
}


impl PublicId {
    /// Return initial/relocated name.
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Verify this id signed a message
    pub fn verify(&self, message: &[u8], sig: &EDSignature) -> bool {
        self.public_key.verify(message, sig).is_ok()
    }

    /// Return public signing key.
    pub fn signing_public_key(&self) -> &EDPublicKey {
        &self.public_key
    }
    /// dummy
    pub fn age(&self) -> u8 {
        0u8
    }

    fn new(public_key: EDPublicKey, enc_public_key : EncPublicKey, pub_key_share: Option<PublicKeyShare>) -> PublicId {
        PublicId {
            public_key: public_key,
            name: Self::name_from_key(&public_key),
            enc_public_key: enc_public_key,
            pub_key_share: pub_key_share,
        }
    }

    fn name_from_key(public_key: &EDPublicKey) -> XorName {
        XorName(public_key.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maidsafe_utilities::serialisation;
    use unwrap::unwrap;

    /// Confirm `PublicId` `Ord` trait favours name over sign keys.
    #[test]
    #[ignore] // Find out if this is required
    fn public_id_order() {

        let pub_id_1 = *FullId::new().public_id();
        let pub_id_2;
        loop {
            let temp_pub_id = *FullId::new().public_id();
            if temp_pub_id.name() > pub_id_1.name() && temp_pub_id.public_key < pub_id_1.public_key
            {
                pub_id_2 = temp_pub_id;
                break;
            }
        }
        assert!(pub_id_1 < pub_id_2);
    }

    #[test]
    fn serialisation() {

        let full_id = FullId::new();
        let serialised = unwrap!(serialisation::serialise(full_id.public_id()));
        let parsed = unwrap!(serialisation::deserialise(&serialised));
        assert_eq!(*full_id.public_id(), parsed);
    }
}

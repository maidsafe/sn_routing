// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    crypto::{encryption, signing},
    parsec,
    rng::{self, MainRng, RngCompat},
    xor_name::XorName,
    ConnectionInfo,
};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use rand_crypto::Rng as _;
use serde::de::Deserialize;
use serde::{Deserializer, Serialize, Serializer};
use std::{
    cmp::Ordering,
    fmt::{self, Debug, Display, Formatter},
    hash::{Hash, Hasher},
    net::{Ipv6Addr, SocketAddr},
    ops::RangeInclusive,
    rc::Rc,
};

/// Network identity component containing name, and public and private keys.
#[derive(Clone)]
pub struct FullId {
    public_id: PublicId,
    // Keep the secret keys in Rc to allow Clone while also preventing multiple copies to exist in
    // memory which might be unsafe.
    secret_keys: Rc<SecretKeys>,
}

impl FullId {
    /// Construct a `FullId` with randomly generated keys.
    pub fn gen(rng: &mut MainRng) -> FullId {
        let mut rng = RngCompat(rng);

        let secret_signing_key = signing::SecretKey::generate(&mut rng);
        let public_signing_key = signing::PublicKey::from(&secret_signing_key);

        let secret_encryption_key: encryption::SecretKey = rng.gen();
        let public_encryption_key = secret_encryption_key.public_key();

        let public_id = PublicId::new(public_signing_key, public_encryption_key);

        FullId {
            public_id,
            secret_keys: Rc::new(SecretKeys {
                signing: secret_signing_key,
                encryption: secret_encryption_key,
            }),
        }
    }

    /// Construct a `FullId` whose name is in the interval [start, end] (both endpoints inclusive).
    /// FIXME(Fraser) - time limit this function? Document behaviour
    pub fn within_range(rng: &mut MainRng, range: &RangeInclusive<XorName>) -> FullId {
        let mut rng = RngCompat(rng);

        loop {
            let secret_signing_key = signing::SecretKey::generate(&mut rng);
            let public_signing_key = signing::PublicKey::from(&secret_signing_key);
            let name = name_from_key(&public_signing_key);

            if range.contains(&name) {
                let secret_encryption_key: encryption::SecretKey = rng.gen();
                let public_encryption_key = secret_encryption_key.public_key();

                return Self {
                    public_id: PublicId::new(public_signing_key, public_encryption_key),
                    secret_keys: Rc::new(SecretKeys {
                        signing: secret_signing_key,
                        encryption: secret_encryption_key,
                    }),
                };
            }
        }
    }

    /// Returns public ID reference.
    pub fn public_id(&self) -> &PublicId {
        &self.public_id
    }

    /// Returns mutable reference to public ID.
    pub fn public_id_mut(&mut self) -> &mut PublicId {
        &mut self.public_id
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> signing::Signature {
        signing::sign(
            message,
            self.public_id.public_signing_key(),
            &self.secret_keys.signing,
        )
    }
}

impl parsec::SecretId for FullId {
    type PublicId = PublicId;

    fn public_id(&self) -> &Self::PublicId {
        self.public_id()
    }

    fn sign_detached(&self, data: &[u8]) -> <Self::PublicId as parsec::PublicId>::Signature {
        self.sign(data)
    }

    fn encrypt<M: AsRef<[u8]>>(&self, to: &Self::PublicId, plaintext: M) -> Option<Vec<u8>> {
        let mut rng = RngCompat(rng::new());
        let ciphertext = to
            .public_encryption_key
            .encrypt_with_rng(&mut rng, plaintext);
        serialise(&ciphertext).ok()
    }

    fn decrypt(&self, _from: &Self::PublicId, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let ciphertext: encryption::Ciphertext = deserialise(ciphertext).ok()?;
        self.secret_keys.encryption.decrypt(&ciphertext)
    }
}

struct SecretKeys {
    signing: signing::SecretKey,
    encryption: encryption::SecretKey,
}

/// Network identity component containing name and public keys.
///
/// Note that the `name` member is omitted when serialising `PublicId` and is calculated from the
/// `public_signing_key` when deserialising.
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
pub struct PublicId {
    name: XorName,
    public_signing_key: signing::PublicKey,
    public_encryption_key: encryption::PublicKey,
}

impl Debug for PublicId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicId(name: {})", self.name())
    }
}

impl Display for PublicId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Serialize for PublicId {
    fn serialize<S: Serializer>(&self, serialiser: S) -> Result<S::Ok, S::Error> {
        (&self.public_signing_key, &self.public_encryption_key).serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for PublicId {
    fn deserialize<D: Deserializer<'de>>(deserialiser: D) -> Result<Self, D::Error> {
        let (public_signing_key, public_encryption_key) = Deserialize::deserialize(deserialiser)?;
        Ok(PublicId::new(public_signing_key, public_encryption_key))
    }
}

impl parsec::PublicId for PublicId {
    type Signature = signing::Signature;

    fn verify_signature(&self, signature: &Self::Signature, data: &[u8]) -> bool {
        self.verify(data, signature)
    }
}

impl PublicId {
    /// Returns initial/relocated name.
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Verifies this id signed a message
    pub fn verify(&self, message: &[u8], sig: &signing::Signature) -> bool {
        self.public_signing_key.verify(message, sig).is_ok()
    }

    /// Returns public signing key.
    pub fn public_signing_key(&self) -> &signing::PublicKey {
        &self.public_signing_key
    }

    /// Returns public encryption key.
    pub fn public_encryption_key(&self) -> &encryption::PublicKey {
        &self.public_encryption_key
    }

    fn new(
        public_signing_key: signing::PublicKey,
        public_encryption_key: encryption::PublicKey,
    ) -> PublicId {
        PublicId {
            name: name_from_key(&public_signing_key),
            public_signing_key,
            public_encryption_key,
        }
    }
}

impl AsRef<XorName> for PublicId {
    fn as_ref(&self) -> &XorName {
        &self.name
    }
}

fn name_from_key(public_key: &signing::PublicKey) -> XorName {
    XorName(public_key.to_bytes())
}

/// Network p2p node identity.
/// When a node knows another node as a `P2pNode` it's implicitly connected to it. This is separate
/// from being connected at the network layer, which currently is handled by quic-p2p.
#[derive(Hash, PartialOrd, Ord, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct P2pNode {
    public_id: PublicId,
    connection_info: OrderedConnectionInfo,
}

impl P2pNode {
    /// Creates a new `P2pNode` given a `PublicId` and a `ConnectionInfo`.
    pub fn new(public_id: PublicId, connection_info: ConnectionInfo) -> Self {
        Self {
            public_id,
            connection_info: OrderedConnectionInfo(connection_info),
        }
    }

    /// Creates a `ConnectionInfo` from the `P2pNode` instance.
    pub fn into_connection_info(self) -> ConnectionInfo {
        self.connection_info.0
    }

    /// Returns the `PublicId`.
    pub fn public_id(&self) -> &PublicId {
        &self.public_id
    }

    /// Returns the `XorName` of the underlying `PublicId`.
    pub fn name(&self) -> &XorName {
        &self.public_id.name()
    }

    /// Returns the `ConnectionInfo`.
    pub fn connection_info(&self) -> &ConnectionInfo {
        &self.connection_info.0
    }

    /// Returns the `SocketAddr`.
    pub fn peer_addr(&self) -> &SocketAddr {
        &self.connection_info.0.peer_addr
    }
}

impl Debug for P2pNode {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "P2pNode({} at {})",
            self.public_id.name(),
            self.connection_info.0.peer_addr,
        )
    }
}

impl Display for P2pNode {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.public_id)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct OrderedConnectionInfo(pub ConnectionInfo);

impl Hash for OrderedConnectionInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        deconstruct_connection_info(&self.0).hash(state);
    }
}

impl PartialEq for OrderedConnectionInfo {
    fn eq(&self, other: &Self) -> bool {
        deconstruct_connection_info(&self.0).eq(&deconstruct_connection_info(&other.0))
    }
}

impl Eq for OrderedConnectionInfo {}

impl PartialOrd for OrderedConnectionInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrderedConnectionInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        deconstruct_connection_info(&self.0).cmp(&deconstruct_connection_info(&other.0))
    }
}

fn deconstruct_connection_info(conn_info: &ConnectionInfo) -> (Ipv6Addr, u16, u32, u32, &Vec<u8>) {
    match conn_info.peer_addr {
        SocketAddr::V4(addr) => (
            addr.ip().to_ipv6_compatible(),
            addr.port(),
            0_u32,
            0_u32,
            &conn_info.peer_cert_der,
        ),
        SocketAddr::V6(addr) => (
            *addr.ip(),
            addr.port(),
            addr.flowinfo(),
            addr.scope_id(),
            &conn_info.peer_cert_der,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng;
    use unwrap::unwrap;

    #[test]
    fn serialisation() {
        let full_id = FullId::gen(&mut rng::new());
        let serialised = unwrap!(serialise(full_id.public_id()));
        let parsed = unwrap!(deserialise(&serialised));
        assert_eq!(*full_id.public_id(), parsed);
    }
}

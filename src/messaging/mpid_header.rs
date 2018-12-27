// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// Maximum allowed length for a [header's `metadata`](struct.MpidHeader.html#method.new) (128
/// bytes).
pub const MAX_HEADER_METADATA_SIZE: usize = 128; // bytes

use super::{Error, GUID_SIZE};
use hex_fmt::HexFmt;
use maidsafe_utilities::serialisation::serialise;
use rand::{self, Rng};
use safe_crypto;
use safe_crypto::{PublicSignKey, SecretSignKey, Signature};
use std::fmt::{self, Debug, Formatter};
use xor_name::XorName;

#[derive(PartialEq, Eq, Hash, Clone, Deserialize, Serialize)]
struct Detail {
    sender: XorName,
    guid: [u8; GUID_SIZE],
    metadata: Vec<u8>,
}

/// Minimal information about a given message which can be used as a notification to the receiver.
#[derive(PartialEq, Eq, Hash, Clone, Deserialize, Serialize)]
pub struct MpidHeader {
    detail: Detail,
    signature: Signature,
}

impl MpidHeader {
    /// Constructor.
    ///
    /// Each new `MpidHeader` will have a random unique identifier assigned to it, accessed via the
    /// [`guid()`](#method.guid) getter.
    ///
    /// `sender` represents the name of the original creator of the message.
    ///
    /// `metadata` is arbitrary, user-supplied information which must not exceed
    /// [`MAX_HEADER_METADATA_SIZE`](constant.MAX_HEADER_METADATA_SIZE.html).  It can be empty if
    /// desired.
    ///
    /// `secret_key` will be used to generate a signature of `sender`, `guid` and `metadata`.
    ///
    /// An error will be returned if `metadata` exceeds `MAX_HEADER_METADATA_SIZE` or if
    /// serialisation during the signing process fails.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        sender: XorName,
        metadata: Vec<u8>,
        secret_key: &SecretSignKey,
    ) -> Result<MpidHeader, Error> {
        if metadata.len() > MAX_HEADER_METADATA_SIZE {
            return Err(Error::MetadataTooLarge);
        }

        let mut detail = Detail {
            sender: sender,
            guid: [0u8; GUID_SIZE],
            metadata: metadata,
        };
        rand::thread_rng().fill_bytes(&mut detail.guid);

        let encoded = serialise(&detail)?;
        Ok(MpidHeader {
            detail: detail,
            signature: secret_key.sign_detached(&encoded),
        })
    }

    /// The name of the original creator of the message.
    pub fn sender(&self) -> &XorName {
        &self.detail.sender
    }

    /// A unique identifier generated randomly when calling `new()`.
    pub fn guid(&self) -> &[u8; GUID_SIZE] {
        &self.detail.guid
    }

    /// Arbitrary, user-supplied information.
    pub fn metadata(&self) -> &Vec<u8> {
        &self.detail.metadata
    }

    /// The signature of `sender`, `guid` and `metadata`, created when calling `new()`.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// The name of the header.  This is a relatively expensive getter - the name is the SHA512 hash
    /// of the serialised header, so its use should be minimised.
    pub fn name(&self) -> Result<XorName, Error> {
        let encoded = serialise(self)?;
        Ok(XorName(safe_crypto::hash(&encoded[..])))
    }

    /// Validates the header's signature against the provided `PublicSignKey`.
    pub fn verify(&self, public_key: &PublicSignKey) -> bool {
        match serialise(&self.detail) {
            Ok(encoded) => public_key.verify_detached(&self.signature, &encoded),
            Err(_) => false,
        }
    }
}

impl Debug for MpidHeader {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), fmt::Error> {
        write!(
            formatter,
            "MpidHeader {{ sender: {:?}, guid: {:.14}, metadata: {:.14}, signature: {:.14} }}",
            self.detail.sender,
            HexFmt(&self.detail.guid),
            HexFmt(&self.detail.metadata),
            HexFmt(&self.signature.into_bytes()[..])
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use messaging;
    use rand;
    use safe_crypto::gen_sign_keypair;
    use xor_name::XorName;

    #[test]
    fn full() {
        let (public_key, secret_key) = gen_sign_keypair();
        let sender: XorName = rand::random();

        // Check with metadata which is empty, then at size limit, then just above limit.
        {
            let header = unwrap!(MpidHeader::new(sender, vec![], &secret_key));
            assert!(header.metadata().is_empty());
        }
        let mut metadata = messaging::generate_random_bytes(MAX_HEADER_METADATA_SIZE);
        let header = unwrap!(MpidHeader::new(sender, metadata.clone(), &secret_key));
        assert_eq!(*header.metadata(), metadata);
        metadata.push(0);
        assert!(MpidHeader::new(sender, metadata.clone(), &secret_key).is_err());
        let _ = metadata.pop();

        // Check verify function with a valid and invalid key
        assert!(header.verify(&public_key));
        let (rand_public_key, _) = gen_sign_keypair();
        assert!(!header.verify(&rand_public_key));

        // Check that identically-constructed headers retain identical sender and metadata, but have
        // different GUIDs and signatures.
        let header1 = unwrap!(MpidHeader::new(sender, metadata.clone(), &secret_key));
        let header2 = unwrap!(MpidHeader::new(sender, metadata.clone(), &secret_key));
        assert_ne!(header1, header2);
        assert_eq!(*header1.sender(), sender);
        assert_eq!(header1.sender(), header2.sender());
        assert_eq!(*header1.metadata(), metadata);
        assert_eq!(header1.metadata(), header2.metadata());
        assert_ne!(header1.guid(), header2.guid());
        assert_ne!(header1.signature(), header2.signature());
        let name1 = unwrap!(header1.name());
        let name2 = unwrap!(header2.name());
        assert_ne!(name1, name2);
    }
}

// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! Mock cryptographic primitives.
//!
//! These primitives are designed to be very fast (several times faster than the real ones), but
//! they are NOT secure. They are supposed to be used for testing only.

/// Mock version of a subset of the `rust_sodium` crate.
pub mod rust_sodium {
    use rand::{Rng, SeedableRng, XorShiftRng};
    use std::cell::RefCell;

    thread_local! {
        static RNG: RefCell<XorShiftRng> = RefCell::new(XorShiftRng::new_unseeded());
    }

    /// Initialise mock `rust_sodium`.
    pub fn init() -> bool {
        true
    }

    /// Initialise mock `rust_sodium` with the given random number generator. This can be used to
    /// guarantee reproducible test results.
    pub fn init_with_rng<T: Rng>(other: &mut T) -> Result<(), i32> {
        RNG.with(|rng| rng.borrow_mut().reseed(other.gen()));
        Ok(())
    }

    /// Mock cryptographic functions.
    pub mod crypto {
        /// Mock signing.
        pub mod sign {
            use super::super::with_rng;
            use rand::Rng;
            use std::ops::{Index, RangeFull};

            /// Number of bytes in a `PublicKey`.
            pub const PUBLICKEYBYTES: usize = 32;
            /// Number of bytes in a `SecretKey`.
            pub const SECRETKEYBYTES: usize = 32;
            /// Number of bytes in a `Signature`.
            pub const SIGNATUREBYTES: usize = 32;

            /// Mock signing public key.
            #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd,
                     Serialize)]
            pub struct PublicKey(pub [u8; PUBLICKEYBYTES]);

            impl Index<RangeFull> for PublicKey {
                type Output = [u8];
                fn index(&self, index: RangeFull) -> &[u8] {
                    self.0.index(index)
                }
            }

            /// Mock signing secret key.
            #[derive(Clone, Debug, Eq, PartialEq)]
            pub struct SecretKey(pub [u8; SECRETKEYBYTES]);

            /// Mock signature.
            #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, Serialize, PartialEq,
                     PartialOrd)]
            pub struct Signature(pub [u8; SIGNATUREBYTES]);

            impl AsRef<[u8]> for Signature {
                fn as_ref(&self) -> &[u8] {
                    &self.0
                }
            }

            /// Generate mock public and corresponding secret key.
            pub fn gen_keypair() -> (PublicKey, SecretKey) {
                with_rng(|rng| {
                    let value = rng.gen();
                    (PublicKey(value), SecretKey(value))
                })
            }

            /// Sign a message using the mock secret key.
            pub fn sign_detached(m: &[u8], sk: &SecretKey) -> Signature {
                let mut temp = m.to_vec();
                temp.extend(&sk.0);
                Signature(hash256(&temp))
            }

            /// Verify the mock signature against the message and the signer's mock public key.
            pub fn verify_detached(signature: &Signature, m: &[u8], pk: &PublicKey) -> bool {
                let mut temp = m.to_vec();
                temp.extend(&pk.0);
                *signature == Signature(hash256(&temp))
            }

            fn hash256(data: &[u8]) -> [u8; 32] {
                use tiny_keccak::sha3_256;
                sha3_256(data)
            }
        }

        /// Mock encryption.
        pub mod box_ {
            use super::super::with_rng;
            use rand::Rng;

            /// Number of bytes in a `PublicKey`.
            pub const PUBLICKEYBYTES: usize = 32;
            /// Number of bytes in a `SecretKey`.
            pub const SECRETKEYBYTES: usize = 32;
            /// Number of bytes in a `Nonce`.
            pub const NONCEBYTES: usize = 4;

            /// Mock public key for asymmetric encryption/decryption.
            #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd,
                     Serialize)]
            pub struct PublicKey(pub [u8; PUBLICKEYBYTES]);

            /// Mock secret key for asymmetric encryption/decryption.
            #[derive(Clone, Debug, Eq, PartialEq)]
            pub struct SecretKey(pub [u8; SECRETKEYBYTES]);

            /// Mock nonce for asymmetric encryption/decryption.
            pub struct Nonce(pub [u8; NONCEBYTES]);

            /// Generate mock public and corresponding secret key.
            pub fn gen_keypair() -> (PublicKey, SecretKey) {
                with_rng(|rng| {
                    let value = rng.gen();
                    (PublicKey(value), SecretKey(value))
                })
            }

            /// Generate mock nonce.
            pub fn gen_nonce() -> Nonce {
                with_rng(|rng| Nonce(rng.gen()))
            }

            /// Perform mock encryption of the given message using their public key, our secret key
            /// and nonce.
            pub fn seal(m: &[u8], nonce: &Nonce, pk: &PublicKey, sk: &SecretKey) -> Vec<u8> {
                let mut result =
                    Vec::with_capacity(m.len() + nonce.0.len() + pk.0.len() + sk.0.len());
                result.extend(&nonce.0);
                result.extend(&pk.0);
                result.extend(&sk.0);
                result.extend(m);
                result
            }

            /// Perform mock decryption of the given ciphertext using their secret key, our public
            /// key and nonce.
            pub fn open(
                c: &[u8],
                nonce: &Nonce,
                pk: &PublicKey,
                sk: &SecretKey,
            ) -> Result<Vec<u8>, ()> {
                let n = nonce.0.len();
                let p = pk.0.len();
                let s = sk.0.len();

                if c[0..n] != nonce.0 {
                    return Err(());
                }

                if c[n..n + p] != sk.0 {
                    return Err(());
                }

                if c[n + p..n + p + s] != pk.0 {
                    return Err(());
                }

                Ok(c[n + p + s..].to_vec())
            }
        }
    }

    fn with_rng<F, R>(f: F) -> R
    where
        F: FnOnce(&mut XorShiftRng) -> R,
    {
        RNG.with(|rng| f(&mut *rng.borrow_mut()))
    }
}

#[cfg(test)]
mod tests {
    use super::rust_sodium::crypto::{box_, sign};
    use rand::{self, Rng};

    #[test]
    fn keypair_generation() {
        let (sign_pk0, sign_sk0) = sign::gen_keypair();
        let (sign_pk1, sign_sk1) = sign::gen_keypair();
        assert_ne!(sign_pk0, sign_pk1);
        assert_ne!(sign_sk0, sign_sk1);

        let (box_pk0, box_sk0) = box_::gen_keypair();
        let (box_pk1, box_sk1) = box_::gen_keypair();
        assert_ne!(box_pk0, box_pk1);
        assert_ne!(box_sk0, box_sk1);
    }

    #[test]
    fn sign_and_verify() {
        let (pk0, sk0) = sign::gen_keypair();
        let message: Vec<_> = rand::thread_rng().gen_iter().take(10).collect();

        let signature = sign::sign_detached(&message, &sk0);
        assert!(sign::verify_detached(&signature, &message, &pk0));

        let (pk1, _) = sign::gen_keypair();
        assert!(!sign::verify_detached(&signature, &message, &pk1));
    }

    #[test]
    fn seal_and_open() {
        let (pk0, sk0) = box_::gen_keypair();
        let (pk1, sk1) = box_::gen_keypair();
        let nonce0 = box_::gen_nonce();

        let original: Vec<_> = rand::thread_rng().gen_iter().take(10).collect();
        let encrypted = box_::seal(&original, &nonce0, &pk0, &sk1);
        let decrypted = unwrap!(box_::open(&encrypted, &nonce0, &pk1, &sk0));
        assert_eq!(decrypted, original);

        assert!(box_::open(&encrypted, &nonce0, &pk0, &sk0).is_err());
        assert!(box_::open(&encrypted, &nonce0, &pk0, &sk1).is_err());
        assert!(box_::open(&encrypted, &nonce0, &pk1, &sk1).is_err());
    }
}

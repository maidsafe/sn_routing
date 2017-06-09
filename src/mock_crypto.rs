use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub mod rust_sodium {
    use rand::{Rng, SeedableRng, XorShiftRng};
    use std::sync::Mutex;

    lazy_static! {
        static ref RNG: Mutex<XorShiftRng> = Mutex::new(XorShiftRng::new_unseeded());
    }

    #[allow(unused)]
    pub fn init() -> bool {
        true
    }

    #[allow(unused)]
    pub fn init_with_rng<T: Rng>(rng: &mut T) -> Result<(), i32> {
        RNG.lock().unwrap().reseed(rng.gen());
        Ok(())
    }

    pub mod crypto {
        pub mod sign {
            use super::super::RNG;
            use super::super::super::cheap_hash;
            use rand::Rng;
            use std::ops::{Index, RangeFull};

            pub const PUBLICKEYBYTES: usize = 32;
            pub const SECRETKEYBYTES: usize = 32;
            pub const SIGNATUREBYTES: usize = 32;

            #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq,
                     PartialOrd, Serialize)]
            pub struct PublicKey(pub [u8; PUBLICKEYBYTES]);

            impl Index<RangeFull> for PublicKey {
                type Output = [u8];
                fn index(&self, index: RangeFull) -> &[u8] {
                    self.0.index(index)
                }
            }

            #[derive(Clone, Debug, Eq, PartialEq)]
            pub struct SecretKey(pub [u8; SECRETKEYBYTES]);

            #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq,
                     PartialOrd, Serialize)]
            pub struct Signature(pub [u8; SIGNATUREBYTES]);

            impl AsRef<[u8]> for Signature {
                fn as_ref(&self) -> &[u8] {
                    &self.0
                }
            }

            pub fn gen_keypair() -> (PublicKey, SecretKey) {
                let value = RNG.lock().unwrap().gen();
                (PublicKey(value), SecretKey(value))
            }

            pub fn sign_detached(m: &[u8], sk: &SecretKey) -> Signature {
                let mut temp = m.to_vec();
                temp.extend(&sk.0);
                Signature(cheap_hash(temp))
            }

            pub fn verify_detached(signature: &Signature, m: &[u8], pk: &PublicKey) -> bool {
                let mut temp = m.to_vec();
                temp.extend(&pk.0);
                *signature == Signature(cheap_hash(temp))
            }
        }

        pub mod box_ {
            use super::super::RNG;
            use rand::Rng;

            pub const PUBLICKEYBYTES: usize = 32;
            pub const SECRETKEYBYTES: usize = 32;
            pub const NONCEBYTES: usize = 4;

            #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq,
                     PartialOrd, Serialize)]
            pub struct PublicKey(pub [u8; PUBLICKEYBYTES]);

            #[derive(Clone, Debug, Eq, PartialEq)]
            pub struct SecretKey(pub [u8; SECRETKEYBYTES]);

            pub struct Nonce(pub [u8; NONCEBYTES]);

            pub fn gen_keypair() -> (PublicKey, SecretKey) {
                let value = RNG.lock().unwrap().gen();
                (PublicKey(value), SecretKey(value))
            }

            pub fn gen_nonce() -> Nonce {
                Nonce(RNG.lock().unwrap().gen())
            }

            pub fn seal(m: &[u8], nonce: &Nonce, pk: &PublicKey, sk: &SecretKey) -> Vec<u8> {
                let mut result = Vec::with_capacity(m.len() + nonce.0.len() + pk.0.len() +
                                                    sk.0.len());
                result.extend(&nonce.0);
                result.extend(&pk.0);
                result.extend(&sk.0);
                result.extend(m);
                result
            }

            pub fn open(c: &[u8],
                        nonce: &Nonce,
                        pk: &PublicKey,
                        sk: &SecretKey)
                        -> Result<Vec<u8>, ()> {
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

                return Ok(c[n + p + s..].to_vec());
            }
        }

        pub mod hash {
            pub mod sha256 {
                use super::super::super::super::cheap_hash;

                pub const DIGESTBYTES: usize = 32;

                #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq,
                         Serialize)]
                pub struct Digest(pub [u8; DIGESTBYTES]);

                pub fn hash(m: &[u8]) -> Digest {
                    Digest(cheap_hash(m))
                }
            }
        }
    }
}

pub mod tiny_keccak {
    use super::cheap_hash;

    pub fn sha3_256(data: &[u8]) -> [u8; 32] {
        cheap_hash(data)
    }
}

#[allow(unsafe_code)]
fn cheap_hash<T: Hash>(value: T) -> [u8; 32] {
    use std::mem;

    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    let hash = hasher.finish();

    let mut result = [0u8; 32];
    unsafe {
        let temp: &mut [u64; 4] = mem::transmute(&mut result);
        temp[0] = hash;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::rust_sodium::crypto::{box_, sign};
    use super::rust_sodium::crypto::hash::sha256;
    use super::tiny_keccak::sha3_256;
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

    #[test]
    fn hash() {
        assert_eq!(sha256::hash(b"alice"), sha256::hash(b"alice"));
        assert_ne!(sha256::hash(b"alice"), sha256::hash(b"bob"));

        assert_eq!(sha3_256(b"alice"), sha3_256(b"alice"));
        assert_ne!(sha3_256(b"alice"), sha3_256(b"bob"));
    }
}

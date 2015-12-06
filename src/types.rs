// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

// TODO(Spandan) This should not require documentation - infact the whole mod should be private
#[doc(hidden)]
pub type RoutingActionSender = ::maidsafe_utilities::event_sender::MaidSafeObserver<::action::Action>;

/// Convert u8 vector to a fixed 64 byte size array.
///
/// # Panics
///
/// Panics if the slice is not 64 bytes in length.
pub fn slice_as_u8_64_array(slice: &[u8]) -> [u8; 64] {
    assert!(slice.len() == 64);
    let mut arr = [0u8; 64];
    // TODO (canndrew): This should use copy_memory when it's stable
    for i in 0..64 {
        arr[i] = slice[i];
    }
    arr
}

/// Convert u8 slice to a fixed 32 byte size array.
///
/// # Panics
///
/// Panics if the slice is not 32 bytes in length
pub fn slice_as_u8_32_array(slice: &[u8]) -> [u8; 32] {
    assert!(slice.len() == 32);
    let mut arr = [0u8; 32];
    // TODO (canndrew): This should use copy_memory when it's stable
    for i in 0..32 {
        arr[i] = slice[i];
    }
    arr
}

/// Return a random vector of bytes of the given size.
pub fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..size {
        vec.push(::rand::random::<u8>());
    }
    vec
}

/// Quorum factor.
pub const QUORUM_FACTOR: f64 = ::kademlia_routing_table::QUORUM_SIZE as f64 /
                               ::kademlia_routing_table::GROUP_SIZE as f64;

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, RustcEncodable, RustcDecodable)]
/// Address.
pub enum Address {
    /// Is a client with supplied public key.
    Client(::sodiumoxide::crypto::sign::PublicKey),
    /// Is a node with given name.
    Node(::XorName),
}

impl ::std::fmt::Debug for Address {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
        match *self {
            Address::Client(ref public_key) => {
                formatter.write_str(&format!("Client({:?})", ::XorName::new(
                    ::sodiumoxide::crypto::hash::sha512::hash(&public_key[..]).0)))
            }
            Address::Node(ref name) => formatter.write_str(&format!("Node({:?})", name)),
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn check_conversions() {
        let bytes = super::generate_random_vec_u8(64);
        let array = super::slice_as_u8_64_array(&bytes[..]);

        assert_eq!(64, array.len());
        assert_eq!(&bytes[..], &array[..]);

        let bytes = super::generate_random_vec_u8(32);
        let array = super::slice_as_u8_32_array(&bytes[..]);

        assert_eq!(32, array.len());
        assert_eq!(&bytes[..], &array[..]);
    }


    #[test]
    fn address() {
        use rand;

        let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let client_address = super::Address::Client(sign_keys.0);

        match client_address {
            super::Address::Client(public_sign_key) => assert_eq!(sign_keys.0, public_sign_key),
            _ => panic!("Unexpected error."),
        }

        let name: ::XorName = rand::random();
        let node_address = super::Address::Node(name);

        match node_address {
            super::Address::Node(node_name) => assert_eq!(name, node_name),
            _ => panic!("Unexpected error."),
        }
    }
}

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

use std::hash;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use rustc_serialize::hex::{ToHex, FromHex, FromHexError};
use std::cmp::*;
use std::fmt;
use rand;

/// Constant byte length of NameType.
pub const NAME_TYPE_LEN : usize = 64;

/// Returns true if both slices are equal in length and have equal contents.
pub fn slice_equal<T: PartialEq>(lhs: &[T], rhs: &[T]) -> bool {
    lhs.len() == rhs.len() && lhs.iter().zip(rhs.iter()).all(|(a, b)| a == b)
}

/// Errors that can occur when decoding a `NameType` from a string.
pub enum NameTypeFromHexError {
    /// The given invalid hex character occured at the given position.
    InvalidCharacter(char, usize),
    /// The hex string did not encode `NAME_TYPE_LEN` bytes.
    InvalidLength,
}

/// NameType can be created using the new function by passing ID as it’s parameter.
#[derive(Eq, Copy)]
pub struct NameType(pub [u8; NAME_TYPE_LEN]);

#[allow(unused)]
impl NameType {

    /// Construct a NameType from a NAME_TYPE_LEN byte array.
    pub fn new(id: [u8; NAME_TYPE_LEN]) -> NameType {
        NameType(id)
    }

    /// Return the internal array.
    pub fn get_id(&self) -> [u8; NAME_TYPE_LEN] {
        self.0
    }

    /// Hex-encode the `NameType` as a `String`.
    pub fn as_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Hex-decode a `NameType` from a `&str`.
    pub fn from_hex(s: &str) -> Result<NameType, NameTypeFromHexError> {
        let data = match s.from_hex() {
            Ok(v)   => v,
            Err(FromHexError::InvalidHexCharacter(c, p))
                => return Err(NameTypeFromHexError::InvalidCharacter(c, p)),
            Err(FromHexError::InvalidHexLength)
                => return Err(NameTypeFromHexError::InvalidLength),
        };
        if data.len() != NAME_TYPE_LEN {
            return Err(NameTypeFromHexError::InvalidLength);
        }
        Ok(NameType(::types::slice_as_u8_64_array(&data[..])))
    }

    // Private function exposed in fmt Debug {:?} and Display {} traits.
    fn get_debug_id(&self) -> String {
        format!("{:02x}{:02x}{:02x}..{:02x}{:02x}{:02x}",
              self.0[0],
              self.0[1],
              self.0[2],
              self.0[NAME_TYPE_LEN-3],
              self.0[NAME_TYPE_LEN-2],
              self.0[NAME_TYPE_LEN-1])
    }
}

impl ::utilities::Identifiable for NameType {
    fn valid_public_id(&self, public_id: &::public_id::PublicId) -> bool {
        *self == public_id.name()
    }
}

impl fmt::Debug for NameType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.get_debug_id())
    }
}

impl fmt::Display for NameType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.get_debug_id())
    }
}

impl PartialEq for NameType {
    fn eq(&self, other: &NameType) -> bool {
        slice_equal(&self.0, &other.0)
    }
}

impl rand::Rand for NameType {
    fn rand<R: rand::Rng>(rng: &mut R) -> NameType {
        let mut ret = [0u8; NAME_TYPE_LEN];
        for r in ret[..].iter_mut() {
            *r = <u8 as rand::Rand>::rand(rng);
        }
        NameType(ret)
    }
}

/// Returns true if `lhs` is closer to `target` than `rhs`.  "Closer" here is as per the Kademlia
/// notion of XOR distance, i.e. the distance between two `NameType`s is the bitwise XOR of their
/// values.
pub fn closer_to_target(lhs: &NameType, rhs: &NameType, target: &NameType) -> bool {
    for i in 0..lhs.0.len() {
        let res_0 = lhs.0[i] ^ target.0[i];
        let res_1 = rhs.0[i] ^ target.0[i];

        if res_0 != res_1 {
            return res_0 < res_1
        }
    }
    false
}

/// Returns true if `lhs` is closer to `target` than `rhs`, or when `lhs == rhs`.
/// "Closer" here is as per the Kademlia notion of XOR distance,
/// i.e. the distance between two `NameType`s is the bitwise XOR of their values.
pub fn closer_to_target_or_equal(lhs: &NameType, rhs: &NameType, target: &NameType) -> bool {
    for i in 0..lhs.0.len() {
        let res_0 = lhs.0[i] ^ target.0[i];
        let res_1 = rhs.0[i] ^ target.0[i];

        if res_0 != res_1 {
            return res_0 < res_1
        }
    }
    true
}

/// The `NameType` can be ordered from zero as a normal Euclidean number
impl Ord for NameType {
    #[inline]
    fn cmp(&self, other: &NameType) -> Ordering {
        Ord::cmp(&&self.0[..], &&other.0[..])
    }
}

impl PartialOrd for NameType {
    #[inline]
    fn partial_cmp(&self, other: &NameType) -> Option<Ordering> {
        PartialOrd::partial_cmp(&&self.0[..], &&other.0[..])
    }
    #[inline]
    fn lt(&self, other: &NameType) -> bool {
        PartialOrd::lt(&&self.0[..], &&other.0[..])
    }
    #[inline]
    fn le(&self, other: &NameType) -> bool {
        PartialOrd::le(&&self.0[..], &&other.0[..])
    }
    #[inline]
    fn gt(&self, other: &NameType) -> bool {
        PartialOrd::gt(&&self.0[..], &&other.0[..])
    }
    #[inline]
    fn ge(&self, other: &NameType) -> bool {
        PartialOrd::ge(&&self.0[..], &&other.0[..])
    }
}

impl hash::Hash for NameType {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0[..])
    }
}

impl Clone for NameType {
    fn clone(&self) -> Self {
        let mut arr_cloned = [0u8; NAME_TYPE_LEN];
        let &NameType(arr_self) = self;

        for i in 0..arr_self.len() {
            arr_cloned[i] = arr_self[i];
        }

        NameType(arr_cloned)
    }
}

impl ::std::ops::Index<::std::ops::Range<usize>> for NameType {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::Range<usize>) -> &[u8] {
        let &NameType(ref b) = self;
        b.index(_index)
    }
}
impl ::std::ops::Index<::std::ops::RangeTo<usize>> for NameType {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::RangeTo<usize>) -> &[u8] {
        let &NameType(ref b) = self;
        b.index(_index)
    }
}
impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for NameType {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::RangeFrom<usize>) -> &[u8] {
        let &NameType(ref b) = self;
        b.index(_index)
    }
}
impl ::std::ops::Index<::std::ops::RangeFull> for NameType {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::RangeFull) -> &[u8] {
        let &NameType(ref b) = self;
        b.index(_index)
    }
}


impl Encodable for NameType {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), E::Error> {
        encoder.emit_seq(NAME_TYPE_LEN, |encoder| {
                for (i, e) in self[..].iter().enumerate() {
                    try!(encoder.emit_seq_elt(i, |encoder| e.encode(encoder)))
                }
                Ok(())
            })
    }
}

impl Decodable for NameType {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<NameType, D::Error> {
        decoder.read_seq(|decoder, len| {
                if len != NAME_TYPE_LEN {
                    return Err(decoder.error(
                        &format!("Expecting array of length: {}, but found {}",
                                 NAME_TYPE_LEN, len)));
                }
                let mut res = NameType([0; NAME_TYPE_LEN]);
                {
                    let NameType(ref mut arr) = res;
                    for (i, val) in arr.iter_mut().enumerate() {
                        *val = try!(decoder.read_seq_elt(i,
                            |decoder| Decodable::decode(decoder)));
                    }
                }
                Ok(res)
            })
    }
}

#[cfg(test)]
mod test {
    use cbor;
    use super::*;
    use id::Id;
    use rand;

    #[test]
    fn serialisation_name_type() {
        let obj_before: NameType = rand::random();
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: NameType = d.decode().next().unwrap().unwrap();
        assert_eq!(obj_before, obj_after);
    }

    #[test]
    fn name_type_equal_assertion() {
        let type1: NameType = rand::random();
        let type1_clone = type1.clone();
        let type2: NameType = rand::random();
        assert_eq!(type1, type1_clone);
        assert!(type1 == type1_clone);
        assert!(!(type1 != type1_clone));
        assert!(type1 != type2);
    }

    #[test]
    fn closeness() {
        let obj0: NameType = rand::random();
        let obj0_clone = obj0.clone();
        let obj1: NameType = rand::random();
        assert!(closer_to_target(&obj0_clone, &obj1, &obj0));
        assert!(!closer_to_target(&obj1, &obj0_clone, &obj0));
    }

    #[test]
    fn format_id_nametype() {
        // test for Ids
        for _ in 0..5 {
            let my_id = Id::new();
            let my_name = my_id.name();
            let debug_id = my_name.get_debug_id();
            let full_id = my_name.as_hex();
            assert_eq!(debug_id.len(), 14);
            assert_eq!(full_id.len(), 2 * NAME_TYPE_LEN);
            assert_eq!(&debug_id[0..6], &full_id[0..6]);
            assert_eq!(&debug_id[8..14], &full_id[2*NAME_TYPE_LEN-6..2*NAME_TYPE_LEN]);
            assert_eq!(&debug_id[6..8], "..");
        }
    }

    #[test]
    fn format_random_nametype() {
        // test for Random NameType
        for _ in 0..5 {
            let my_name : NameType = rand::random();
            let debug_id = my_name.get_debug_id();
            let full_id = my_name.as_hex();
            assert_eq!(debug_id.len(), 14);
            assert_eq!(full_id.len(), 2 * NAME_TYPE_LEN);
            assert_eq!(&debug_id[0..6], &full_id[0..6]);
            assert_eq!(&debug_id[8..14], &full_id[2*NAME_TYPE_LEN-6..2*NAME_TYPE_LEN]);
            assert_eq!(&debug_id[6..8], "..");
        }
    }

    #[test]
    fn format_fixed_low_char_nametype() {
        // test for fixed low char values in NameType
        let low_char_id = [1u8; NAME_TYPE_LEN];
        let my_low_char_name = NameType::new(low_char_id);
        let debug_id = my_low_char_name.get_debug_id();
        let full_id = my_low_char_name.as_hex();
        assert_eq!(debug_id.len(), 14);
        assert_eq!(full_id.len(), 2 * NAME_TYPE_LEN);
        assert_eq!(&debug_id[0..6], &full_id[0..6]);
        assert_eq!(&debug_id[8..14], &full_id[2*NAME_TYPE_LEN-6..2*NAME_TYPE_LEN]);
        assert_eq!(&debug_id[6..8], "..");
    }

    //TODO(Ben: resolve from_data)
    // #[test]
    // fn name_from_data() {
    //   use rustc_serialize::hex::ToHex;
    //   let data = "this is a known string".to_string().into_bytes();
    //   let expected_name = "8758b09d420bdb901d68fdd6888b38ce9ede06aad7f\
    //                        e1e0ea81feffc76260554b9d46fb6ea3b169ff8bb02\
    //                        ef14a03a122da52f3063bcb1bfb22cffc614def522".to_string();
    //   assert_eq!(&expected_name, &NameType::from_data(&data).0.to_hex());
    // }
}

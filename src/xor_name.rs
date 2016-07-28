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

use rand;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use rustc_serialize::hex::{FromHex, FromHexError, ToHex};
use std::cmp::Ordering;
use std::{fmt, ops};
use kademlia_routing_table::Xorable;


/// Create a 32-byte array of `u8` from a 32-byte reference to a `u8` slice.
pub fn slice_as_u8_32_array(slice: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr.clone_from_slice(slice);
    arr
}

/// Constant byte length of `XorName`.
pub const XOR_NAME_LEN: usize = 32;

/// Constant bit length of `XorName`.
pub const XOR_NAME_BITS: usize = XOR_NAME_LEN * 8;

/// Errors that can occur when decoding a `XorName` from a string.
#[derive(Debug)]
pub enum XorNameFromHexError {
    /// The given invalid hex character occurred at the given position.
    InvalidCharacter(char, usize),
    /// The hex string did not encode `XOR_NAME_LEN` bytes.
    WrongLength,
}


/// A [`XOR_NAME_BITS`](constant.XOR_NAME_BITS.html)-bit number, viewed as a point in XOR space.
///
/// This wraps an array of [`XOR_NAME_LEN`](constant.XOR_NAME_LEN.html) bytes, i. e. a number
/// between 0 and 2<sup>`XOR_NAME_BITS`</sup> - 1.
///
/// XOR space is the space of these numbers, with the [XOR metric][1] as a notion of distance,
/// i. e. the points with IDs `x` and `y` are considered to have distance `x xor y`.
///
/// [1]: https://en.wikipedia.org/wiki/Kademlia#System_details
#[derive(Eq, Copy, Clone, Hash, Ord, PartialEq, PartialOrd)]
pub struct XorName(pub [u8; XOR_NAME_LEN]);

impl XorName {
    /// Hex-encode the `XorName` as a `String`.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Returns a copy of `self`, with the `index`-th bit flipped.
    ///
    /// If the parameter does not address one of the name's bits, i. e. if it does not satisfy
    /// `index < XOR_NAME_BITS`, the result will be equal to the argument.
    pub fn with_flipped_bit(&self, index: usize) -> XorName {
        if index >= XOR_NAME_BITS {
            return *self;
        }
        let &XorName(mut bytes) = self;
        bytes[index / 8] ^= 1 << (7 - index % 8);
        XorName(bytes)
    }

    /// Returns the number of bits in which `self` differs from `other`.
    pub fn count_differing_bits(&self, other: &XorName) -> u32 {
        self.0.iter().zip(other.0.iter()).fold(0, |acc, (a, b)| acc + (a ^ b).count_ones())
    }

    /// Hex-decode a `XorName` from a `&str`.
    pub fn from_hex(s: &str) -> Result<XorName, XorNameFromHexError> {
        let data = match s.from_hex() {
            Ok(v) => v,
            Err(FromHexError::InvalidHexCharacter(c, p)) => {
                return Err(XorNameFromHexError::InvalidCharacter(c, p))
            }
            Err(FromHexError::InvalidHexLength) => return Err(XorNameFromHexError::WrongLength),
        };
        if data.len() != XOR_NAME_LEN {
            return Err(XorNameFromHexError::WrongLength);
        }
        Ok(XorName(slice_as_u8_32_array(&data[..])))
    }

    /// Returns the number of leading bits in which `self` and `name` agree.
    ///
    /// Here, "leading bits" means the most significant bits. E. g. for `10101...` and `10011...`,
    /// that value will be 2, as their common prefix `10` has length 2 and the third bit is the
    /// first one in which they disagree.
    ///
    /// Equivalently, this is `XOR_NAME_BITS - bucket_distance`, where `bucket_distance` is the
    /// length of the remainders after the common prefix is removed from the IDs of `self` and
    /// `name`.
    ///
    /// The bucket distance is the magnitude of the XOR distance. More precisely, if `d > 0` is the
    /// XOR distance between `self` and `name`, the bucket distance equals `floor(log2(d))`, i. e.
    /// a bucket distance of `n` means that 2<sup>`n - 1`</sup> `<= d <` 2<sup>`n`</sup>.
    pub fn bucket_index(&self, other: &XorName) -> usize {
        self.0.bucket_index(&other.0)
    }

    /// Compares `lhs` and `rhs` with respect to their distance from `self`.
    pub fn cmp_distance(&self, lhs: &XorName, rhs: &XorName) -> Ordering {
        self.0.cmp_distance(&lhs.0, &rhs.0)
    }

    /// Returns `true` if the `i`-th bit of `name` is different from the `i`-th bit of `self`.
    pub fn differs_in_bit(&self, name: &XorName, i: usize) -> bool {
        self.0.differs_in_bit(&name.0, i)
    }

    /// Returns true if `lhs` is closer to `self` than `rhs`.
    ///
    /// Equivalently, this returns `true` if in the most significant bit where `lhs` and `rhs`
    /// disagree, `lhs` agrees with `self`.
    pub fn closer(&self, lhs: &XorName, rhs: &XorName) -> bool {
        self.cmp_distance(lhs, rhs) == Ordering::Less
    }

    /// Returns true if `lhs` is closer to `self` than `rhs`, or `lhs == rhs`.
    pub fn closer_or_equal(&self, lhs: &XorName, rhs: &XorName) -> bool {
        self.cmp_distance(lhs, rhs) != Ordering::Greater
    }

    // Private function exposed in fmt Debug {:?} and Display {} traits.
    fn get_debug_id(&self) -> String {
        format!("{:02x}{:02x}{:02x}..", self.0[0], self.0[1], self.0[2])
    }
}

impl Xorable for XorName {
    fn bucket_index(&self, other: &XorName) -> usize {
        self.bucket_index(other)
    }

    fn cmp_distance(&self, lhs: &XorName, rhs: &XorName) -> Ordering {
        self.cmp_distance(lhs, rhs)
    }

    fn differs_in_bit(&self, name: &XorName, i: usize) -> bool {
        self.differs_in_bit(name, i)
    }
}

impl fmt::Debug for XorName {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}", self.get_debug_id())
    }
}

impl fmt::Display for XorName {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}", self.get_debug_id())
    }
}

impl fmt::Binary for XorName {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter,
               "{:08b} {:08b} {:08b}..{:08b} {:08b} {:08b}",
               self.0[0],
               self.0[1],
               self.0[2],
               self.0[XOR_NAME_LEN - 3],
               self.0[XOR_NAME_LEN - 2],
               self.0[XOR_NAME_LEN - 1])
    }
}

impl rand::Rand for XorName {
    fn rand<R: rand::Rng>(rng: &mut R) -> XorName {
        let mut ret = [0u8; XOR_NAME_LEN];
        for r in ret[..].iter_mut() {
            *r = <u8 as rand::Rand>::rand(rng);
        }
        XorName(ret)
    }
}

impl ops::Index<ops::Range<usize>> for XorName {
    type Output = [u8];
    fn index(&self, index: ops::Range<usize>) -> &[u8] {
        let &XorName(ref b) = self;
        b.index(index)
    }
}
impl ops::Index<ops::RangeTo<usize>> for XorName {
    type Output = [u8];
    fn index(&self, index: ops::RangeTo<usize>) -> &[u8] {
        let &XorName(ref b) = self;
        b.index(index)
    }
}

impl ops::Index<ops::RangeFrom<usize>> for XorName {
    type Output = [u8];
    fn index(&self, index: ops::RangeFrom<usize>) -> &[u8] {
        let &XorName(ref b) = self;
        b.index(index)
    }
}

impl ops::Index<ops::RangeFull> for XorName {
    type Output = [u8];
    fn index(&self, index: ops::RangeFull) -> &[u8] {
        let &XorName(ref b) = self;
        b.index(index)
    }
}

impl Encodable for XorName {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), E::Error> {
        encoder.emit_seq(XOR_NAME_LEN, |encoder| {
            for (i, e) in self[..].iter().enumerate() {
                try!(encoder.emit_seq_elt(i, |encoder| e.encode(encoder)))
            }
            Ok(())
        })
    }
}

impl Decodable for XorName {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<XorName, D::Error> {
        decoder.read_seq(|decoder, len| {
            if len != XOR_NAME_LEN {
                return Err(decoder.error(&format!("Expecting array of length: {}, but found {}",
                                                  XOR_NAME_LEN,
                                                  len)));
            }
            let mut res = XorName([0; XOR_NAME_LEN]);
            {
                let XorName(ref mut arr) = res;
                for (i, val) in arr.iter_mut().enumerate() {
                    *val = try!(decoder.read_seq_elt(i, |decoder| Decodable::decode(decoder)));
                }
            }
            Ok(res)
        })
    }
}

#[cfg(test)]
mod test {
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use std::cmp::Ordering;
    use super::*;
    use rand;

    #[test]
    fn serialisation_xor_name() {
        let obj_before: XorName = rand::random();
        let data = unwrap_result!(serialise(&obj_before));
        let obj_after: XorName = unwrap_result!(deserialise(&data));
        assert_eq!(obj_before, obj_after);
    }

    #[test]
    #[cfg_attr(feature="clippy", allow(eq_op))]
    fn xor_name_ord() {
        let type1: XorName = XorName([1u8; XOR_NAME_LEN]);
        let type2: XorName = XorName([2u8; XOR_NAME_LEN]);
        assert!(Ord::cmp(&type1, &type1) == Ordering::Equal);
        assert!(Ord::cmp(&type1, &type2) == Ordering::Less);
        assert!(Ord::cmp(&type2, &type1) == Ordering::Greater);
        assert!(type1 < type2);
        assert!(type1 <= type2);
        assert!(type1 <= type1);
        assert!(type2 > type1);
        assert!(type2 >= type1);
        assert!(type1 >= type1);
        assert!(!(type2 < type1));
        assert!(!(type2 <= type1));
        assert!(!(type1 > type2));
        assert!(!(type1 >= type2));
    }

    #[test]
    fn xor_name_equal_assertion() {
        let type1: XorName = rand::random();
        let type1_clone = type1;
        let type2: XorName = rand::random();
        assert_eq!(type1, type1_clone);
        assert!(type1 == type1_clone);
        assert!(!(type1 != type1_clone));
        assert!(type1 != type2);
    }

    #[test]
    fn closeness() {
        let obj0: XorName = rand::random();
        let obj0_clone = obj0;
        let obj1: XorName = rand::random();
        assert!(obj0.closer(&obj0_clone, &obj1));
        assert!(!obj0.closer(&obj1, &obj0_clone));
    }

    #[test]
    fn format_random_nametype() {
        // test for Random XorName
        for _ in 0..5 {
            let my_name: XorName = rand::random();
            let debug_id = my_name.get_debug_id();
            let full_id = my_name.to_hex();
            assert_eq!(debug_id.len(), 8);
            assert_eq!(full_id.len(), 2 * XOR_NAME_LEN);
            assert_eq!(&debug_id[0..6].to_owned(), &full_id[0..6]);
        }
    }

    #[test]
    fn format_fixed_low_char_nametype() {
        // test for fixed low char values in XorName
        let low_char_id = [1u8; XOR_NAME_LEN];
        let my_low_char_name = XorName(low_char_id);
        let debug_id = my_low_char_name.get_debug_id();
        let full_id = my_low_char_name.to_hex();
        assert_eq!(debug_id.len(), 8);
        assert_eq!(full_id.len(), 2 * XOR_NAME_LEN);
        assert_eq!(&debug_id[0..6], &full_id[0..6].to_owned());
    }

    #[test]
    fn with_flipped_bit() {
        let name: XorName = rand::random();
        for i in 0..18 {
            assert_eq!(i, name.bucket_index(&name.with_flipped_bit(i)));
        }
        for i in 0..10 {
            assert_eq!(19 * i, name.bucket_index(&name.with_flipped_bit(19 * i)));
        }
        assert_eq!(name, name.with_flipped_bit(XOR_NAME_BITS));
        assert_eq!(name, name.with_flipped_bit(XOR_NAME_BITS + 1000));
    }

    #[test]
    fn count_differing_bits() {
        let name: XorName = rand::random();
        assert_eq!(0, name.count_differing_bits(&name));
        let one_bit = name.with_flipped_bit(5);
        assert_eq!(1, name.count_differing_bits(&one_bit));
        let two_bits = one_bit.with_flipped_bit(100);
        assert_eq!(2, name.count_differing_bits(&two_bits));
    }
}

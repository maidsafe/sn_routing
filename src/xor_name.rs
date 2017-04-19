// Copyright 2015 MaidSafe.net limited.
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

use hex::{FromHex, FromHexError, ToHex};
use rand;
use routing_table::Xorable;
use std::{fmt, ops};
use std::cmp::Ordering;

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
#[derive(Eq, Copy, Clone, Default, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct XorName(pub [u8; XOR_NAME_LEN]);

impl XorName {
    /// Hex-encode the `XorName` as a `String`.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Returns the number of bits in which `self` differs from `other`.
    pub fn count_differing_bits(&self, other: &XorName) -> u32 {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0, |acc, (a, b)| acc + (a ^ b).count_ones())
    }

    /// Hex-decode a `XorName` from a `&str`.
    pub fn from_hex(s: &str) -> Result<XorName, XorNameFromHexError> {
        let data: Vec<u8> = match FromHex::from_hex(&s) {
            Ok(v) => v,
            Err(FromHexError::InvalidHexCharacter { c, index }) => {
                return Err(XorNameFromHexError::InvalidCharacter(c, index))
            }
            Err(FromHexError::InvalidHexLength) => return Err(XorNameFromHexError::WrongLength),
        };
        if data.len() != XOR_NAME_LEN {
            return Err(XorNameFromHexError::WrongLength);
        }
        Ok(XorName(slice_as_u8_32_array(&data[..])))
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

    /// Calculate the absolute difference between this name and another, |self - other|.
    ///
    /// This is 1-dimensional Euclidean distance.
    pub fn abs_difference<'a>(&'a self, other: &'a XorName) -> XorName {
        if self >= other {
            self - other
        } else {
            other - self
        }
    }

    /// Return true if the name is in the interval [start, end] (both endpoint inclusive).
    pub fn between(&self, start: &XorName, end: &XorName) -> bool {
        self >= start && self <= end
    }
}

impl Xorable for XorName {
    fn common_prefix(&self, other: &XorName) -> usize {
        self.0.common_prefix(&other.0)
    }

    fn cmp_distance(&self, lhs: &XorName, rhs: &XorName) -> Ordering {
        self.0.cmp_distance(&lhs.0, &rhs.0)
    }

    fn bit(&self, i: usize) -> bool {
        self.0.bit(i)
    }

    fn differs_in_bit(&self, name: &XorName, i: usize) -> bool {
        self.0.differs_in_bit(&name.0, i)
    }

    fn with_flipped_bit(self, i: usize) -> XorName {
        XorName(self.0.with_flipped_bit(i))
    }

    fn with_bit(self, i: usize, bit: bool) -> Self {
        XorName(self.0.with_bit(i, bit))
    }

    fn binary(&self) -> String {
        self.0.binary()
    }

    fn debug_binary(&self) -> String {
        self.0.debug_binary()
    }

    fn set_remaining(self, n: usize, val: bool) -> Self {
        XorName(self.0.set_remaining(n, val))
    }

    fn from_hash<T: AsRef<[u8]>>(hash: T) -> Self {
        XorName(Xorable::from_hash(hash))
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
        write!(formatter, "{}", self.debug_binary())
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

impl ops::Not for XorName {
    type Output = XorName;
    fn not(mut self) -> XorName {
        for byte in &mut self.0 {
            *byte = !*byte;
        }
        self
    }
}

impl ops::Sub for XorName {
    type Output = XorName;

    fn sub(self, rhs: XorName) -> Self::Output {
        &self - &rhs
    }
}

impl<'a> ops::Sub for &'a XorName {
    type Output = XorName;
    fn sub(self, rhs: &XorName) -> Self::Output {
        let XorName(ref x) = *self;
        let XorName(ref y) = *rhs;

        let mut result = [0; XOR_NAME_LEN];
        let mut carry = 0;

        for i in (0..XOR_NAME_LEN).rev() {
            if x[i] == 0 && carry == 1 {
                result[i] = 255 - y[i];
                continue;
            }

            let x_val: u16 = x[i] as u16 - carry;
            let y_val: u16 = y[i] as u16;

            if x_val >= y_val {
                result[i] = (x_val - y_val) as u8;
                carry = 0;
            } else {
                result[i] = (256 + x_val - y_val) as u8;
                carry = 1;
            }
        }

        #[cfg(debug_assertions)]
        panic_on_underflow(x, y, carry);

        XorName(result)
    }
}

#[cfg(debug_assertions)]
fn panic_on_underflow(x: &[u8; XOR_NAME_LEN], y: &[u8; XOR_NAME_LEN], carry: u16) {
    if carry != 0 {
        panic!("underflow while subtracting XorNames with content: {:?}, {:?}",
               x,
               y);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use rand;
    use routing_table::Xorable;
    use std::cmp::Ordering;

    #[test]
    fn serialisation_xor_name() {
        let obj_before: XorName = rand::random();
        let data = unwrap!(serialise(&obj_before));
        assert_eq!(data.len(), XOR_NAME_LEN);
        let obj_after: XorName = unwrap!(deserialise(&data));
        assert_eq!(obj_before, obj_after);
    }

    #[test]
    #[cfg_attr(feature="cargo-clippy", allow(eq_op))]
    fn xor_name_ord() {
        let type1: XorName = XorName([1u8; XOR_NAME_LEN]);
        let type2: XorName = XorName([2u8; XOR_NAME_LEN]);
        assert_eq!(Ord::cmp(&type1, &type1), Ordering::Equal);
        assert_eq!(Ord::cmp(&type1, &type2), Ordering::Less);
        assert_eq!(Ord::cmp(&type2, &type1), Ordering::Greater);
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
        assert!(!(type1 != type1_clone));
        assert_ne!(type1, type2);
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
            assert_eq!(i, name.common_prefix(&name.with_flipped_bit(i)));
        }
        for i in 0..10 {
            assert_eq!(19 * i, name.common_prefix(&name.with_flipped_bit(19 * i)));
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

    #[test]
    fn subtraction() {
        for _ in 0..100000 {
            let x = rand::random();
            let y = rand::random();
            let (larger, smaller) = if x > y { (x, y) } else { (y, x) };
            assert_eq!(&xor_from_int(larger - smaller)[..],
                       &(xor_from_int(larger) - xor_from_int(smaller))[..]);
        }
    }

    #[test]
    #[cfg_attr(debug_assertions, should_panic)]
    fn subtraction_underflow() {
        let _ = xor_from_int(1_000_001) - xor_from_int(1_000_002);
    }

    #[test]
    fn abs_difference() {
        for _ in 0..100000 {
            let x = rand::random();
            let y = rand::random();

            let abs_diff_int = if x >= y { x - y } else { y - x };

            let x_diff_y = xor_from_int(x).abs_difference(&xor_from_int(y));
            let y_diff_x = xor_from_int(y).abs_difference(&xor_from_int(x));

            assert_eq!(&xor_from_int(abs_diff_int)[..], &x_diff_y[..]);
            assert_eq!(&x_diff_y[..], &y_diff_x[..]);
        }
    }

    #[test]
    fn from_int() {
        assert_eq!(&xor_from_int(0xabcdef)[XOR_NAME_LEN - 3..],
                   &[0xab, 0xcd, 0xef]);
        assert_eq!(xor_from_int(0xabcdef)[..XOR_NAME_LEN - 3],
                   XorName::default()[..XOR_NAME_LEN - 3]);
    }

    fn xor_from_int(x: u64) -> XorName {
        let mut name = XorName::default();
        for i in 0..8 {
            name.0[XOR_NAME_LEN - 1 - i] = ((x >> (8 * i)) & 0xff) as u8;
        }
        name
    }
}

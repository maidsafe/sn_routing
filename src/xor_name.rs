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

use hex::ToHex;
use num_bigint::BigUint;
use rand;
use std::{fmt, ops};
use std::cmp::Ordering;

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
/// This wraps an array of [`XOR_NAME_LEN`](constant.XOR_NAME_LEN.html) bytes, i.e. a number
/// between 0 and 2<sup>`XOR_NAME_BITS`</sup> - 1.
///
/// XOR space is the space of these numbers, with the [XOR metric][1] as a notion of distance,
/// i. e. the points with IDs `x` and `y` are considered to have distance `x xor y`.
///
/// [1]: https://en.wikipedia.org/wiki/Kademlia#System_details
#[derive(Eq, Copy, Clone, Default, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct XorName(pub [u8; XOR_NAME_LEN]);

impl XorName {
    /// Returns the length of the common prefix with the `other`; e.g. when `other = 11110000` and
    /// `self = 11111111` this is 4.
    pub fn common_prefix(&self, other: &Self) -> usize {
        for byte_index in 0..XOR_NAME_LEN {
            if self[byte_index] != other[byte_index] {
                return (byte_index * 8) +
                    (self[byte_index] ^ other[byte_index]).leading_zeros() as usize;
            }
        }
        XOR_NAME_BITS
    }

    /// Compares the distance of the arguments to `self`. Returns `Less` if `lhs` is closer,
    /// `Greater` if `rhs` is closer, and `Equal` if `lhs == rhs`. (The XOR distance can only be
    /// equal if the arguments are equal.)
    pub fn cmp_distance(&self, lhs: &Self, rhs: &Self) -> Ordering {
        for i in 0..XOR_NAME_LEN {
            if lhs[i] != rhs[i] {
                return Ord::cmp(&(lhs[i] ^ self[i]), &(rhs[i] ^ self[i]));
            }
        }
        Ordering::Equal
    }

    /// Returns `true` if the `bit_index`-th bit is `1`.
    pub fn bit(&self, bit_index: usize) -> bool {
        let byte_index = bit_index / 8;
        let pow_i = 1 << (7 - (bit_index % 8));
        self[byte_index] & pow_i != 0
    }

    /// Returns `true` if the `bit_index`-th bit of `other` has a different value to the
    /// `bit_index`-th bit of `self`.
    pub fn differs_in_bit(&self, other: &Self, bit_index: usize) -> bool {
        let byte_index = bit_index / 8;
        let pow_i = 1 << (7 - (bit_index % 8));
        (self[byte_index] ^ other[byte_index]) & pow_i != 0
    }

    /// Returns a copy of `self`, with the `bit_index`-th bit flipped.
    ///
    /// If `bit_index` >= `XOR_NAME_BITS`, an unmodified copy of `self` is returned.
    pub fn with_flipped_bit(mut self, bit_index: usize) -> Self {
        if bit_index >= XOR_NAME_BITS {
            return self;
        }
        self[bit_index / 8] ^= 1 << (7 - (bit_index % 8));
        self
    }

    /// Returns a copy of `self`, with the `bit_index`-th bit set to 0 if `value` is false or 1 if
    /// `value` is true.
    ///
    /// If `bit_index` >= `XOR_NAME_BITS`, an unmodified copy of `self` is returned.
    pub fn with_bit(mut self, bit_index: usize, value: bool) -> Self {
        if bit_index >= XOR_NAME_BITS {
            return self;
        }
        let pow_i = 1 << (7 - (bit_index % 8));
        if value {
            self[bit_index / 8] |= pow_i;
        } else {
            self[bit_index / 8] &= !pow_i;
        }
        self
    }

    /// Returns a binary format string, with leading zero bits included.
    pub fn binary(&self) -> String {
        let mut result = String::with_capacity(XOR_NAME_BITS);
        for value in &self.0 {
            result.push_str(&format!("{:08b}", value));
        }
        result
    }

    /// Returns a binary debug format string of `????????...????????`
    pub fn debug_binary(&self) -> String {
        let mut result = String::with_capacity(19);
        result.push_str(&format!("{:08b}", self[0]));
        result.push_str("...");
        result.push_str(&format!("{:08b}", self[XOR_NAME_LEN - 1]));
        result
    }

    /// Returns a copy of self with first `n` bits preserved, and remaining bits set to 0 if `value`
    /// is false or 1 if `value` is true.
    ///
    /// If `n` >= `XOR_NAME_BITS`, an unmodified copy of `self` is returned.
    pub fn set_remaining(mut self, n: usize, value: bool) -> Self {
        for (byte_index, byte_value) in self.0.iter_mut().enumerate() {
            if n <= byte_index * 8 {
                *byte_value = if value { !0 } else { 0 };
            } else if n < (byte_index + 1) * 8 {
                let mask = !0 >> (n - byte_index * 8);
                if value {
                    *byte_value |= mask
                } else {
                    *byte_value &= !mask
                }
            }
            // else n >= XOR_NAME_BITS: nothing to do
        }
        self
    }

    /// Hex-encode the `XorName` as a `String`.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Returns the number of bits in which `self` differs from `other`.
    pub fn count_differing_bits(&self, other: &Self) -> u32 {
        self.0.iter().zip(other.0.iter()).fold(0, |acc, (a, b)| {
            acc + (a ^ b).count_ones()
        })
    }

    // /// Hex-decode a `XorName` from a `&str`.
    // pub fn from_hex(s: &str) -> Result<Self, XorNameFromHexError> {
    //     let data: Vec<u8> = match FromHex::from_hex(&s) {
    //         Ok(v) => v,
    //         Err(FromHexError::InvalidHexCharacter { c, index }) => {
    //             return Err(XorNameFromHexError::InvalidCharacter(c, index))
    //         }
    //         Err(FromHexError::InvalidHexLength) => return Err(XorNameFromHexError::WrongLength),
    //     };
    //     if data.len() != XOR_NAME_LEN {
    //         return Err(XorNameFromHexError::WrongLength);
    //     }
    //     Ok(XorName(slice_as_u8_32_array(&data[..])))
    // }

    /// Returns true if `lhs` is closer to `self` than `rhs`.
    ///
    /// Equivalently, this returns `true` if in the most significant bit where `lhs` and `rhs`
    /// disagree, `lhs` agrees with `self`.
    pub fn closer(&self, lhs: &Self, rhs: &Self) -> bool {
        self.cmp_distance(lhs, rhs) == Ordering::Less
    }

    /// Returns true if `lhs` is closer to `self` than `rhs`, or `lhs == rhs`.
    pub fn closer_or_equal(&self, lhs: &Self, rhs: &Self) -> bool {
        self.cmp_distance(lhs, rhs) != Ordering::Greater
    }

    /// Private function exposed in fmt Debug {:?} and Display {} traits.
    fn get_debug_id(&self) -> String {
        format!("{:02x}{:02x}{:02x}..", self.0[0], self.0[1], self.0[2])
    }

    /// Used to construct a XorName from a `BigUint`. `value` should not represent a number greater
    /// than or equal to `2^XOR_NAME_BITS`. If it does, the excessive most significant bits are
    /// ignored.
    fn from_big_uint(value: BigUint) -> Self {
        let little_endian_value = value.to_bytes_le();
        if little_endian_value.len() > XOR_NAME_LEN {
            error!("This BigUint value exceeds the maximum capable of being held as an XorName.");
        }
        // Convert the little-endian vector to a 32-byte big-endian array.
        let mut xor_name = Self::default();
        for (xor_name_elt, little_endian_elt) in
            xor_name.0.iter_mut().rev().zip(little_endian_value.iter())
        {
            *xor_name_elt = *little_endian_elt;
        }
        xor_name
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
        let mut result = [0u8; XOR_NAME_LEN];
        rng.fill_bytes(&mut result);
        XorName(result)
    }
}

impl ops::Index<usize> for XorName {
    type Output = u8;
    fn index(&self, index: usize) -> &u8 {
        let &XorName(ref b) = self;
        b.index(index)
    }
}

impl ops::IndexMut<usize> for XorName {
    fn index_mut(&mut self, index: usize) -> &mut u8 {
        let &mut XorName(ref mut b) = self;
        b.index_mut(index)
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
        (&self).sub(&rhs)
    }
}

impl<'a> ops::Sub for &'a XorName {
    type Output = XorName;
    fn sub(self, rhs: &XorName) -> Self::Output {
        XorName::from_big_uint(
            BigUint::from_bytes_be(&self.0) - BigUint::from_bytes_be(&rhs.0),
        )
    }
}

impl ops::Div<u32> for XorName {
    type Output = XorName;
    fn div(self, rhs: u32) -> Self::Output {
        (&self).div(&rhs)
    }
}

impl<'a> ops::Div<&'a u32> for &'a XorName {
    type Output = XorName;
    fn div(self, rhs: &u32) -> Self::Output {
        XorName::from_big_uint(BigUint::from_bytes_be(&self.0) / BigUint::new(vec![*rhs]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maidsafe_utilities::SeededRng;
    use rand::Rng;
    use std::cmp::Ordering;

    // Assigns the 8 bytes of `x` to the *last* 8 elements of a default `XorName`.
    fn xor_name_from_int(x: u64) -> XorName {
        let mut name = XorName::default();
        for i in 0..8 {
            name[XOR_NAME_LEN - 1 - i] = ((x >> (8 * i)) & 0xff) as u8;
        }
        name
    }

    // Assigns the 4 bytes of `x` to the *first* 4 elements of a default `XorName`.
    fn xor_name_from_array(x: [u8; 4]) -> XorName {
        let mut name = XorName::default();
        for i in 0..4 {
            name[i] = x[i];
        }
        name
    }

    #[test]
    fn common_prefix() {
        // 0000.. and 1000..
        let mut lhs = XorName::default();
        let mut rhs = xor_name_from_array([128, 0, 0, 0]);
        assert_eq!(0, lhs.common_prefix(&rhs));
        assert_eq!(0, rhs.common_prefix(&lhs));

        // 0000_0000_0000_1010.. and 0000_0000_0001_0000..
        lhs = xor_name_from_array([0, 10, 0, 0]);
        rhs = xor_name_from_array([0, 16, 0, 0]);
        assert_eq!(11, lhs.common_prefix(&rhs));
        assert_eq!(11, rhs.common_prefix(&lhs));

        // equal `XorName`s
        let mut rng = SeededRng::thread_rng();
        lhs = rng.gen();
        rhs = lhs;
        assert_eq!(XOR_NAME_BITS, lhs.common_prefix(&rhs));
        assert_eq!(XOR_NAME_BITS, rhs.common_prefix(&lhs));
    }

    #[test]
    fn cmp_distance() {
        let target = xor_name_from_array([1, 2, 3, 4]);
        let mut name1 = xor_name_from_array([2, 3, 4, 5]);
        let mut name2 = name1;
        assert_eq!(Ordering::Equal, target.cmp_distance(&name1, &name2));

        name1 = xor_name_from_array([2, 2, 4, 5]);
        name2 = xor_name_from_array([2, 3, 6, 5]);
        assert_eq!(Ordering::Less, target.cmp_distance(&name1, &name2));
        assert_eq!(Ordering::Greater, target.cmp_distance(&name2, &name1));

        name1 = xor_name_from_array([1, 2, 3, 8]);
        name2 = xor_name_from_array([1, 2, 8, 4]);
        assert_eq!(Ordering::Less, target.cmp_distance(&name1, &name2));
        assert_eq!(Ordering::Greater, target.cmp_distance(&name2, &name1));

        name1 = xor_name_from_array([1, 2, 7, 4]);
        name2 = xor_name_from_array([1, 2, 6, 4]);
        assert_eq!(Ordering::Less, target.cmp_distance(&name1, &name2));
        assert_eq!(Ordering::Greater, target.cmp_distance(&name2, &name1));
    }

    #[test]
    fn bit() {
        let name = xor_name_from_array([2, 128, 1, 0]);
        assert_eq!(true, name.bit(6));
        assert_eq!(true, name.bit(8));
        assert_eq!(true, name.bit(23));
        assert_eq!(false, name.bit(5));
        assert_eq!(false, name.bit(7));
        assert_eq!(false, name.bit(9));
        assert_eq!(false, name.bit(22));
        assert_eq!(false, name.bit(24));
    }

    #[test]
    fn differs_in_bit() {
        let mut name = xor_name_from_array([0, 1, 0, 16]);
        assert!(XorName::default().differs_in_bit(&name, 15));
        name = xor_name_from_array([0, 7, 0, 0]);
        assert!(name.differs_in_bit(&XorName::default(), 14));
        assert!(!name.differs_in_bit(&XorName::default(), 26));
    }

    #[test]
    fn set_remaining() {
        let name = xor_name_from_array([13, 112, 9, 1]);
        assert_eq!(name.set_remaining(0, false), XorName::default());
        assert_eq!(name.set_remaining(100, false), name);
        assert_eq!(
            name.set_remaining(10, false),
            xor_name_from_array([13, 64, 0, 0])
        );
        let mut expected = XorName([255; XOR_NAME_LEN]);
        expected[0] = 13;
        expected[1] = 127;
        assert_eq!(name.set_remaining(10, true), expected);
    }

    #[test]
    #[cfg_attr(feature = "cargo-clippy", allow(eq_op))]
    fn ord() {
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
    fn equal_assertion() {
        let mut rng = SeededRng::thread_rng();
        let type1: XorName = rng.gen();
        let type1_clone = type1;
        let type2: XorName = rng.gen();
        assert_eq!(type1, type1_clone);
        assert!(!(type1 != type1_clone));
        assert_ne!(type1, type2);
    }

    #[test]
    fn closeness() {
        let mut rng = SeededRng::thread_rng();
        let obj0: XorName = rng.gen();
        let obj0_clone = obj0;
        let obj1: XorName = rng.gen();
        assert!(obj0.closer(&obj0_clone, &obj1));
        assert!(!obj0.closer(&obj1, &obj0_clone));
    }

    #[test]
    fn format_random_nametype() {
        // test for Random XorName
        let mut rng = SeededRng::thread_rng();
        for _ in 0..5 {
            let my_name: XorName = rng.gen();
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
        let mut rng = SeededRng::thread_rng();
        let name: XorName = rng.gen();
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
        let mut rng = SeededRng::thread_rng();
        let name: XorName = rng.gen();
        assert_eq!(0, name.count_differing_bits(&name));
        let one_bit = name.with_flipped_bit(5);
        assert_eq!(1, name.count_differing_bits(&one_bit));
        let two_bits = one_bit.with_flipped_bit(100);
        assert_eq!(2, name.count_differing_bits(&two_bits));
    }

    #[test]
    fn subtraction() {
        let mut rng = SeededRng::thread_rng();
        for _ in 0..100000 {
            let x = rng.gen();
            let y = rng.gen();
            let (larger, smaller) = if x > y { (x, y) } else { (y, x) };
            assert_eq!(
                &xor_name_from_int(larger - smaller)[..],
                &(xor_name_from_int(larger) - xor_name_from_int(smaller))[..]
            );
            assert_eq!(
                XorName::default(),
                xor_name_from_int(x) - xor_name_from_int(x)
            );
        }
    }

    #[test]
    #[should_panic]
    fn subtraction_underflow() {
        let _ = xor_name_from_int(1_000_001) - xor_name_from_int(1_000_002);
    }

    #[test]
    fn division() {
        let mut rng = SeededRng::thread_rng();
        for _ in 0..100000 {
            let x = rng.gen();
            let y = rng.gen();
            assert_eq!(xor_name_from_int(x / y as u64), xor_name_from_int(x) / y);
            assert_eq!(xor_name_from_int(1), xor_name_from_int(y as u64) / y);
        }
    }

    #[test]
    #[should_panic]
    fn division_by_zero() {
        let _ = xor_name_from_int(1) / 0;
    }

    #[test]
    fn check_from_int() {
        assert_eq!(
            &xor_name_from_int(0xabcdef)[XOR_NAME_LEN - 3..],
            &[0xab, 0xcd, 0xef]
        );
        assert_eq!(
            xor_name_from_int(0xabcdef)[..XOR_NAME_LEN - 3],
            XorName::default()[..XOR_NAME_LEN - 3]
        );
    }
}

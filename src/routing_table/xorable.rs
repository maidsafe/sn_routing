// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use std::cmp::Ordering;
use std::mem;

/// A sequence of bits, as a point in XOR space.
///
/// These are considered points in a space with the XOR metric, and need to implement the
/// functionality required by `RoutingTable` to use them as node names.
pub trait Xorable: Ord {
    /// Returns the bucket that `other` belongs to, in the routing table of the node with name
    /// `self`. This must be the number of leading bits in which `self` and `other` agree. E. g.
    /// the bucket index of `other = 11110000` for `self = 11111111` is 4, because the fifth bit is
    /// the first one in which they differ.
    fn common_prefix(&self, other: &Self) -> usize;

    /// Compares the distance of the arguments to `self`. Returns `Less` if `lhs` is closer,
    /// `Greater` if `rhs` is closer, and `Equal` if `lhs == rhs`. (The XOR distance can only be
    /// equal if the arguments are equal.)
    fn cmp_distance(&self, lhs: &Self, rhs: &Self) -> Ordering;

    /// Returns `true` if the `i`-th bit is `1`.
    fn bit(&self, i: usize) -> bool;

    /// Returns `true` if the `i`-th bit of other has a different value to the `i`-th bit of `self`.
    fn differs_in_bit(&self, other: &Self, i: usize) -> bool;

    /// Returns a copy of `self`, with the `index`-th bit flipped.
    ///
    /// If `index` exceeds the number of bits in `self`, an unmodified copy of `self` is returned.
    fn with_flipped_bit(self, i: usize) -> Self;

    /// Returns a copy of `self`, with the `index`-th bit set to `bit`.
    ///
    /// If `index` exceeds the number of bits in `self`, an unmodified copy of `self` is returned.
    fn with_bit(self, i: usize, bit: bool) -> Self;

    /// Returns a binary format string, with leading zero bits included.
    fn binary(&self) -> String;

    /// Returns a binary debug format string of `????????...????????`
    fn debug_binary(&self) -> String;

    /// Returns a copy of self with first `n` bits preserved, and remaining bits
    /// set to 0 (val == false) or 1 (val == true).
    fn set_remaining(self, n: usize, val: bool) -> Self;
}

/// Converts a string into debug format of `????????...????????` when the string is longer than 20.
pub fn debug_format(input: String) -> String {
    if input.len() <= 20 {
        return input;
    }
    input.chars().take(8).chain("...".chars()).chain(input.chars().skip(input.len() - 8)).collect()
}

macro_rules! impl_xorable_for_array {
    ($t: ident, $l: expr) => {
        impl Xorable for [$t; $l] {
            fn common_prefix(&self, other: &[$t; $l]) -> usize {
                for byte_index in 0..$l {
                    if self[byte_index] != other[byte_index] {
                        return (byte_index * mem::size_of::<$t>() * 8) +
                               (self[byte_index] ^ other[byte_index]).leading_zeros() as usize;
                    }
                }
                $l * mem::size_of::<$t>()
            }

            fn cmp_distance(&self, lhs: &[$t; $l], rhs: &[$t; $l]) -> Ordering {
                for i in 0..$l {
                    if lhs[i] != rhs[i] {
                        return Ord::cmp(&(lhs[i] ^ self[i]), &(rhs[i] ^ self[i]));
                    }
                }
                Ordering::Equal
            }

            fn bit(&self, i: usize) -> bool {
                let bits = mem::size_of::<$t>() * 8;
                let index = i / bits;
                let pow_i = 1 << (bits - 1 - (i % bits));
                self[index] & pow_i != 0
            }

            fn differs_in_bit(&self, name: &[$t; $l], i: usize) -> bool {
                let bits = mem::size_of::<$t>() * 8;
                let index = i / bits;
                let pow_i = 1 << (bits - 1 - (i % bits));
                (self[index] ^ name[index]) & pow_i != 0
            }

            fn with_flipped_bit(mut self, i: usize) -> Self {
                let bits = mem::size_of::<$t>() * 8;
                if i >= bits * self.len() {
                    return self;
                }
                self[i / bits] ^= 1 << (bits - 1 - i % bits);
                self
            }

            fn with_bit(mut self, i: usize, bit: bool) -> Self {
                let bits = mem::size_of::<$t>() * 8;
                if i >= bits * self.len() {
                    return self;
                }
                let pow_i = 1 << (bits - 1 - i % bits); // 1 on bit i % bits.
                if bit {
                    self[i / bits] |= pow_i;
                } else {
                    self[i / bits] &= !pow_i;
                }
                self
            }

            fn binary(&self) -> String {
                let bits = mem::size_of::<$t>() * 8 * $l;
                let mut s = String::with_capacity(bits);
                for value in self.iter() {
                    s.push_str(&value.binary());
                }
                s
            }

            fn debug_binary(&self) -> String {
                debug_format(self.binary())
            }
            
            fn set_remaining(mut self, n: usize, val: bool) -> Self {
                let bits = mem::size_of::<$t>() * 8;
                for i in 0..$l {
                    if n <= i * bits {
                        self[i] = if val { !0 } else { 0 };
                    } else if n < (i + 1) * bits {
                        let mask = !0 >> (n - i * bits);
                        if val {
                            self[i] = self[i] | mask
                        } else {
                            self[i] = self[i] & !mask
                        }
                    }
                    // else n >= (i+1) * bits: nothing to do
                }
                self
            }
        }
    }
}

impl_xorable_for_array!(u8, 32);
impl_xorable_for_array!(u8, 16);
impl_xorable_for_array!(u8, 8);
impl_xorable_for_array!(u8, 4);

macro_rules! impl_xorable {
    ($t:ident) => {
        impl Xorable for $t {
            fn common_prefix(&self, other: &Self) -> usize {
                (self ^ other).leading_zeros() as usize
            }

            fn cmp_distance(&self, lhs: &Self, rhs: &Self) -> Ordering {
                Ord::cmp(&(lhs ^ self), &(rhs ^ self))
            }

            fn bit(&self, i: usize) -> bool {
                let pow_i = 1 << (mem::size_of::<Self>() * 8 - 1 - i); // 1 on bit i.
                self & pow_i != 0
            }

            fn differs_in_bit(&self, name: &Self, i: usize) -> bool {
                let pow_i = 1 << (mem::size_of::<Self>() * 8 - 1 - i); // 1 on bit i.
                (self ^ name) & pow_i != 0
            }

            fn with_flipped_bit(mut self, i: usize) -> Self {
                if i >= mem::size_of::<Self>() * 8 {
                    return self;
                }
                let pow_i = 1 << (mem::size_of::<Self>() * 8 - 1 - i); // 1 on bit i.
                self ^= pow_i;
                self
            }

            fn with_bit(mut self, i: usize, bit: bool) -> Self {
                if i >= mem::size_of::<Self>() * 8 {
                    return self;
                }
                let pow_i = 1 << (mem::size_of::<Self>() * 8 - 1 - i); // 1 on bit i.
                if bit {
                    self |= pow_i;
                } else {
                    self &= !pow_i;
                }
                self
            }

            fn binary(&self) -> String {
                format!("{1:00$b}", mem::size_of::<Self>() * 8, self)
            }

            fn debug_binary(&self) -> String {
                debug_format(self.binary())
            }
            
            fn set_remaining(mut self, n: usize, val: bool) -> Self {
                let bits = mem::size_of::<$t>() * 8;
                if n >= bits {
                    self
                } else {
                    let mask = !0 >> n;
                    if val {
                        self | mask
                    } else {
                        self & !mask
                    }
                }
            }
        }
    }
}

impl_xorable!(usize);
impl_xorable!(u64);
impl_xorable!(u32);
impl_xorable!(u16);
impl_xorable!(u8);



#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use super::*;

    #[test]
    fn common_prefix() {
        assert_eq!(0, 0u8.common_prefix(&128u8));
        assert_eq!(3, 10u8.common_prefix(&16u8));
        assert_eq!(0, 0u16.common_prefix(&(1 << 15)));
        assert_eq!(11, 10u16.common_prefix(&16u16));
    }

    #[test]
    fn common_prefix_array() {
        assert_eq!(0, [0, 0, 0, 0].common_prefix(&[128u8, 0, 0, 0]));
        assert_eq!(11, [0, 10u8, 0, 0].common_prefix(&[0, 16u8, 0, 0]));
    }

    #[test]
    fn cmp_distance() {
        assert_eq!(Ordering::Equal, 42u8.cmp_distance(&13, &13));
        assert_eq!(Ordering::Less, 42u8.cmp_distance(&44, &45));
        assert_eq!(Ordering::Greater, 42u8.cmp_distance(&45, &44));
    }

    #[test]
    fn cmp_distance_array() {
        assert_eq!(Ordering::Equal,
                   [1u8, 2, 3, 4].cmp_distance(&[2u8, 3, 4, 5], &[2u8, 3, 4, 5]));
        assert_eq!(Ordering::Less,
                   [1u8, 2, 3, 4].cmp_distance(&[2u8, 2, 4, 5], &[2u8, 3, 6, 5]));
        assert_eq!(Ordering::Greater,
                   [1u8, 2, 3, 4].cmp_distance(&[2u8, 3, 6, 5], &[2u8, 2, 4, 5]));
        assert_eq!(Ordering::Less,
                   [1u8, 2, 3, 4].cmp_distance(&[1, 2, 3, 8], &[1, 2, 8, 4]));
        assert_eq!(Ordering::Greater,
                   [1u8, 2, 3, 4].cmp_distance(&[1, 2, 8, 4], &[1, 2, 3, 8]));
        assert_eq!(Ordering::Less,
                   [1u8, 2, 3, 4].cmp_distance(&[1, 2, 7, 4], &[1, 2, 6, 4]));
        assert_eq!(Ordering::Greater,
                   [1u8, 2, 3, 4].cmp_distance(&[1, 2, 6, 4], &[1, 2, 7, 4]));
    }

    #[test]
    fn bit() {
        assert_eq!(false, 0b00101000u8.bit(0));
        assert_eq!(true, 0b00101000u8.bit(2));
        assert_eq!(false, 0b00101000u8.bit(3));
    }

    #[test]
    fn bit_array() {
        assert_eq!(true, [2u8, 128, 1, 0].bit(6));
        assert_eq!(true, [2u8, 128, 1, 0].bit(8));
        assert_eq!(true, [2u8, 128, 1, 0].bit(23));
        assert_eq!(false, [2u8, 128, 1, 0].bit(5));
        assert_eq!(false, [2u8, 128, 1, 0].bit(7));
        assert_eq!(false, [2u8, 128, 1, 0].bit(9));
        assert_eq!(false, [2u8, 128, 1, 0].bit(22));
        assert_eq!(false, [2u8, 128, 1, 0].bit(24));
    }

    #[test]
    fn differs_in_bit() {
        assert!(0b00101010u8.differs_in_bit(&0b00100010u8, 4));
        assert!(0b00101010u8.differs_in_bit(&0b00000010u8, 4));
        assert!(!0b00101010u8.differs_in_bit(&0b00001010u8, 4));
    }

    #[test]
    fn differs_in_bit_array() {
        assert!([0u8, 0, 0, 0].differs_in_bit(&[0, 1, 0, 10], 15));
        assert!([0u8, 7, 0, 0].differs_in_bit(&[0, 0, 0, 0], 14));
        assert!(![0u8, 7, 0, 0].differs_in_bit(&[0, 0, 0, 0], 26));
    }

    #[test]
    fn set_remaining() {
        assert_eq!(0b10011011u8.set_remaining(5, false), 0b10011000);
        assert_eq!(0b11111111u8.set_remaining(2, false), 0b11000000);
        assert_eq!(0b00000000u8.set_remaining(4, true), 0b00001111);
    }

    #[test]
    fn set_remaining_array() {
        assert_eq!([13u8, 112, 9, 1].set_remaining(0, false), [0u8, 0, 0, 0]);
        assert_eq!([13u8, 112, 9, 1].set_remaining(100, false),
                   [13u8, 112, 9, 1]);
        assert_eq!([13u8, 112, 9, 1].set_remaining(10, false), [13u8, 64, 0, 0]);
        assert_eq!([13u8, 112, 9, 1].set_remaining(10, true),
                   [13u8, 127, 255, 255]);
    }
}

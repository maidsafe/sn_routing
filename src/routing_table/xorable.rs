// Copyright 2016 MaidSafe.net limited.
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

use std::mem;
use std::cmp::Ordering;

/// A sequence of bits, as a point in XOR space.
///
/// These are considered points in a space with the XOR metric, and need to implement the
/// functionality required by `RoutingTable` to use them as node names.
pub trait Xorable {
    /// Returns the bucket that `other` belongs to, in the routing table of the node with name
    /// `self`. This must be the number of leading bits in which `self` and `other` agree. E. g.
    /// the bucket index of `other = 11110000` for `self = 11111111` is 4, because the fifth bit is
    /// the first one in which they differ.
    fn max_bucket_index(&self, other: &Self) -> usize;

    /// Compares the distance of the arguments to `self`. Returns `Less` if `lhs` is closer,
    /// `Greater` if `rhs` is closer, and `Equal` if `lhs == rhs`. (The XOR distance can only be
    /// equal if the arguments are equal.)
    fn cmp_distance(&self, lhs: &Self, rhs: &Self) -> Ordering;

    /// Returns `true` if the `i`-th bit of other has a different value to the `i`-th bit of `self`.
    fn differs_in_bit(&self, other: &Self, i: usize) -> bool;

    /// Returns a copy of `self`, with the `index`-th bit flipped.
    ///
    /// If the parameter does not address one of the name's bits, i. e. if it does not satisfy
    /// `index < XOR_NAME_BITS`, the result will be equal to the argument.
    fn with_flipped_bit(&self, index: usize) -> Self;

    /// Returns a default copy(all zero)
    fn all_zero_copy() -> Self;
}


macro_rules! impl_xorable_for_array {
    ($t: ident, $l: expr) => {
        impl Xorable for [$t; $l] {
            fn max_bucket_index(&self, other: &[$t; $l]) -> usize {
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

            fn differs_in_bit(&self, name: &[$t; $l], i: usize) -> bool {
                let bits = mem::size_of::<$t>() * 8;
                let index = i / bits;
                let pow_i = 1 << (bits - 1 - (i % bits));
                (self[index] ^ name[index]) & pow_i != 0
            }

            fn with_flipped_bit(&self, index: usize) -> Self {
                let bits = mem::size_of::<$t>() * 8;
                let mut copy = *self;
                if index >= bits * self.len() {
                    return copy;
                }
                copy[index / bits] ^= 1 << (bits - 1 - index % bits);
                copy
            }

            fn all_zero_copy() -> Self {
                [0; $l]
            }
        }
    }
}

impl_xorable_for_array!(u8, 64);
impl_xorable_for_array!(u8, 32);
impl_xorable_for_array!(u8, 16);
impl_xorable_for_array!(u8, 8);
impl_xorable_for_array!(u8, 4);

macro_rules! impl_xorable {
    ($t:ident) => {
        impl Xorable for $t {
            fn max_bucket_index(&self, other: &Self) -> usize {
                (self ^ other).leading_zeros() as usize
            }

            fn cmp_distance(&self, lhs: &Self, rhs: &Self) -> Ordering {
                Ord::cmp(&(lhs ^ self), &(rhs ^ self))
            }

            fn differs_in_bit(&self, name: &Self, i: usize) -> bool {
                let pow_i = 1 << (mem::size_of::<Self>() * 8 - 1 - i); // 1 on bit i.
                (self ^ name) & pow_i != 0
            }

            fn with_flipped_bit(&self, index: usize) -> Self {
                if index >= mem::size_of::<Self>() * 8 {
                    return *self;
                }
                let pow_i = 1 << (mem::size_of::<Self>() * 8 - 1 - index); // 1 on bit i.
                self ^ pow_i
            }

            fn all_zero_copy() -> Self {
                0
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
mod test {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn max_bucket_index() {
        assert_eq!(0, 0u8.max_bucket_index(&128u8));
        assert_eq!(3, 10u8.max_bucket_index(&16u8));
        assert_eq!(0, 0u16.max_bucket_index(&(1 << 15)));
        assert_eq!(11, 10u16.max_bucket_index(&16u16));
    }

    #[test]
    fn max_bucket_index_array() {
        assert_eq!(0, [0, 0, 0, 0].max_bucket_index(&[128u8, 0, 0, 0]));
        assert_eq!(11, [0, 10u8, 0, 0].max_bucket_index(&[0, 16u8, 0, 0]));
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
}

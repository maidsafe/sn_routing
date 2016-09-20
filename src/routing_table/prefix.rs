// Copyright 2015 MaidSafe.net limited.
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

use std::cmp::{self, Ordering};
use std::fmt::{Binary, Debug, Formatter};
use std::fmt::Result as FmtResult;
use std::hash::{Hash, Hasher};
use super::xorable::Xorable;

// A group prefix, i.e. a sequence of bits specifying the part of the network's name space
// consisting of all names that start with this sequence.
#[derive(Clone, Copy, Default, Eq, Ord)]
pub struct Prefix<T: Clone + Copy + Default + Binary + Xorable> {
    bit_count: usize,
    name: T,
}

impl<T: Clone + Copy + Default + Binary + Xorable> Prefix<T> {
    /// Constructor.
    pub fn new(bit_count: usize, name: T) -> Prefix<T> {
        Prefix {
            bit_count: bit_count,
            name: name,
        }
    }

    /// Return a copy of `self` with the `bit_count` increased by one and update `self` by also
    /// increasing the `bit_count` by one and flipping bit at the old `bit_count`.
    ///
    /// E.g. for prefix `10` where name is `1010`, `self` will become `101` and this will return
    /// `100`.
    ///
    /// Note that this means for the case where `a` and `b` are `Prefix`es and `a == b`, then it
    /// doesn't necessarily follow that `a.split() == b.split()`.
    pub fn split(&mut self) -> Prefix<T> {
        self.bit_count += 1;
        Prefix::new(self.bit_count,
                    self.name.with_flipped_bit(self.bit_count - 1))
    }

    /// Used when merging two groups whose prefixes differ at `bit_count`.  Effectively decrements
    /// the `bit_count` by `1`.
    pub fn merge(&mut self) {
        self.bit_count -= 1;
    }

    /// Getter.
    pub fn bit_count(&self) -> usize {
        self.bit_count
    }

    /// Returns `true` if `self` is a prefix of `other` or vice versa.
    pub fn is_compatible(&self, other: &Prefix<T>) -> bool {
        let i = self.name.common_prefix(&other.name);
        i >= self.bit_count || i >= other.bit_count
    }

    /// Returns `true` if the `other` prefix differs in exactly one bit from this one.
    pub fn is_neighbour(&self, other: &Prefix<T>) -> bool {
        let i = self.name.common_prefix(&other.name);
        if i >= self.bit_count || i >= other.bit_count {
            false
        } else {
            let j = self.name.with_flipped_bit(i).common_prefix(&other.name);
            j >= self.bit_count || j >= other.bit_count
        }
    }

    pub fn common_prefix(&self, name: &T) -> usize {
        cmp::min(self.bit_count, self.name.common_prefix(name))
    }

    pub fn max_identical_index(&self, name: &T) -> usize {
        self.name.common_prefix(name)
    }

    /// Returns `true` if this is a prefix of the given `name`.
    pub fn matches(&self, name: &T) -> bool {
        self.name.common_prefix(name) >= self.bit_count
    }

    /// Compares the distance of `self` and `other` to `target`. Returns `Less` if `self` is closer,
    /// `Greater` if `other` is closer, and `Equal` if `self.name == other.name`.
    pub fn cmp_distance(&self, other: &Self, target: &T) -> Ordering {
        target.cmp_distance(&self.name, &other.name)
    }
}

impl<T: Clone + Copy + Default + Binary + Xorable> PartialEq<Prefix<T>> for Prefix<T> {
    fn eq(&self, other: &Self) -> bool {
        self.is_compatible(other) && self.bit_count == other.bit_count
    }
}

impl<T: Clone + Copy + Default + Binary + Xorable> PartialOrd<Prefix<T>> for Prefix<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self == other {
            Some(Ordering::Equal)
        } else if self.is_compatible(other) {
            None
        } else {
            Some(self.name.cmp(&other.name))
        }
    }
}

impl<T: Clone + Copy + Default + Binary + Xorable> Hash for Prefix<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for i in 0..self.bit_count {
            self.name.bit(i).hash(state);
        }
    }
}

impl<T: Clone + Copy + Default + Binary + Xorable> Binary for Prefix<T> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        let mut binary = format!("{:08b}", self.name);
        binary.truncate(self.bit_count);
        write!(formatter, "Prefix({})", binary)
    }
}

impl<T: Clone + Copy + Default + Binary + Xorable> Debug for Prefix<T> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        Binary::fmt(self, formatter)
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    fn str_to_prefix(bits: &[u8]) -> Prefix<u8> {
        let mut name = 0u8;
        for (i, bit) in bits.iter().enumerate() {
            if *bit == b'1' {
                name |= 1 << (7 - i);
            }
        }
        Prefix::new(bits.len(), name)
    }

    #[test]
    fn prefix() {
        let mut prefix = str_to_prefix(b"101");
        assert_eq!(prefix.split(), str_to_prefix(b"1011"));
        assert_eq!(prefix, str_to_prefix(b"1010"));
        assert!(str_to_prefix(b"101").is_compatible(&str_to_prefix(b"1010")));
        assert!(str_to_prefix(b"1010").is_compatible(&str_to_prefix(b"101")));
        assert!(!str_to_prefix(b"1010").is_compatible(&str_to_prefix(b"1011")));
        // assert_eq!(3, str_to_prefix(b"1010").common_prefix(&str_to_prefix(b"1011"))); // 101
        // assert_eq!(3, str_to_prefix(b"101").common_prefix(&str_to_prefix(b"1011"))); // 101
        assert!(str_to_prefix(b"101").is_neighbour(&str_to_prefix(b"1111")));
        assert!(!str_to_prefix(b"1010").is_neighbour(&str_to_prefix(b"1111")));
        assert!(str_to_prefix(b"1010").is_neighbour(&str_to_prefix(b"10111")));
        assert!(!str_to_prefix(b"101").is_neighbour(&str_to_prefix(b"10111")));
        assert!(str_to_prefix(b"101").matches(&0b10101100));
        assert!(!str_to_prefix(b"1011").matches(&0b10101100));
    }
}

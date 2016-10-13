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

use rustc_serialize::{Decodable, Decoder, DecoderHelpers, Encodable, Encoder, EncoderHelpers};
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
//TODO: insignificant bits should all be zero!

impl<T: Clone + Copy + Default + Binary + Xorable> Prefix<T> {
    /// Creates a new `Prefix` with the first `bit_count` bits of `name`.
    pub fn new(bit_count: usize, name: T) -> Prefix<T> {
        Prefix {
            bit_count: bit_count,
            name: name,
        }
    }

    /// Returns `self` with an appended bit: `0` if `bit` is `false`, and `1` if `bit` is `true`.
    pub fn pushed(mut self, bit: bool) -> Prefix<T> {
        self.name = self.name.with_bit(self.bit_count, bit);
        self.bit_count += 1;
        self
    }

    /// Returns a prefix copying the first `bitcount() - 1` bits from `self`,
    /// or `self` if it is already empty.
    pub fn popped(mut self) -> Prefix<T> {
        self.bit_count = self.bit_count.saturating_sub(1);
        self
    }

    /// Returns the number of bits in the prefix.
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
    /// `Greater` if `other` is closer, and `Equal` if they are equally close or compatible.
    pub fn cmp_distance(&self, other: &Self, target: &T) -> Ordering {
        if self.is_compatible(&other) {
            Ordering::Equal
        } else {
            Ord::cmp(&other.name.common_prefix(target),
                     &self.name.common_prefix(target))
        }
    }
    
    /// Returns the smallest name matching the prefix
    pub fn lower_bound(&self) -> T {
        self.name.set_remaining(self.bit_count, false)
    }
    
    /// Returns the largest name matching the prefix
    pub fn upper_bound(&self) -> T {
        self.name.set_remaining(self.bit_count, true)
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
        let mut binary = self.name.binary();
        binary.truncate(self.bit_count);
        write!(formatter, "Prefix({})", binary)
    }
}

impl<T: Clone + Copy + Default + Binary + Xorable> Debug for Prefix<T> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        Binary::fmt(self, formatter)
    }
}

impl<T: Clone + Copy + Default + Binary + Xorable> Encodable for Prefix<T> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), E::Error> {
        let bit_vec = (0..self.bit_count).map(|i| self.name.bit(i)).collect::<Vec<_>>();
        encoder.emit_from_vec(&bit_vec, |encoder, element| encoder.emit_bool(*element))
    }
}

impl<T: Clone + Copy + Default + Binary + Xorable> Decodable for Prefix<T> {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Prefix<T>, D::Error> {
        // TODO - This is a rough and ready implementation to be replaced by Andreas' upcoming one.
        // This implementation will cause the `split()` function to be incorrect as that depends on
        // `self.name` being the name of the holder.  I don't know what idiot thought `split()` was
        // a good idea!
        let bit_vec = try!(decoder.read_to_vec(|decoder| decoder.read_bool()));
        let mut name = T::default();
        for (index, element) in bit_vec.iter().enumerate() {
            if name.bit(index) != *element {
                name = name.with_flipped_bit(index);
            }
        }
        Ok(Prefix::new(bit_vec.len(), name))
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
        assert_eq!(str_to_prefix(b"101").pushed(true), str_to_prefix(b"1011"));
        assert_eq!(str_to_prefix(b"101").pushed(false), str_to_prefix(b"1010"));
        assert_eq!(str_to_prefix(b"1011").popped(), str_to_prefix(b"101"));
        assert!(str_to_prefix(b"101").is_compatible(&str_to_prefix(b"1010")));
        assert!(str_to_prefix(b"1010").is_compatible(&str_to_prefix(b"101")));
        assert!(!str_to_prefix(b"1010").is_compatible(&str_to_prefix(b"1011")));
        assert!(str_to_prefix(b"101").is_neighbour(&str_to_prefix(b"1111")));
        assert!(!str_to_prefix(b"1010").is_neighbour(&str_to_prefix(b"1111")));
        assert!(str_to_prefix(b"1010").is_neighbour(&str_to_prefix(b"10111")));
        assert!(!str_to_prefix(b"101").is_neighbour(&str_to_prefix(b"10111")));
        assert!(str_to_prefix(b"101").matches(&0b10101100));
        assert!(!str_to_prefix(b"1011").matches(&0b10101100));
        
        assert_eq!(str_to_prefix(b"0101").lower_bound(), 0b01010000);
        assert_eq!(str_to_prefix(b"0101").upper_bound(), 0b01011111);
    }
}

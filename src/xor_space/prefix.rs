// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Xorable;
use std::{
    cmp::{self, Ordering},
    fmt::{Binary, Debug, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    ops::RangeInclusive,
};

#[cfg(test)]
use {super::XorName, std::str::FromStr};

/// A section prefix, i.e. a sequence of bits specifying the part of the network's name space
/// consisting of all names that start with this sequence.
#[derive(Clone, Copy, Default, Eq, Deserialize, Serialize)]
pub struct Prefix<T: Clone + Copy + Default + Binary + Xorable> {
    bit_count: u16,
    name: T,
}

impl<T: Clone + Copy + Default + Binary + Xorable> Prefix<T> {
    /// Creates a new `Prefix` with the first `bit_count` bits of `name`. Insignificant bits are all
    /// set to 0. If `bit_count` exceeds the size of `T` in bits, then it is reduced to this lower
    /// value.
    pub fn new(bit_count: usize, name: T) -> Prefix<T> {
        Prefix {
            bit_count: cmp::min(bit_count, T::bit_len()) as u16,
            name: name.set_remaining(bit_count, false),
        }
    }

    /// Returns the name of this prefix.
    pub fn name(&self) -> T {
        self.name
    }

    /// Returns `self` with an appended bit: `0` if `bit` is `false`, and `1` if `bit` is `true`. If
    /// `self.bit_count` is already at the maximum for this type, then an unmodified copy of `self`
    /// is returned.
    pub fn pushed(mut self, bit: bool) -> Prefix<T> {
        self.name = self.name.with_bit(self.bit_count(), bit);
        self.bit_count = cmp::min(self.bit_count + 1, T::bit_len() as u16);
        self
    }

    /// Returns a prefix copying the first `bitcount() - 1` bits from `self`,
    /// or `self` if it is already empty.
    pub fn popped(mut self) -> Prefix<T> {
        if self.bit_count > 0 {
            self.bit_count -= 1;
            // unused bits should be zero:
            self.name = self.name.with_bit(self.bit_count(), false);
        }
        self
    }

    /// Returns the number of bits in the prefix.
    pub fn bit_count(&self) -> usize {
        self.bit_count as usize
    }

    /// Returns `true` if this is the empty prefix, with no bits.
    pub fn is_empty(&self) -> bool {
        self.bit_count == 0
    }

    /// Returns `true` if `self` is a prefix of `other` or vice versa.
    pub fn is_compatible(&self, other: &Prefix<T>) -> bool {
        let i = self.name.common_prefix(&other.name);
        i >= self.bit_count() || i >= other.bit_count()
    }

    /// Returns `true` if `other` is compatible but strictly shorter than `self`.
    pub fn is_extension_of(&self, other: &Prefix<T>) -> bool {
        let i = self.name.common_prefix(&other.name);
        i >= other.bit_count() && self.bit_count() > other.bit_count()
    }

    /// Returns `true` if the `other` prefix differs in exactly one bit from this one.
    pub fn is_neighbour(&self, other: &Prefix<T>) -> bool {
        let i = self.name.common_prefix(&other.name);
        if i >= self.bit_count() || i >= other.bit_count() {
            false
        } else {
            let j = self.name.with_flipped_bit(i).common_prefix(&other.name);
            j >= self.bit_count() || j >= other.bit_count()
        }
    }

    /// Returns `true` if the `other` prefix differs only in the last bit from this one.
    pub fn is_sibling(&self, other: &Self) -> bool {
        let i = self.name.common_prefix(&other.name);
        self.bit_count() == other.bit_count() && self.bit_count() == i + 1
    }

    /// Returns the number of common leading bits with the input name, capped with prefix length.
    pub fn common_prefix(&self, name: &T) -> usize {
        cmp::min(self.bit_count(), self.name.common_prefix(name))
    }

    /// Returns `true` if this is a prefix of the given `name`.
    pub fn matches(&self, name: &T) -> bool {
        self.name.common_prefix(name) >= self.bit_count()
    }

    /// Compares the distance of `self` and `other` to `target` (returns `Less` if `self` is
    /// closer to `target` than `other`).
    pub fn cmp_distance(&self, other: &Self, target: &T) -> Ordering {
        let lhs_len = self.bit_count();
        let lhs_diff = lhs_len - self.common_prefix(target);

        let rhs_len = other.bit_count();
        let rhs_diff = rhs_len - other.common_prefix(target);

        lhs_diff.cmp(&rhs_diff).then_with(|| rhs_len.cmp(&lhs_len))
    }

    /// Compares the prefixes using breadth-first order. That is, shorter prefixes are ordered
    /// before longer. This is in contrast with the default `Ord` impl of `Prefix` which uses
    /// depth-first order.
    pub fn cmp_breadth_first(&self, other: &Self) -> Ordering {
        self.bit_count
            .cmp(&other.bit_count)
            .then_with(|| self.name.cmp(&other.name))
    }

    /// Returns the smallest name matching the prefix
    pub fn lower_bound(&self) -> T {
        self.name.set_remaining(self.bit_count(), false)
    }

    /// Returns the largest name matching the prefix
    pub fn upper_bound(&self) -> T {
        self.name.set_remaining(self.bit_count(), true)
    }

    /// Inclusive range from lower_bound to upper_bound
    pub fn range_inclusive(&self) -> RangeInclusive<T> {
        RangeInclusive::new(self.lower_bound(), self.upper_bound())
    }

    /// Returns whether the namespace defined by `self` is covered by prefixes in the `prefixes`
    /// set
    pub fn is_covered_by<'a, U>(&self, prefixes: U) -> bool
    where
        T: 'a,
        U: IntoIterator<Item = &'a Prefix<T>> + Clone,
    {
        let max_prefix_len = prefixes
            .clone()
            .into_iter()
            .map(Prefix::bit_count)
            .max()
            .unwrap_or(0);
        self.is_covered_by_impl(prefixes, max_prefix_len)
    }

    fn is_covered_by_impl<'a, U>(&self, prefixes: U, max_prefix_len: usize) -> bool
    where
        T: 'a,
        U: IntoIterator<Item = &'a Prefix<T>> + Clone,
    {
        prefixes
            .clone()
            .into_iter()
            .any(|x| x.is_compatible(self) && x.bit_count() <= self.bit_count())
            || (self.bit_count() <= max_prefix_len
                && self
                    .pushed(false)
                    .is_covered_by_impl(prefixes.clone(), max_prefix_len)
                && self
                    .pushed(true)
                    .is_covered_by_impl(prefixes, max_prefix_len))
    }

    /// Returns the neighbouring prefix differing in the `i`-th bit
    /// If `i` is larger than our bit count, `self` is returned
    pub fn with_flipped_bit(&self, i: usize) -> Prefix<T> {
        if i >= self.bit_count() {
            *self
        } else {
            Self::new(self.bit_count(), self.name.with_flipped_bit(i))
        }
    }

    /// Returns the given `name` with first bits replaced by `self`
    pub fn substituted_in(&self, mut name: T) -> T {
        // TODO: is there a more efficient way of doing that?
        for i in 0..self.bit_count() {
            name = name.with_bit(i, self.name.bit(i));
        }
        name
    }

    /// Returns the same prefix, with the last bit flipped, or unchanged, if empty.
    pub fn sibling(&self) -> Prefix<T> {
        if self.bit_count > 0 {
            self.with_flipped_bit((self.bit_count - 1) as usize)
        } else {
            *self
        }
    }

    /// Returns the ancestors of this prefix that has the given bit count.
    ///
    /// # Panics
    ///
    /// Panics if `bit_count` is not less than the bit count of this prefix.
    pub fn ancestor(&self, bit_count: usize) -> Prefix<T> {
        assert!(bit_count < self.bit_count());
        Self::new(bit_count, self.name)
    }

    /// Returns an iterator that yields all ancestors of this prefix.
    pub fn ancestors(&self) -> Ancestors<T> {
        Ancestors {
            target: *self,
            current_len: 0,
        }
    }
}

impl<T: Clone + Copy + Default + Binary + Xorable> PartialEq<Prefix<T>> for Prefix<T> {
    fn eq(&self, other: &Self) -> bool {
        self.is_compatible(other) && self.bit_count == other.bit_count
    }
}

impl<T: Clone + Copy + Default + Binary + Xorable> PartialOrd<Prefix<T>> for Prefix<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Clone + Copy + Default + Binary + Xorable> Ord for Prefix<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            Ordering::Equal
        } else if self.is_compatible(other) {
            self.bit_count().cmp(&other.bit_count())
        } else {
            self.name.cmp(&other.name)
        }
    }
}

impl<T: Clone + Copy + Default + Binary + Xorable> Hash for Prefix<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for i in 0..self.bit_count() {
            self.name.bit(i).hash(state);
        }
    }
}

impl<T: Clone + Copy + Default + Binary + Xorable> Binary for Prefix<T> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        let mut binary = self.name.binary();
        binary.truncate(self.bit_count());
        write!(formatter, "{}", binary)
    }
}

impl<T: Clone + Copy + Default + Binary + Xorable> Debug for Prefix<T> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        write!(formatter, "Prefix({:b})", self)
    }
}

#[cfg(test)]
impl FromStr for Prefix<u8> {
    type Err = String;

    fn from_str(bits: &str) -> Result<Prefix<u8>, String> {
        let mut name = 0u8;
        for (i, bit) in bits.chars().enumerate() {
            if bit == '1' {
                name |= 1 << (7 - i);
            } else if bit != '0' {
                return Err(format!(
                    "'{}' not allowed - the string must represent a binary number.",
                    bit
                ));
            }
        }
        Ok(Self::new(bits.len(), name))
    }
}

#[cfg(test)]
impl FromStr for Prefix<XorName> {
    type Err = String;

    fn from_str(bits: &str) -> Result<Prefix<XorName>, String> {
        let mut name = [0; 32];
        for (i, bit) in bits.chars().enumerate() {
            if bit == '1' {
                let byte = i / 8;
                name[byte] |= 1 << (7 - i);
            } else if bit != '0' {
                return Err(format!(
                    "'{}' not allowed - the string must represent a binary number.",
                    bit
                ));
            }
        }
        Ok(Self::new(bits.len(), XorName(name)))
    }
}

/// Iterator that yields the ancestors of the given prefix starting at the root prefix.
/// Does not include the prefix itself.
pub struct Ancestors<T: Clone + Copy + Default + Binary + Xorable> {
    target: Prefix<T>,
    current_len: usize,
}

impl<T> Iterator for Ancestors<T>
where
    T: Clone + Copy + Default + Binary + Xorable,
{
    type Item = Prefix<T>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_len < self.target.bit_count() {
            let output = self.target.ancestor(self.current_len);
            self.current_len += 1;
            Some(output)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng;
    use rand::seq::SliceRandom;

    #[test]
    fn prefix() {
        assert_eq!(parse("101").pushed(true), parse("1011"));
        assert_eq!(parse("101").pushed(false), parse("1010"));
        assert_eq!(parse("1011").popped(), parse("101"));
        assert!(parse("101").is_compatible(&parse("1010")));
        assert!(parse("1010").is_compatible(&parse("101")));
        assert!(!parse("1010").is_compatible(&parse("1011")));
        assert!(parse("101").is_neighbour(&parse("1111")));
        assert!(!parse("1010").is_neighbour(&parse("1111")));
        assert!(parse("1010").is_neighbour(&parse("10111")));
        assert!(!parse("101").is_neighbour(&parse("10111")));
        assert!(parse("101").matches(&0b1010_1100));
        assert!(!parse("1011").matches(&0b1010_1100));

        assert_eq!(parse("0101").lower_bound(), 0b0101_0000);
        assert_eq!(parse("0101").upper_bound(), 0b0101_1111);

        // Check we handle passing an excessive `bit_count` to `new()`.
        assert_eq!(Prefix::<u64>::new(64, 0).bit_count(), 64);
        assert_eq!(Prefix::<u64>::new(65, 0).bit_count(), 64);
    }

    #[test]
    fn breadth_first_order() {
        let expected = [
            parse(""),
            parse("0"),
            parse("1"),
            parse("00"),
            parse("01"),
            parse("10"),
            parse("11"),
            parse("000"),
            parse("001"),
            parse("010"),
            parse("011"),
            parse("100"),
            parse("101"),
            parse("110"),
            parse("111"),
        ];

        let mut rng = rng::new();

        for _ in 0..100 {
            let mut actual = expected;
            actual.shuffle(&mut rng);
            actual.sort_by(|lhs, rhs| lhs.cmp_breadth_first(rhs));

            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn ancestors() {
        assert_eq!(parse("").ancestors().collect::<Vec<_>>(), vec![]);

        assert_eq!(parse("0").ancestors().collect::<Vec<_>>(), vec![parse("")]);

        assert_eq!(
            parse("01").ancestors().collect::<Vec<_>>(),
            vec![parse(""), parse("0")]
        );

        assert_eq!(
            parse("011").ancestors().collect::<Vec<_>>(),
            vec![parse(""), parse("0"), parse("01")]
        );
    }

    #[test]
    fn is_sibling() {
        assert!(parse("0").is_sibling(&parse("1")));
        assert!(parse("00").is_sibling(&parse("01")));
        assert!(!parse("").is_sibling(&parse("")));
        assert!(!parse("0").is_sibling(&parse("")));
        assert!(!parse("0").is_sibling(&parse("0")));
        assert!(!parse("01").is_sibling(&parse("11")));
    }

    #[test]
    fn cmp_distance() {
        assert_eq!(
            parse("0").cmp_distance(&parse("0"), &0b0100_0000),
            Ordering::Equal
        );
        assert_eq!(
            parse("01").cmp_distance(&parse("00"), &0b0100_0000),
            Ordering::Less
        );
        assert_eq!(
            parse("01").cmp_distance(&parse("0"), &0b0100_0000),
            Ordering::Less
        );
        assert_eq!(
            parse("00").cmp_distance(&parse("0"), &0b0100_0000),
            Ordering::Greater
        );
        assert_eq!(
            parse("01").cmp_distance(&parse("00"), &0b1000_0000),
            Ordering::Equal
        );
    }

    fn parse(input: &str) -> Prefix<u8> {
        Prefix::from_str(input).unwrap()
    }
}

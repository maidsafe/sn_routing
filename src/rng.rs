// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Random number generation utilities.

pub use self::implementation::{new, MainRng};
#[cfg(test)]
pub use self::test::Seed;

// Rng implementation used in production. Uses `OsRng` for maximum cryptographic security.
#[cfg(not(test))]
mod implementation {
    pub use rand::rngs::OsRng as MainRng;

    /// Create new rng instance.
    pub fn new() -> MainRng {
        MainRng
    }
}

// Rng implementation used in tests. Uses `TestRng` to allow reproducible test results and
// to avoid opening too many file handles which could happen on some platforms if we used `OsRng`.
#[cfg(test)]
mod implementation {
    pub use super::test::TestRng as MainRng;

    /// Create new default rng instance.
    pub fn new() -> MainRng {
        MainRng::new()
    }
}

#[cfg(test)]
mod test {
    use rand::{
        distributions::{Distribution, Standard},
        CryptoRng, Rng, RngCore, SeedableRng,
    };
    use rand_xorshift::XorShiftRng;
    use std::{
        env,
        fmt::{self, Debug, Display, Formatter},
        str::FromStr,
    };

    pub const SEED_ENV_NAME: &str = "SEED";

    /// Random number generator for tests that can be seeded using environment variable.
    /// Example: `SEED="[1, 2, 3, 4]"`
    pub struct TestRng(XorShiftRng);

    impl TestRng {
        /// Create new rng with default seed. That is, try to use the seed from environment variable
        /// if provided, otherwise use random seed.
        pub fn new() -> Self {
            Self::from_seed(Seed::default())
        }
    }

    impl CryptoRng for TestRng {}

    impl Default for TestRng {
        fn default() -> Self {
            Self::new()
        }
    }

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.0.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.fill_bytes(dest)
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.0.try_fill_bytes(dest)
        }
    }

    impl SeedableRng for TestRng {
        type Seed = Seed;

        fn from_seed(seed: Seed) -> Self {
            Self(XorShiftRng::from_seed(seed.0))
        }
    }

    /// Seed for random number generators.
    #[derive(Clone, Copy, Eq, PartialEq, Hash, Debug)]
    pub struct Seed([u8; 16]);

    impl Seed {
        /// Create a seed from an Array of 4 u32.
        pub fn from_u32s(seed: [u32; 4]) -> Self {
            let mut seed_value = [0u8; 16];
            for (chunk, chunk_values) in seed_value
                .chunks_mut(4)
                .zip(seed.iter().map(|value| value.to_le_bytes()))
            {
                chunk.copy_from_slice(&chunk_values);
            }
            Seed(seed_value)
        }

        /// Try to create seed by parsing the "SEED" env variable.
        ///
        /// # Panics
        ///
        /// Panics if the env variable is not empty but invalid.
        pub fn from_env() -> Option<Self> {
            if let Ok(value) = env::var(SEED_ENV_NAME) {
                Some(value.parse().unwrap())
            } else {
                None
            }
        }

        /// Create random seed.
        pub fn random() -> Self {
            Self(rand::thread_rng().gen())
        }
    }

    impl Default for Seed {
        fn default() -> Self {
            Self::from_env().unwrap_or_else(Self::random)
        }
    }

    impl FromStr for Seed {
        type Err = ParseError;

        fn from_str(mut input: &str) -> Result<Self, Self::Err> {
            let mut seed = [0u32; 4];

            skip_whitespace(&mut input);
            skip(&mut input, '[')?;

            for (index, value) in seed.iter_mut().enumerate() {
                skip_whitespace(&mut input);

                if index > 0 {
                    skip(&mut input, ',')?;
                    skip_whitespace(&mut input);
                }

                *value = parse_u32(&mut input)?;
            }

            skip_whitespace(&mut input);
            skip(&mut input, ']')?;

            Ok(Self::from_u32s(seed))
        }
    }

    impl AsMut<[u8]> for Seed {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.0
        }
    }

    impl Distribution<Seed> for Standard {
        fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Seed {
            // Note: the `wrapping_add` trick is a workaround for what seems to be a weakness in
            // `XorShiftRng`. Without it we would sometimes end up with multiple rngs producing
            // identical values.
            // The idea is taken from: https://github.com/maidsafe/maidsafe_utilities/blob/24dfcbc6ee07a14bf64f3bc573f68cea01e06862/src/seeded_rng.rs#L92
            Seed::from_u32s([
                rng.next_u32().wrapping_add(rng.next_u32()),
                rng.next_u32().wrapping_add(rng.next_u32()),
                rng.next_u32().wrapping_add(rng.next_u32()),
                rng.next_u32().wrapping_add(rng.next_u32()),
            ])
        }
    }

    impl Display for Seed {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            use itertools::Itertools;
            use std::convert::TryInto;

            write!(
                f,
                "[{}]",
                self.0
                    .chunks(4)
                    .filter_map(|values| (*values).try_into().map(u32::from_le_bytes).ok())
                    .format(", ")
            )
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct ParseError;

    fn skip_whitespace(input: &mut &str) {
        *input = input.trim_start();
    }

    fn skip(input: &mut &str, ch: char) -> Result<(), ParseError> {
        if input.starts_with(ch) {
            *input = &input[1..];
            Ok(())
        } else {
            Err(ParseError)
        }
    }

    fn parse_u32(input: &mut &str) -> Result<u32, ParseError> {
        let mut empty = true;
        let mut output = 0;

        while let Some(digit) = input.chars().next().and_then(|ch| ch.to_digit(10)) {
            empty = false;
            output = output * 10 + digit;
            *input = &input[1..];
        }

        if empty {
            Err(ParseError)
        } else {
            Ok(output)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_seed() {
            assert_eq!("[0, 0, 0, 0]".parse(), Ok(Seed::from_u32s([0, 0, 0, 0])));
            assert_eq!("[0, 1, 2, 3]".parse(), Ok(Seed::from_u32s([0, 1, 2, 3])));
            assert_eq!(
                "[2173726344, 4077344496, 2175816672, 3385125285]".parse(),
                Ok(Seed::from_u32s([
                    2_173_726_344,
                    4_077_344_496,
                    2_175_816_672,
                    3_385_125_285
                ]))
            );
            assert_eq!("".parse(), Err::<Seed, _>(ParseError));
        }
    }
}

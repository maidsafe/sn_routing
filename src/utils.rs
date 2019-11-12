// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::xor_name::XorName;
use rand::{OsRng, Rng};
use std::{
    fmt::{self, Display, Formatter},
    ops::RangeInclusive,
    time::Duration,
};

#[cfg(any(test, feature = "mock_base"))]
use {crate::test_rng::TestRng, rand::SeedableRng};

/// Display a "number" to the given number of decimal places
pub trait DisplayDuration {
    /// Construct a formattable object
    fn display_secs(&self) -> DisplayDurObj;
}

impl DisplayDuration for Duration {
    fn display_secs(&self) -> DisplayDurObj {
        DisplayDurObj { dur: *self }
    }
}

/// Display a number to the given number of decimal places
pub struct DisplayDurObj {
    dur: Duration,
}

impl Display for DisplayDurObj {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut secs = self.dur.as_secs();
        if self.dur.subsec_nanos() >= 500_000_000 {
            secs += 1;
        }
        write!(f, "{} seconds", secs)
    }
}

/// Identified or node/client for logging purposes.
#[derive(Clone)]
pub struct LogIdent(String);

impl LogIdent {
    pub fn new<T: Display + ?Sized>(node: &T) -> Self {
        LogIdent(format!("{}", node))
    }
}

impl Display for LogIdent {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Target Xor interval
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct XorTargetInterval(pub XorName, pub XorName);

impl XorTargetInterval {
    /// Create a XorTargetInterval from the equivalent RangeInclusive
    pub fn new(range: RangeInclusive<XorName>) -> Self {
        let (start, end) = range.into_inner();
        Self(start, end)
    }

    /// check if the inclusive range contains the value
    pub fn contains(&self, value: &XorName) -> bool {
        RangeInclusive::new(self.0, self.1).contains(value)
    }
}

impl Into<RangeInclusive<XorName>> for XorTargetInterval {
    fn into(self) -> RangeInclusive<XorName> {
        RangeInclusive::new(self.0, self.1)
    }
}

// `CryptoRng` trait shim. TODO: remove this when we update rand to more recent version as it has
// its own `CryptoRng`.
pub trait CryptoRng: Rng {}

impl<'a, R: CryptoRng> CryptoRng for &'a mut R {}

impl CryptoRng for OsRng {}

// Note: `TestRng` is not really a CSPRNG (it uses xor-shift under the hood), but that is OK as
// this is used only in tests.
#[cfg(any(test, feature = "mock_base"))]
impl CryptoRng for TestRng {}

// Wrapper around `Box<dyn CryptoRng>` that itself implements `Rng` and so allows to also call
// methods that require `self: Sized`.
pub struct DynCryptoRng(Box<dyn CryptoRng>);

impl DynCryptoRng {
    pub fn new<R: CryptoRng + 'static>(rng: R) -> Self {
        Self(Box::new(rng))
    }
}

impl Rng for DynCryptoRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
}

impl CryptoRng for DynCryptoRng {}

// Note: routing uses different version of the rand crate than threshold_crypto. This is a
// compatibility adapter between the two.
pub struct RngCompat<R>(pub R);

impl<R: Rng> rand_crypto::RngCore for RngCompat<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_crypto::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<R: CryptoRng> rand_crypto::CryptoRng for RngCompat<R> {}

// Create new Rng instance. Use `TestRng` in test/mock, to allow reproducible test results and
// to avoid opening too many file handles which could happen on some platforms if we used `OsRng`.
#[cfg(any(test, feature = "mock_base"))]
pub fn new_rng() -> TestRng {
    TestRng::new()
}

// Create new Rng instance. Use `OsRng` in production for maximum cryptographic security.
#[cfg(not(any(test, feature = "mock_base")))]
pub fn new_rng() -> OsRng {
    match OsRng::new() {
        Ok(rng) => rng,
        Err(error) => panic!("Failed to create OsRng: {:?}", error),
    }
}

#[cfg(not(any(test, feature = "mock_base")))]
pub fn new_rng_from<R: Rng>(_: &mut R) -> OsRng {
    new_rng()
}

#[cfg(any(test, feature = "mock_base"))]
pub fn new_rng_from<R: Rng>(rng: &mut R) -> TestRng {
    TestRng::from_seed(rng.gen())
}

#[cfg(test)]
mod tests {
    use super::DisplayDuration;
    use std::time::Duration;

    #[test]
    fn duration_formatting() {
        assert_eq!(
            format!("{}", Duration::new(653_105, 499_000_000).display_secs()),
            "653105 seconds"
        );
        assert_eq!(
            format!("{}", Duration::new(653_105, 500_000_000).display_secs()),
            "653106 seconds"
        );
        assert_eq!(
            format!("{}", Duration::new(0, 900_000_000).display_secs()),
            "1 seconds"
        );
    }
}

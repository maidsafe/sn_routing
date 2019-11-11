// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::xor_name::XorName;
#[cfg(any(test, feature = "mock_base"))]
use maidsafe_utilities::SeededRng;
use rand::{OsRng, Rng};
use std::{
    fmt::{self, Display, Formatter},
    ops::RangeInclusive,
    time::Duration,
};

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

#[cfg(any(test, feature = "mock_base"))]
pub fn rand_index(exclusive_max: usize) -> usize {
    let mut rng = SeededRng::thread_rng();
    rng.gen::<usize>() % exclusive_max
}

#[cfg(all(not(test), not(feature = "mock_base")))]
pub fn rand_index(exclusive_max: usize) -> usize {
    ::rand::random::<usize>() % exclusive_max
}

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

impl rand_crypto::CryptoRng for RngCompat<OsRng> {}

// Note: `SeededRng` is not really a CSPRNG (it uses xor-shift under the hood), but that is OK as
// this is used only in tests.
#[cfg(any(test, feature = "mock_base"))]
impl rand_crypto::CryptoRng for RngCompat<SeededRng> {}

// Create new Rng instance. Use `SeededRng` in test/mock, to allow reproducible test results and
// to avoid opening too many file handles which could happen on some platforms if we used `OsRng`.
#[cfg(any(test, feature = "mock_base"))]
pub fn new_rng() -> SeededRng {
    SeededRng::thread_rng()
}

// Create new Rng instance. Use `OsRng` in production for maximum cryptographic security.
#[cfg(not(any(test, feature = "mock_base")))]
pub fn new_rng() -> OsRng {
    match OsRng::new() {
        Ok(rng) => rng,
        Err(error) => panic!("Failed to create OsRng: {:?}", error),
    }
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

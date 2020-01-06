// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::xor_space::XorName;
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
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
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
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
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

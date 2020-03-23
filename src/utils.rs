// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::{
    fmt::{self, Display, Formatter},
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

// Test utils

/// If the iterator yields exactly one element, returns it. Otherwise panics.
// TODO: remove this allow(unused)
#[allow(unused)]
#[cfg(all(test, feature = "mock"))]
pub fn exactly_one<I>(input: I) -> I::Item
where
    I: IntoIterator,
{
    let mut input = input.into_iter();
    let first = match input.next() {
        Some(first) => first,
        None => panic!("exactly one element expected, got none"),
    };
    if input.next().is_some() {
        panic!("exactly one element expected, got more");
    }
    first
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

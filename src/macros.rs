// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// This macro will panic with the given message if compiled with "mock", otherwise it
/// will simply log the message at the requested level.
///
/// Example usage:
/// `log_or_panic!(log::Level::Warn, "{:?} Bad value: {}", self, value);`
#[macro_export]
macro_rules! log_or_panic {
    ($log_level:expr, $($arg:tt)*) => {
        if cfg!(feature = "mock") && !::std::thread::panicking() {
            $crate::log_utils::with_ident(|ident| {
                panic!("{}{}", ident, format_args!($($arg)*));
            })
        } else {
            log!($log_level, $($arg)*);
        }
    };
}

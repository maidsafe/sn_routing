// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

/// This macro will panic with the given message if compiled with "use-mock-crust", otherwise it
/// will simply log the message at the requested level.
///
/// Example usage:
/// `log_or_panic!(Level::Warn, "{:?} Bad value: {}", self, value);`
#[macro_export]
macro_rules! log_or_panic {
    ($log_level:expr, $($arg:tt)*) => {
        if cfg!(feature = "use-mock-crust") && !::std::thread::panicking() {
            panic!($($arg)*);
        } else {
            log!($log_level, $($arg)*);
        }
    };
}

// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

/// A replacement for calling `unwrap()` on a `Result`.
///
/// This macro is intended to be used in all cases where we `unwrap` a `Result` to deliberately
/// ignoring the result and logging in case of error - eg., in test-cases. This macro will
/// decorate the failure for easy viewing.
///
/// # Examples
///
/// ```
/// let some_result: Result<String, u32> = Ok("Hello".to_string());
/// ignore_result!(some_result);
/// ```
#[macro_export]
macro_rules! ignore_result {
    ($result:expr) => {
        let _ = $result.unwrap_or_else(|error| {
            let message =
                "Result evaluated to Err: ".to_string() + &format!("{:?}", error)[..];
            let decorator_length = ::std::cmp::min(message.len() + 2, 100);
            let decorator = (0..decorator_length).map(|_| "=").collect::<String>();
            warn!("\n\n {}\n| {} |\n {}\n\n", decorator, message, decorator)
        });
    }
}

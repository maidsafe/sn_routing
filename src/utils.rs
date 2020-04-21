// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// Test utils

/// If the iterator yields exactly one element, returns it. Otherwise panics.
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

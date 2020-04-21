// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use itertools::Itertools;
use std::{
    fmt::{self, Debug, Formatter},
    iter, mem,
};

/// Vec-like container that is guaranteed to contain at least one element.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct NonEmptyList<T> {
    head: Vec<T>,
    tail: T,
}

impl<T> NonEmptyList<T> {
    pub fn new(first: T) -> Self {
        Self {
            head: Vec::new(),
            tail: first,
        }
    }

    pub fn push(&mut self, item: T) {
        self.head.push(mem::replace(&mut self.tail, item))
    }

    pub fn len(&self) -> usize {
        self.head.len() + 1
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> + DoubleEndedIterator {
        self.head.iter().chain(iter::once(&self.tail))
    }

    pub fn last(&self) -> &T {
        &self.tail
    }
}

impl<T> Debug for NonEmptyList<T>
where
    T: Debug,
{
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "[{:?}]", self.iter().format(", "))
    }
}

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

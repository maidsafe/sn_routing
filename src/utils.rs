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

use kademlia_routing_table::group_size;
use maidsafe_utilities::serialisation::deserialise;
use routing::RefreshAccumulatorValue;
use std::collections::HashMap;
use types::{MergedValue, Refreshable};

static HANDLE_VERSION: ::std::sync::Once = ::std::sync::ONCE_INIT;

/// Returns the median (rounded down to the nearest integral value) of `values` which can be
/// unsorted.  If `values` is empty, returns `0`.
pub fn median(mut values: Vec<u64>) -> u64 {
    match values.len() {
        0 => 0u64,
        1 => values[0],
        len if len % 2 == 0 => {
            values.sort();
            let lower_value = values[(len / 2) - 1];
            let upper_value = values[len / 2];
            (lower_value + upper_value) / 2
        }
        len => {
            values.sort();
            values[len / 2]
        }
    }
}

// TODO - this function should be removed in favour of using the dynamic quorum size from Routing
pub fn quorum_size() -> usize {
    group_size() / 2
}

pub fn merge<T>(values: Vec<RefreshAccumulatorValue>, quorum_size: usize) -> Option<MergedValue<T>>
    where T: for<'a> Refreshable + 'static {
    // Turn the `values` into a `HashMap<src_name, Vec<contents>>`.  Normally all values will have
    // the same `src_name` and so this HashMap len should be 1, but this lets us filter out any
    // stray entries which have a different `src_name` to all others.
    let names_and_contents = values.into_iter().fold(HashMap::<_, Vec<_>>::new(), |mut accumulator, value| {
        accumulator.entry(value.src_name).or_insert(vec![]).push(value.content);
        accumulator
    });

    // If any entry in the HashMap has at least quorum values in its corresponding vector of
    // contents, use that to try and merge.
    if let Some(quorum_entry) = names_and_contents.iter().find(|elt| elt.1.len() >= quorum_size) {
        // Convert the vector of serialised contents to a vector of parsed entries
        let parsed_entries = quorum_entry.1.iter().filter_map(|elt| deserialise(elt).ok()).collect::<Vec<_>>();
        if parsed_entries.len() >= quorum_size {
            return T::merge(*quorum_entry.0, parsed_entries, quorum_size);
        }
    }
    None
}

pub fn handle_version() {
    HANDLE_VERSION.call_once(|| {
        let name = ::crust::exe_file_stem().unwrap_or(::std::path::Path::new("").to_path_buf());
        let name_and_version = format!("{} v{}", name.to_string_lossy(), env!("CARGO_PKG_VERSION"));
        if ::std::env::args().any(|arg| arg == "--version") {
            println!("{}", name_and_version);
            ::std::process::exit(0);
        }
        let message = String::from("Running ") + &name_and_version;
        let underline = String::from_utf8(vec!['=' as u8; message.len()]).unwrap();
        info!("\n\n{}\n{}", message, underline);
    });
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::random;

    pub fn generate_random_vec_u8(size: usize) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::with_capacity(size);
        for _ in 0..size {
            vec.push(random::<u8>());
        }
        vec
    }

    #[test]
    fn get_median() {
        assert_eq!(0, median(vec![0u64; 0]));
        assert_eq!(9, median(vec![9]));
        assert_eq!(0, median(vec![1, 0]));
        assert_eq!(1, median(vec![1, 0, 9]));
        assert_eq!(5, median(vec![1, 0, 9, 10]));
        assert_eq!(5, median(vec![20, 1, 0, 9]));
        assert_eq!(5, median(vec![20, 1, 0, 10]));
        assert_eq!(6, median(vec![20, 1, 0, 11]));
    }
}

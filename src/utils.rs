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

use xor_name::XorName;

/// Indicates a "handle_xxx" function of a persona has dealt with the request (i.e. it was for that
/// persona).  It doesn't indicate success or failure - only that the request has been handled.
pub const HANDLED: Option<()> = Some(());

/// Indicates a "handle_xxx" function of a persona has NOT dealt with the request (i.e. it was not
/// for that persona).
pub const NOT_HANDLED: Option<()> = None;

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

pub fn merge<T>(from_group: XorName, payloads: Vec<Vec<u8>>) -> Option<T>
    where T: for<'a> ::types::Refreshable + 'static {
    let mut transfer_entries = Vec::<T>::new();
    for it in payloads.iter() {
        let mut decoder = ::cbor::Decoder::from_bytes(&it[..]);
        if let Some(parsed_entry) = decoder.decode().next().and_then(|result| result.ok()) {
            transfer_entries.push(parsed_entry);
        }
    }
    T::merge(from_group, transfer_entries).and_then(|result| {
        let mut decoder = ::cbor::Decoder::from_bytes(&result.serialised_contents()[..]);
        if let Some(parsed_entry) = decoder.decode().next().and_then(|result| result.ok()) {
            let parsed: T = parsed_entry;
            Some(parsed)
        } else {
            None
        }
    })
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
pub fn random_name() -> XorName {
    // TODO - once Routing provides either a compile-time value for `NameType`'s length or exposes
    // `NameType::generate_random()` this should be used here.  Issue reported at
    // https://github.com/maidsafe/routing/issues/674
    XorName(::routing::types::slice_as_u8_64_array(
        &*::routing::types::generate_random_vec_u8(::routing::NAME_TYPE_LEN)))
}

#[cfg(test)]
mod test {
    use super::*;

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

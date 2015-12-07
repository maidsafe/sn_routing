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


#[derive(PartialEq, Eq, Clone, Debug)]
/// DataCacheOptions.
pub struct DataCacheOptions {
    cache_plain_data: bool,
    cache_structured_data: bool,
    cache_immutable_data: bool,
}

impl DataCacheOptions {
    /// Constructor
    pub fn new() -> DataCacheOptions {
        DataCacheOptions {
            cache_plain_data: false,
            cache_structured_data: false,
            cache_immutable_data: false,
        }
    }
    /// Construct with caching off.
    pub fn no_caching() -> DataCacheOptions {
        DataCacheOptions {
            cache_plain_data: false,
            cache_structured_data: false,
            cache_immutable_data: false,
        }
    }

    /// Construct with caching optionally set.
    pub fn with_caching(cache_plain_data: bool,
                        cache_structured_data: bool,
                        cache_immutable_data: bool)
                        -> DataCacheOptions {
        DataCacheOptions {
            cache_plain_data: cache_plain_data,
            cache_structured_data: cache_structured_data,
            cache_immutable_data: cache_immutable_data,
        }
    }

    /// Enable or disable Data caching.
    pub fn set_cache_options(&mut self, cache_options: DataCacheOptions) {
        self.cache_plain_data = cache_options.cache_plain_data;
        self.cache_structured_data = cache_options.cache_structured_data;
        self.cache_immutable_data = cache_options.cache_immutable_data;
    }

    /// Return true if any caching option is set otherwise false.
    pub fn caching_enabled(&self) -> bool {
        if self.cache_plain_data || self.cache_structured_data || self.cache_immutable_data {
            return true;
        }
        false
    }

    /// Return PlainData caching option.
    pub fn plain_data_caching_enabled(&self) -> bool {
        self.cache_plain_data
    }

    /// Return StructuredData caching option.
    pub fn structured_data_caching_enabled(&self) -> bool {
        self.cache_structured_data
    }

    /// Return ImmutableData caching option.
    pub fn immutable_data_caching_enabled(&self) -> bool {
        self.cache_immutable_data
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_conversions() {
        let bytes = ::types::generate_random_vec_u8(64);
        let array = ::types::slice_as_u8_64_array(&bytes[..]);

        assert_eq!(64, array.len());
        assert_eq!(&bytes[..], &array[..]);

        let bytes = ::types::generate_random_vec_u8(32);
        let array = ::types::slice_as_u8_32_array(&bytes[..]);

        assert_eq!(32, array.len());
        assert_eq!(&bytes[..], &array[..]);
    }

    #[test]
    fn cache_options_no_caching() {
        let cache_options = DataCacheOptions::no_caching();

        assert!(!cache_options.plain_data_caching_enabled());
        assert!(!cache_options.structured_data_caching_enabled());
        assert!(!cache_options.immutable_data_caching_enabled());
        assert!(!cache_options.caching_enabled());
    }

    #[test]
    fn cache_options_with_caching() {
        let cache_options = DataCacheOptions::with_caching(true, true, true);

        assert!(cache_options.plain_data_caching_enabled());
        assert!(cache_options.structured_data_caching_enabled());
        assert!(cache_options.immutable_data_caching_enabled());
        assert!(cache_options.caching_enabled());
    }

    #[test]
    fn cache_options_set_options() {
        let mut cache_options = DataCacheOptions::with_caching(false, false, false);

        assert!(!cache_options.plain_data_caching_enabled());
        assert!(!cache_options.structured_data_caching_enabled());
        assert!(!cache_options.immutable_data_caching_enabled());
        assert!(!cache_options.caching_enabled());

        cache_options.set_cache_options(DataCacheOptions::with_caching(true, false, false));

        assert!(cache_options.plain_data_caching_enabled());
        assert!(!cache_options.structured_data_caching_enabled());
        assert!(!cache_options.immutable_data_caching_enabled());
        assert!(cache_options.caching_enabled());

        cache_options.set_cache_options(DataCacheOptions::with_caching(false, true, false));

        assert!(!cache_options.plain_data_caching_enabled());
        assert!(cache_options.structured_data_caching_enabled());
        assert!(!cache_options.immutable_data_caching_enabled());
        assert!(cache_options.caching_enabled());

        cache_options.set_cache_options(DataCacheOptions::with_caching(false, false, true));

        assert!(!cache_options.plain_data_caching_enabled());
        assert!(!cache_options.structured_data_caching_enabled());
        assert!(cache_options.immutable_data_caching_enabled());
        assert!(cache_options.caching_enabled());
    }

    #[test]
    fn address() {
        use rand;

        let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let client_address = ::types::Address::Client(sign_keys.0);

        match client_address {
            ::types::Address::Client(public_sign_key) => assert_eq!(sign_keys.0, public_sign_key),
            _ => panic!("Unexpected error."),
        }

        let name: ::XorName = rand::random();
        let node_address = ::types::Address::Node(name);

        match node_address {
            ::types::Address::Node(node_name) => assert_eq!(name, node_name),
            _ => panic!("Unexpected error."),
        }
    }
}

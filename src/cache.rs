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

use lru_time_cache::LruCache;
use messages::{ExternalRequest, ExternalResponse};
use data::{Data, DataRequest};
use NameType;
use time::Duration;

pub struct CacheOptions {
	cache_plain_data: bool,
	cache_structured_data: bool,
	cache_immutable_data: bool,
	duration: Option<Duration>,
	capacity: Option<usize>,
}

impl CacheOptions {

    /// Construct with caching off.
    pub fn new() -> CacheOptions {
        CacheOptions {
            cache_plain_data: false,
            cache_structured_data: false,
            cache_immutable_data: false,
            duration: None,
            capacity: None,
        }
    }
}

pub struct DataCache {
    cache: LruCache<NameType, Data>,
    cache_options: CacheOptions,
}

impl DataCache {

	/// Constructor accepting CacheOptions for the cache type and data types that are cacheable.
	pub fn new(cache_options: CacheOptions) -> DataCache {
		DataCache {
			cache: DataCache::init_cache(
                    cache_options.duration.clone(), cache_options.capacity.clone()),
            cache_options: cache_options,
		}
	}

	/// Insert a NameType/Data pair into the cache if cache_options accepts caching for the Data
	/// type. Ignores optional return from LruCache insert.
	pub fn insert(&mut self, response: ExternalResponse) {
        match response {
            ExternalResponse::Get(data, _, _) => {
                match data {
                	Data::PlainData(ref plain_data) => {
                        if self.cache_options.cache_plain_data {
                        	self.cache.insert(data.name(), data.clone());
                        }
                    }
                    Data::StructuredData(ref structured_data) => {
                        if self.cache_options.cache_structured_data {
                        	self.cache.insert(data.name(), data.clone());
                        }
                    }
                    Data::ImmutableData(ref immutable_data) => {
                    	if self.cache_options.cache_immutable_data {
                        	self.cache.insert(data.name(), data.clone());
                        }
                    }
                }
            }
            _ => {}
        };
    }

    /// Optionally retrieve a Data value from cache.
    pub fn get(&mut self, request: ExternalRequest) -> Option<&Data> {
        match request {
            ExternalRequest::Get(data_request, _) => {
                match data_request {
                	DataRequest::PlainData(data_name) => {
                        if self.cache_options.cache_plain_data {
                        	return self.cache.get(&data_name)
                        }
                        return None;
                    }
                    DataRequest::StructuredData(data_name, _) => {
                        if self.cache_options.cache_structured_data {
                            return self.cache.get(&data_name);
                        }
                        return None;
                    }
                    DataRequest::ImmutableData(data_name, _) => {
                        if self.cache_options.cache_immutable_data {
							return self.cache.get(&data_name);
                        }
                        return None;
                    }
                }
            }
            _ => None,
        }
    }

    /// Returns true if a Data entry exists for the specified name.
    pub fn contains_key(&self, name: &NameType) -> bool {
        self.cache.contains_key(name)
    }

	fn init_cache(time_to_live: Option<Duration>, capacity: Option<usize>) 
			-> LruCache<NameType, Data> {
	    match (time_to_live, capacity) {
	        (Some(time_to_live), Some(capacity)) => {
	            LruCache::<NameType, Data>::with_expiry_duration_and_capacity(time_to_live, capacity)
	        }
	        (Some(time_to_live), None) => {
	            LruCache::<NameType, Data>::with_expiry_duration(time_to_live)
	        }
	        (None, Some(capacity)) => {
	            LruCache::<NameType, Data>::with_capacity(capacity)
	        }
	        (None, None) => {
	           LruCache::<NameType, Data>::with_capacity(0usize)
	        }
	    }
	}
}

#[cfg(test)]
mod test {
}
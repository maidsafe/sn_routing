// Copyright 2015 MaidSafe.net limited.
//
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

use NameType;
use data_cache_options::DataCacheOptions;
use data::{Data, DataRequest};

use messages::{RoutingMessage, Content, ExternalRequest, ExternalResponse};

// use error::{RoutingError, InterfaceError};


/// Routing Node
pub struct DataCache {
    cache_options: DataCacheOptions,
    data_cache: Option<LruCache<NameType, Data>>,
}

impl DataCache {
    /// constructor
    pub fn new() ->DataCache {
        DataCache {
        cache_options : DataCacheOptions::new(),
        data_cache : None    
        }   
    }
    /// Set cache via the DataCacheOptions struct
    pub fn set_cache_options(&mut self, cache_options: DataCacheOptions) {
        self.cache_options.set_cache_options(cache_options);
        if self.cache_options.caching_enabled() {
            match self.data_cache {
                None => self.data_cache =
                    Some(LruCache::<NameType, Data>::with_expiry_duration(
                            ::time::Duration::minutes(10))),
                Some(_) => {}
            }
        } else {
            self.data_cache = None;
        }
    }

    /// method to cache data in a put method (we will always insert the set data types)
    pub fn handle_cache_put(&mut self, message: &RoutingMessage) {
        match self.data_cache {
            Some(ref mut data_cache) => {
                if let Content::ExternalResponse(response) = message.content.clone() {
                    if let ExternalResponse::Get(data, _, _) = response {
                        match data {
                            Data::PlainData(_) => {
                                if self.cache_options.plain_data_caching_enabled() {
                                    debug!("Caching PlainData {:?}", data.name());
                                    let _ = data_cache.insert(data.name(), data.clone());
                                }
                            }
                            Data::StructuredData(_) => {
                                if self.cache_options.structured_data_caching_enabled() {
                                    debug!("Caching StructuredData {:?}", data.name());
                                    let _ = data_cache.insert(data.name(), data.clone());
                                }
                            }
                            Data::ImmutableData(_) => {
                                if self.cache_options.immutable_data_caching_enabled() {
                                    debug!("Caching ImmutableData {:?}", data.name());
                                    // TODO verify data
                                    let _ = data_cache.insert(data.name(), data.clone());
                                }
                            }
                        }
                    }


                }
            }
            None => {}
        }

    }
  
    /// if we have cached the data then return it here.
    pub fn handle_cache_get(&mut self, message: &RoutingMessage) -> Option<Content> {
        match self.data_cache {
            Some(ref mut data_cache) => {
                match message.content.clone() {
                    Content::ExternalRequest(request) => {
                        match request {
                            ExternalRequest::Get(data_request, _) => {
                                match data_request {
                                    DataRequest::PlainData(data_name) => {
                                        if self.cache_options.plain_data_caching_enabled() {
                                            match data_cache.get(&data_name) {
                                                Some(data) => {
                                                    debug!("Got PlainData {:?} from cache",
                                                           data_name);
                                                    let response =
                                                        ExternalResponse::Get(data.clone(),
                                                                              data_request,
                                                                              None);
                                                    return Some(Content::ExternalResponse(response));
                                                }
                                                None => return None,
                                            }
                                        }
                                        None
                                    }
                                    DataRequest::StructuredData(_, _) => {
                                        if self.cache_options.structured_data_caching_enabled() {
                                            if let Some(data) = data_cache.get(&data_request.name()) {
                                                    debug!("Got StructuredData {:?} from \
                                                           cache", data_request.name());
                                                    let response =
                                                        ExternalResponse::Get(data.clone(),
                                                                              data_request,
                                                                              None);
                                                    return Some(Content::ExternalResponse(response));
                                            }
                                        }
                                        None
                                    }
                                    DataRequest::ImmutableData(data_name, _) => {
                                        if self.cache_options.immutable_data_caching_enabled() {
                                            match data_cache.get(&data_name) {
                                                Some(data) => {
                                                    debug!("Got ImmutableData {:?} from \
                                                           cache", data_name);
                                                    let response =
                                                        ExternalResponse::Get(data.clone(),
                                                                              data_request,
                                                                              None);
                                                    return Some(Content::ExternalResponse(response));
                                                }
                                                None => return None,
                                            }
                                        }
                                        None
                                    }
                                }
                            }
                            _ => None,
                        }

                    }
                    _ => None,
                }

            }
            None => None,
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn not_tested() {
    }

}

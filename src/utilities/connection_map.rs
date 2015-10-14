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

/// validates that the type can be validated with a public id
pub trait Identifiable {
    /// should return true if the public id is the validator for the type
    fn valid_public_id(&self, public_id: ::public_id::PublicId) -> bool;
}

/// ConnectionMap maintains a double directory to look up a connection or a name V
#[allow(unused)]
pub struct ConnectionMap<V> {
    connection_map: ::std::collections::BTreeMap<V, ::public_id::PublicId>,
    lookup_map: ::std::collections::HashMap<::crust::Connection, V>,
}

#[allow(unused)]
impl<V> ConnectionMap<V> where V: PartialOrd + Ord + Clone + Identifiable {
    /// Create a new connection map
    pub fn new() -> ConnectionMap<V> {
        ConnectionMap {
            connection_map: ::std::collections::BTreeMap::new(),
            lookup_map: ::std::collections::HashMap::new(),
        }
    }


    pub fn add_peer(&mut self, connection: ::crust::Connection, identifier: V,
        public_id: ::public_id::PublicId) -> bool {

        false
    }
}

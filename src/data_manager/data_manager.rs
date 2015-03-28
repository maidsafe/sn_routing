// Copyright 2015 MaidSafe.net limited
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe
// Software.

#![allow(dead_code)]

extern crate routing;

mod database;

use self::routing::types;

type CloseGroupDifference = self::routing::types::CloseGroupDifference;
type Address = self::routing::types::Address;

pub struct DataManager {
  db_ : database::DataManagerDatabase
  // close_group_ : CloseGroupDifference
}

impl DataManager {
  pub fn new() -> DataManager {
    DataManager { db_: database::DataManagerDatabase::new() }
                  // close_group_: CloseGroupDifference(Vec::<Address>::new(), Vec::<Address>::new()) }
  }

  pub fn handle_get(&mut self, name : &routing::types::Identity) ->Result<routing::Action, routing::RoutingError> {
	  let result = self.db_.get_pmid_nodes(name);
	  if result.len() == 0 {
	    return Err(routing::RoutingError::NoData);
	  }
      
	  let mut dest_pmids : Vec<routing::DhtIdentity> = Vec::new();
	  for pmid in result.iter() {
        dest_pmids.push(routing::DhtIdentity { id: types::vector_as_u8_64_array(pmid.clone()) });
	  }
	  Ok(routing::Action::SendOn(dest_pmids))
  }
}
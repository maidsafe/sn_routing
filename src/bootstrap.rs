/*  Copyright 2015 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */


extern crate maidsafe_types;
extern crate sodiumoxide;
extern crate time;

use common_bits::*;
use sodiumoxide::crypto;
use std::cmp;
use std::net;
use std::time::duration::Duration;

type BootStrapContacts = Vec<Contact>;

struct Contact {
  id: maidsafe_types::NameType,
  endpoint_pair: (net::SocketAddrV4, net::SocketAddrV4),
  public_key: crypto::asymmetricbox::PublicKey,
}

impl Clone for Contact {
  fn clone(&self) -> Contact {
    Contact {
      id: self.id.clone(),
      endpoint_pair: (self.endpoint_pair.0.clone(), self.endpoint_pair.1.clone()),
      public_key: self.public_key.clone(),
    }
  }
}

struct BootStrapHandler {
  database: Vec<String>,
  last_updated: time::Tm,
}

impl BootStrapHandler {
  pub fn new() -> BootStrapHandler {
    BootStrapHandler {
      database: vec!["hello".to_string(); 32],
      last_updated: time::now(),
    }
  }

  pub fn get_max_list_size() -> usize {
    1500
  }

  pub fn get_update_duration() -> Duration {
    Duration::hours(4)
  }

  pub fn add_bootstrap_contacts(&mut self, contacts: BootStrapContacts) {
    self.insert_bootstrap_contacts(contacts);

    if time::now() + BootStrapHandler::get_update_duration() > self.last_updated {
      self.check_bootstrap_contacts();
    }
  }

  pub fn read_bootstrap_contacts(&self) -> BootStrapContacts {
    BootStrapContacts::new()
  }

  pub fn replace_bootstrap_contacts(&mut self, contacts: BootStrapContacts) {
    self.remove_bootstrap_contacts();
    self.insert_bootstrap_contacts(contacts);
  }

  pub fn out_of_date(&self) -> bool {
    time::now() + BootStrapHandler::get_update_duration() > self.last_updated
  }

  pub fn reset_timer(&mut self) {
    self.last_updated = time::now();
  }

  fn insert_bootstrap_contacts(&mut self, contacts: BootStrapContacts) {

  }

  fn remove_bootstrap_contacts(&mut self) {
    ;
  }

  fn check_bootstrap_contacts(&self) {
    ;
  }
}

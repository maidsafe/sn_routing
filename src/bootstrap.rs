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
extern crate sqlite3;
extern crate cbor;

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use sodiumoxide::crypto;
use std::net;
use std::time::duration::Duration;
use sqlite3::*;

type BootStrapContacts = Vec<Contact>;

static BOOTSTRAP_FILE_NAME: &'static str = "bootstrap.cache";
static MAX_LIST_SIZE: usize = 1500;

fn array_to_vec(arr: &[u8]) -> Vec<u8> {
	let mut vector: Vec<u8> = Vec::new();
	vector.push_all(&arr);
	vector
}

// TODO Move Contact to maidsafe_types
struct Contact {
  id: maidsafe_types::NameType,
  endpoint_pair: (net::SocketAddrV4, net::SocketAddrV4),
  public_key: crypto::asymmetricbox::PublicKey,
}

impl Contact {	
	pub fn new(id: maidsafe_types::NameType, endpoint_pair: (net::SocketAddrV4, net::SocketAddrV4), public_key: crypto::asymmetricbox::PublicKey) -> Contact {
		Contact {
			id: id,
			endpoint_pair: endpoint_pair,
			public_key: public_key
		}
	}
}

impl Encodable for Contact {
	fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
		let addr_0_ip = array_to_vec(&self.endpoint_pair.0.ip().octets());
		let addr_0_port = &self.endpoint_pair.0.port();
		let addr_1_ip = array_to_vec(&self.endpoint_pair.1.ip().octets());
    let addr_1_port = &self.endpoint_pair.1.port();
    let public_key = array_to_vec(&self.public_key.0);
    CborTagEncode::new(5483_000, &(&self.id, addr_0_ip, addr_0_port, addr_1_ip, addr_1_port, public_key)).encode(e)
  }
}

fn vector_as_u8_4_array(vector: Vec<u8>) -> [u8;4] {
  let mut arr = [0u8;4];
  for i in (0..4) {
    arr[i] = vector[i];
  }
  arr
}

impl Decodable for Contact {
	fn decode<D: Decoder>(d: &mut D)->Result<Contact, D::Error> {
    try!(d.read_u64());
    
    let (id_, addr_0_ip_, addr_0_port, addr_1_ip_, addr_1_port, public_key) = try!(Decodable::decode(d));
    let id = maidsafe_types::helper::vector_as_u8_64_array(id_);
    let addr_0_ip: [u8;4] = vector_as_u8_4_array(addr_0_ip_);
    let addr_1_ip: [u8;4] = vector_as_u8_4_array(addr_1_ip_);
    let addr_0 = net::SocketAddrV4::new(net::Ipv4Addr::new(addr_0_ip[0], addr_0_ip[1], addr_0_ip[2], addr_0_ip[3]), addr_0_port);
    let addr_1 = net::SocketAddrV4::new(net::Ipv4Addr::new(addr_1_ip[0], addr_1_ip[1], addr_1_ip[2], addr_1_ip[3]), addr_1_port);
    let pub_ = crypto::asymmetricbox::PublicKey(maidsafe_types::helper::vector_as_u8_32_array(public_key));
    
    Ok(Contact::new(maidsafe_types::NameType(id), (addr_0, addr_1), pub_))
  }
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
  database: Database,
  last_updated: time::Tm,
}

impl BootStrapHandler {
  pub fn new() -> BootStrapHandler {
  	// TODO instead of in-memory pass the file path
  	let mut db = open(":memory:").unwrap();
  	db.exec("CREATE TABLE IF NOT EXISTS BOOTSTRAP_CONTACTS(CONTACT BLOB PRIMARY KEY NOT NULL)").unwrap();  	
    BootStrapHandler {
      database: db,
      last_updated: time::now(),
    }
  }

  pub fn get_max_list_size() -> usize {
    MAX_LIST_SIZE
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
    if contacts.is_empty() {
    	return;
    }    
  }

  fn remove_bootstrap_contacts(&mut self) {
    ;
  }

  fn check_bootstrap_contacts(&self) {
    ;
  }
}

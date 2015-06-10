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
//! usage example (using default methods of connecting to the network):
//!      starting first node : simple_key_value_store --first
//!      starting later on nodes : simple_key_value_store --node
//!      starting a client : simple_key_value_store
//! usage example (using explicit list of peer endpoints and overriding default methods to connect to the network):
//!      starting first node : simple_key_value_store --first
//!      (127.0.0.0:7364 to be the socket address the first node listening on)
//!      starting later on nodes : simple_key_value_store --node 127.0.0.0:7364
//!      starting a client : simple_key_value_store 127.0.0.0:7364

extern crate cbor;
extern crate docopt;
extern crate rand;
extern crate rustc_serialize;
extern crate sodiumoxide;

extern crate crust;
extern crate routing;

use std::fmt;
use std::io;
use std::net::{SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::spawn;

use cbor::CborTagEncode;
use docopt::Docopt;
use rand::random;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use sodiumoxide::crypto;

use crust::Endpoint;
use routing::node_interface::*;
use routing::routing_client::{RoutingClient};
use routing::routing_node::{RoutingNode};
use routing::sendable::Sendable;
use routing::types;
use routing::authority::Authority;
use routing::{NameType};
use routing::types::MessageAction;
use routing::error::{ResponseError, InterfaceError};

// ==========================   Program Options   =================================
static USAGE: &'static str = "
Usage:
  simple_key_value_store [--node] [<peer>...]
  simple_key_value_store --first
  simple_key_value_store (-h | --help)

  Running with '--node' or without '--first' requires an existing network to connect to.
  '--first' must be passed as parameter to start the first node in the network.
  Running with '--node' or '--first' starts a passive node that reacts on received requests.
  Running without '--node' or '--first' starts an interactive node that can initiate requests to the network.

  If no arguments are passed (as peer), this will try to connect to an existing network
  using Crust's discovery protocol.  If this is unsuccessful, you can provide
  a list of known endpoints (other running instances of this example) and the node
  will try to connect to one of these in order to connect to the network.

Options:
  -h --help           Show this screen.
  --first             Node runs as the first passive node in the network.
  --node              Node runs as the non-first passive node in the network.
";

// ==========================   Helper Function   =================================
pub fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..size {
        vec.push(random::<u8>());
    }
    vec
}


// ==========================   Test Data Structure   =================================
#[derive(Clone)]
struct TestData {
    key: Vec<u8>,
    value: Vec<u8>
}

impl TestData {
    fn new(key: Vec<u8>, value: Vec<u8>) -> TestData {
        TestData { key: key, value: value }
    }

    pub fn get_name_from_key(key: &Vec<u8>) -> NameType {
        let digest = crypto::hash::sha512::hash(key);
        NameType(digest.0)
    }

    pub fn get_key(&self) -> Vec<u8> { self.key.clone() }

    pub fn get_value(&self) -> Vec<u8> { self.value.clone() }
}

impl Sendable for TestData {
    fn name(&self) -> NameType {
        let digest = crypto::hash::sha512::hash(&self.key);
        NameType(digest.0)
    }

    fn type_tag(&self)->u64 { 201 }

    fn serialised_contents(&self)->Vec<u8> {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&self]).unwrap();
        e.into_bytes()
    }

    fn refresh(&self)->bool {
        false
    }

    fn merge(&self, _responses: Vec<Box<Sendable>>) -> Option<Box<Sendable>> { None }
}

impl Encodable for TestData {
    fn encode<E: Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        CborTagEncode::new(5483_002, &(&self.key, &self.value)).encode(e)
    }
}

impl Decodable for TestData {
    fn decode<D: Decoder>(d: &mut D) -> Result<TestData, D::Error> {
        try!(d.read_u64());
        let (key, value) = try!(Decodable::decode(d));
        let test_data = TestData { key: key, value: value };
        Ok(test_data)
    }
}

impl PartialEq for TestData {
    fn eq(&self, other: &TestData) -> bool {
        self.key == other.key && self.value == other.value
    }
}

impl fmt::Debug for TestData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let key_string = std::string::String::from_utf8(self.get_key()).unwrap();
        let value_string = std::string::String::from_utf8(self.get_value()).unwrap();
        write!(f, "TestData( key: {:?} , value: {:?} )", key_string, value_string)
    }
}

// ==========================   Implement traits   =================================
struct Stats {
    pub stats : Vec<(u32, TestData)>
}

struct TestClient {
    pub stats: Arc<Mutex<Stats>>
}

impl routing::client_interface::Interface for TestClient {
    fn handle_get_response(&mut self, _: types::MessageId, response: Result<Vec<u8>, ResponseError>) {
        if response.is_ok() {
            let mut d = cbor::Decoder::from_bytes(response.unwrap());
            let response_data: TestData = d.decode().next().unwrap().unwrap();
            println!("testing client received get_response with testdata {:?}", response_data);
        } else {
            println!("testing client received error get_response");
        }
    }
    fn handle_put_response(&mut self, _: types::MessageId, response: Result<Vec<u8>, ResponseError>) {
        if response.is_ok() {
            println!("testing client shall not receive a success put_response");
        } else {
            println!("testing client received error put_response");
        }
    }
}

struct TestNode {
    stats: Arc<Mutex<Stats>>
}

impl TestNode {
    pub fn new() -> TestNode {
        TestNode { stats: Arc::new(Mutex::new(Stats {stats: Vec::<(u32, TestData)>::new()})) }
    }
}

impl Interface for TestNode {
    fn handle_get(&mut self, _type_id: u64, name: NameType, _our_authority: Authority,
                  _from_authority: Authority, from_address: NameType)
                   -> Result<MessageAction, InterfaceError> {
        println!("testing node handle get request from {} of chunk {}", from_address, name);
        let stats = self.stats.clone();
        let stats_value = stats.lock().unwrap();
        for data in stats_value.stats.iter().filter(|data| data.1.name() == name) {
            return Ok(MessageAction::Reply(data.1.serialised_contents().clone()));
        }
        Err(InterfaceError::Response(ResponseError::NoData))
    }
    fn handle_put(&mut self, our_authority: Authority, _from_authority: Authority,
                from_address: NameType, _dest_address: types::DestinationAddress,
                data_in: Vec<u8>) -> Result<MessageAction, InterfaceError> {
        if our_authority != Authority::NaeManager {
            if our_authority == Authority::ClientManager {
                let mut d = cbor::Decoder::from_bytes(data_in);
                let in_coming_data: TestData = d.decode().next().unwrap().unwrap();
                println!("ClientManager forwarding data to DataManager around {:?} ", in_coming_data.name());
                return Ok(MessageAction::SendOn(vec![in_coming_data.name()]));
            }
            println!("returning as our_authority is {:?} which is not supposed to handle_put", our_authority);
            return Err(InterfaceError::Abort);
        }
        let stats = self.stats.clone();
        let mut stats_value = stats.lock().unwrap();
        let mut d = cbor::Decoder::from_bytes(data_in);
        let in_coming_data: TestData = d.decode().next().unwrap().unwrap();
        println!("testing node handle put request from {} of data {:?}", from_address, in_coming_data);
        for data in stats_value.stats.iter_mut().filter(|data| data.1 == in_coming_data) {
            data.0 += 1;
            // return with abort to terminate the flow
            return Err(InterfaceError::Abort);
        }
        stats_value.stats.push((1, in_coming_data));
        // return with abort to terminate the flow
        Err(InterfaceError::Abort)
    }
    fn handle_post(&mut self, _our_authority: Authority, _from_authority: Authority,
                   _from_address: NameType, _name : NameType, _data: Vec<u8>) -> Result<MessageAction, InterfaceError> {
        Err(InterfaceError::Abort)
    }
    fn handle_get_response(&mut self, from_address: NameType,
                           response: Result<Vec<u8>, ResponseError>) -> routing::node_interface::MethodCall {
        if response.is_ok() {
            let mut d = cbor::Decoder::from_bytes(response.unwrap());
            let response_data: TestData = d.decode().next().unwrap().unwrap();
            println!("testing node received get_response from {} with data as {:?}", from_address, response_data);
        } else {
            println!("testing node received error get_response from {}", from_address);
        }
        routing::node_interface::MethodCall::None
    }
    fn handle_put_response(&mut self, _from_authority: Authority, from_address: NameType,
                           response: Result<Vec<u8>, ResponseError>) -> MethodCall {
        if response.is_ok() {
            println!("testing node shall not receive a put_response in case of success");
        } else {
            println!("testing node received error put_response from {}", from_address);
        }
        MethodCall::None
    }
    fn handle_post_response(&mut self, _from_authority: Authority, _from_address: NameType,
                            _response: Result<Vec<u8>, ResponseError>) {
        unimplemented!();
    }
    fn handle_churn(&mut self, _close_group: Vec<NameType>)
        -> Vec<routing::node_interface::MethodCall> {
        unimplemented!();
    }
    fn handle_cache_get(&mut self, _type_id: u64, name : NameType, _from_authority: Authority,
                        _from_address: NameType) -> Result<MessageAction, InterfaceError> {
        let stats = self.stats.clone();
        let stats_value = stats.lock().unwrap();
        for data in stats_value.stats.iter().filter(|data| data.1.name() == name) {
            println!("testing node find data {} in cache", name);
            return Ok(MessageAction::Reply(data.1.serialised_contents().clone()));
        }
        Err(InterfaceError::Abort)
    }
    fn handle_cache_put(&mut self, _from_authority: Authority, _from_address: NameType,
                        data: Vec<u8>) -> Result<MessageAction, InterfaceError> {
        let stats = self.stats.clone();
        let mut stats_value = stats.lock().unwrap();
        let mut d = cbor::Decoder::from_bytes(data);
        let in_coming_data: TestData = d.decode().next().unwrap().unwrap();
        for _ in stats_value.stats.iter_mut().filter(|data| data.1 == in_coming_data) {
            println!("testing node already have data {:?} in cache", in_coming_data);
            return Err(InterfaceError::Abort);
        }
        println!("testing node inserted data {:?} into cache", in_coming_data);
        stats_value.stats.push((0, in_coming_data));
        Err(InterfaceError::Abort)
    }
    fn handle_get_key(&mut self,
                      _type_id: u64,
                      _name: NameType,
                      _our_authority: Authority,
                      _from_authority: Authority,
                      _from_address: NameType) -> Result<MessageAction, InterfaceError> {
        unimplemented!();
    }
}

struct TestNodeGenerator;

impl CreatePersonas<TestNode> for TestNodeGenerator {
    fn create_personas(&mut self) -> TestNode {
        TestNode::new()
    }
}

fn main() {
    let args = Docopt::new(USAGE)
                      .and_then(|dopt| dopt.parse())
                      .unwrap_or_else(|e| e.exit());

    // You can conveniently access values with `get_{bool,count,str,vec}`
    // functions. If the key doesn't exist (or if, e.g., you use `get_str` on
    // a switch), then a sensible default value is returned.
    let mut command = String::new();
    if args.get_bool("--node") {
        let mut test_node = RoutingNode::<TestNode, TestNodeGenerator>::new(TestNodeGenerator);
        if !args.get_str("peer").is_empty() {
            match SocketAddr::from_str(args.get_str("peer")) {
                Ok(addr) => {
                    println!("initial bootstrapping to {} ", addr);
                    let _ = test_node.bootstrap(Some(vec![Endpoint::Tcp(addr)]), None);
                }
                Err(_) => {}
            };
        } else {
            // if no bootstrap endpoint provided, still need to call the bootstrap method to trigger default behaviour
            let _ = test_node.bootstrap(None, None);
        }
        loop {
            command.clear();
            println!("Input command (stop)");
            let _ = io::stdin().read_line(&mut command);
            let v: Vec<&str> = command.split(' ').collect();
            match v[0].trim() {
                "stop" => break,
                _ => println!("Invalid Option")
            }
        }
    } else if args.get_bool("--first") {
        let mut test_node = RoutingNode::<TestNode, TestNodeGenerator>::new(TestNodeGenerator);
        test_node.run_zero_membrane();
        loop {
            let mut command = String::new();
            command.clear();
            println!("Input command (stop)");
            let _ = io::stdin().read_line(&mut command);
            let v: Vec<&str> = command.split(' ').collect();
            match v[0].trim() {
                "stop" => break,
                _ => println!("Invalid Option")
          }
        }
    } else {
        let test_client = RoutingClient::new(Arc::new(Mutex::new(TestClient {
            stats: Arc::new(Mutex::new(Stats {
                stats: Vec::<(u32, TestData)>::new()})) })), types::Id::new());
        let mutate_client = Arc::new(Mutex::new(test_client));
        let copied_client = mutate_client.clone();
        spawn(move || {
            loop {
                thread::sleep_ms(10);
                copied_client.lock().unwrap().run();
            }
        });
        if !args.get_str("peer").is_empty() {
            match SocketAddr::from_str(args.get_str("peer")) {
                Ok(addr) => {
                    println!("initial bootstrapping to {} ", addr);
                    let _ = mutate_client.lock().unwrap().bootstrap(Some(vec![Endpoint::Tcp(addr)]), None);
                }
                Err(_) => {}
            };
        }else {
            // if no bootstrap endpoint provided, still need to call the bootstrap method to trigger default behaviour
            let _ = mutate_client.lock().unwrap().bootstrap(None, None);
        }
        loop {
            command.clear();
            println!("Enter command (stop | put <key> <value> | get <key>)>");
            let _ = io::stdin().read_line(&mut command);
            let v: Vec<&str> = command.split(' ').collect();
            match v[0].trim() {
                "stop" => break,
                "put" => {
                    let key: Vec<u8> = v[1].trim().bytes().collect();
                    let value: Vec<u8> = v[2].trim().bytes().collect();
                    let data = TestData::new(key.clone(), value.clone());
                    let key_string = std::string::String::from_utf8(key).unwrap();
                    let value_string = std::string::String::from_utf8(value).unwrap();
                    println!("Putting {} to network under key {}", value_string, key_string);
                    let _ = mutate_client.lock().unwrap().put(data);
                },
                "get" => {
                    let key: Vec<u8> = v[1].trim().bytes().collect();
                    let name = TestData::get_name_from_key(&key);
                    let key_string = std::string::String::from_utf8(key).unwrap();
                    println!("Getting value for key {} from network.", key_string);
                    let _ = mutate_client.lock().unwrap().get(201, name);
                },
                _ => println!("Invalid Option")
            }
        }
    }
}

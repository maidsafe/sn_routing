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

use docopt::Docopt;
use rand::random;
use sodiumoxide::crypto;

use crust::Endpoint;
use routing::node_interface::*;
use routing::routing_client::{ClientIdPacket, RoutingClient};
use routing::routing_node::{RoutingNode};
use routing::sendable::Sendable;
use routing::types;
use routing::{Action, NameType, RoutingError};


// ==========================   Program Options   =================================
static USAGE: &'static str = "
Usage: routing -h
       routing -o
       routing -v <endpoint>
       routing -c <endpoint>

Options:
    -h, --help       Display the help message
    -o, --origin     Startup the first testing node
    -c, --client     Node started as client, bootstrap to the specified endpoint
    -v, --vault      Node started as vault, bootstrap to the specified endpoint
";

#[derive(RustcDecodable, Debug)]
struct Args {
    arg_endpoint: Option<String>,
    flag_origin : bool,
    flag_client : bool,
    flag_vault : bool,
    flag_help : bool
}


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
    data: Vec<u8>
}

impl TestData {
    fn new(in_data: Vec<u8>) -> TestData {
        TestData { data: in_data }
    }
}

impl Sendable for TestData {
    fn name(&self) -> NameType {
        let digest = crypto::hash::sha512::hash(&self.data);
        NameType(digest.0)
    }

    fn type_tag(&self)->u64 { unimplemented!() }

    fn serialised_contents(&self)->Vec<u8> { self.data.clone() }

    fn refresh(&self)->bool {
        false
    }

    fn merge(&self, responses: Vec<Box<Sendable>>) -> Option<Box<Sendable>> { None }
}

impl PartialEq for TestData {
    fn eq(&self, other: &TestData) -> bool {
        self.data == other.data
    }
}

impl fmt::Debug for TestData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TestData( name: {:?} )", self.name())
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
    fn handle_get_response(&mut self, _: types::MessageId, response: Result<Vec<u8>, RoutingError>) {
        if response.is_ok() {
            let response_data = TestData::new(response.unwrap());
            println!("testing client received get_response with data name as {}", response_data.name());
        } else {
            println!("testing client received error get_response");
        }
    }
    fn handle_put_response(&mut self, _: types::MessageId, response: Result<Vec<u8>, RoutingError>) {
        if response.is_ok() {
            let response_data = TestData::new(response.unwrap());
            println!("testing client received put_response with data name as {}", response_data.name());
        } else {
            println!("testing client received error put_response");
        }
    }
}

struct TestNode {
    pub stats: Arc<Mutex<Stats>>
}

impl Interface for TestNode {
    fn handle_get(&mut self, type_id: u64, name: NameType, our_authority: types::Authority,
                  from_authority: types::Authority, from_address: NameType)
                   -> Result<Action, RoutingError> {
        println!("testing node handle get request from {} of data {}", from_address, name);
        let stats = self.stats.clone();
        let stats_value = stats.lock().unwrap();
        for data in stats_value.stats.iter().filter(|data| data.1.name() == name) {
            return Ok(Action::Reply(data.1.serialised_contents().clone()));
        }
        Err(RoutingError::NoData)
    }
    fn handle_put(&mut self, our_authority: types::Authority, from_authority: types::Authority,
                from_address: NameType, dest_address: types::DestinationAddress,
                data_in: Vec<u8>) -> Result<Action, RoutingError> {
        let stats = self.stats.clone();
        let mut stats_value = stats.lock().unwrap();
        let in_coming_data = TestData::new(data_in.clone());
        println!("testing node handle put request from {} of data {}", from_address, in_coming_data.name());
        for data in stats_value.stats.iter_mut().filter(|data| data.1 == in_coming_data) {
            data.0 += 1;
            // return with success to terminate the flow
            return Err(RoutingError::Success);
        }
        stats_value.stats.push((1, TestData::new(data_in.clone())));
        // return with success to terminate the flow
        Err(RoutingError::Success)
    }
    fn handle_post(&mut self, our_authority: types::Authority, from_authority: types::Authority,
                   from_address: NameType, name : NameType, data: Vec<u8>) -> Result<Action, RoutingError> {
        Err(RoutingError::Success)
    }
    fn handle_get_response(&mut self, from_address: NameType,
                           response: Result<Vec<u8>, RoutingError>) -> routing::node_interface::RoutingNodeAction {
        if response.is_ok() {
            let response_data = TestData::new(response.unwrap());
            println!("testing node received get_response from {} with data name as {}",
                     from_address, response_data.name());
        } else {
            println!("testing node received error get_response from {}", from_address);
        }
        routing::node_interface::RoutingNodeAction::None
    }
    fn handle_put_response(&mut self, from_authority: types::Authority, from_address: NameType,
                           response: Result<Vec<u8>, RoutingError>) {
        if response.is_ok() {
            let response_data = TestData::new(response.unwrap());
            println!("testing node received put_response from {} with data name as {}",
                     from_address, response_data.name());
        } else {
            println!("testing node received error put_response from {}", from_address);
        }
    }
    fn handle_post_response(&mut self, from_authority: types::Authority, from_address: NameType,
                            response: Result<Vec<u8>, RoutingError>) {
        unimplemented!();
    }
    fn handle_churn(&mut self, close_group: Vec<NameType>)
        -> Vec<routing::node_interface::RoutingNodeAction> {
        unimplemented!();
    }
    fn handle_cache_get(&mut self, type_id: u64, name : NameType, from_authority: types::Authority,
                        from_address: NameType) -> Result<Action, RoutingError> {
        let stats = self.stats.clone();
        let stats_value = stats.lock().unwrap();
        for data in stats_value.stats.iter().filter(|data| data.1.name() == name) {
            println!("testing node find data {} in cache", name);
            return Ok(Action::Reply(data.1.serialised_contents().clone()));
        }
        Err(RoutingError::Success)
    }
    fn handle_cache_put(&mut self, from_authority: types::Authority, from_address: NameType,
                        data: Vec<u8>) -> Result<Action, RoutingError> {
        let stats = self.stats.clone();
        let mut stats_value = stats.lock().unwrap();
        let in_coming_data = TestData::new(data.clone());
        for data in stats_value.stats.iter_mut().filter(|data| data.1 == in_coming_data) {
            println!("testing node already have data {} in cache", in_coming_data.name());
            return Err(RoutingError::Success);
        }
        println!("testing node inserted data {} into cache", in_coming_data.name());
        stats_value.stats.push((0, TestData::new(data.clone())));
        Err(RoutingError::Success)
    }
    fn handle_get_key(&mut self,
                      type_id: u64,
                      name: NameType,
                      our_authority: routing::types::Authority,
                      from_authority: routing::types::Authority,
                      from_address: NameType) -> Result<Action, RoutingError> {
        unimplemented!();
    }
}

fn main() {
    let args : Args = Docopt::new(USAGE)
                     .and_then(|d| d.decode())
                     .unwrap_or_else(|e| e.exit());
    if args.flag_help {
        println!("{:?}", args);
        return;
    }

    let mut command = String::new();
    if args.flag_origin || args.flag_vault {
        let test_node = RoutingNode::new(TestNode { stats: Arc::new(Mutex::new(Stats {stats: Vec::<(u32, TestData)>::new()})) });
        let mutate_node = Arc::new(Mutex::new(test_node));
        let copied_node = mutate_node.clone();
        spawn(move || {
            loop {
                thread::sleep_ms(10);
                copied_node.lock().unwrap().run();
            }
        });
        if args.arg_endpoint.is_some() {
            match SocketAddr::from_str(args.arg_endpoint.unwrap().trim()) {
                Ok(addr) => {
                    println!("initial bootstrapping to {} ", addr);
                    let _ = mutate_node.lock().unwrap().bootstrap(Some(vec![Endpoint::Tcp(addr)]), None); 
                }
                Err(_) => {}
            };
        }
        loop {
            command.clear();
            println!("Input command (stop, bootstrap <endpoint>)");
            let _ = io::stdin().read_line(&mut command);
            let v: Vec<&str> = command.split(' ').collect();
            match v[0].trim() {
                "stop" => break,
                "bootstrap" => {
                    let endpoint_address = match SocketAddr::from_str(v[1].trim()) {
                        Ok(addr) => addr,
                        Err(_) => continue
                    };
                    println!("bootstrapping to {} ", endpoint_address);
                    let _ = mutate_node.lock().unwrap().bootstrap(Some(vec![Endpoint::Tcp(endpoint_address)]), None);
                },
                _ => println!("Invalid Option")
            }
        }
    } else if args.flag_client {
        let sign_keypair = crypto::sign::gen_keypair();
        let encrypt_keypair = crypto::asymmetricbox::gen_keypair();
        let client_id_packet = ClientIdPacket::new((sign_keypair.0, encrypt_keypair.0), (sign_keypair.1, encrypt_keypair.1));
        let test_client = RoutingClient::new(TestClient { stats: Arc::new(Mutex::new(Stats {stats: Vec::<(u32, TestData)>::new()})) }, client_id_packet);
        let mutate_client = Arc::new(Mutex::new(test_client));
        let copied_client = mutate_client.clone();
        spawn(move || {
            loop {
                thread::sleep_ms(10);
                copied_client.lock().unwrap().run();
            }
        });
        if args.arg_endpoint.is_some() {
            match SocketAddr::from_str(args.arg_endpoint.unwrap().trim()) {
                Ok(addr) => {
                    println!("initial bootstrapping to {} ", addr);
                    let _ = mutate_client.lock().unwrap().bootstrap(Some(vec![Endpoint::Tcp(addr)]), None); 
                }
                Err(_) => {}
            };
        }
        let mut ori_packets = Vec::<TestData>::new();
        loop {
            command.clear();
            println!("Input command (stop, put <msg_length>, get <index>)");
            let _ = io::stdin().read_line(&mut command);
            let v: Vec<&str> = command.split(' ').collect();
            match v[0].trim() {
                "stop" => break,
                "put" => {
                    let length : usize = match v[1].trim().parse().ok() { Some(length) => length, _ => 1024 };
                    let data = TestData::new(generate_random_vec_u8(length));
                    ori_packets.push(data.clone());
                    println!("putting data {} to network ", data.name());             
                    let _ = mutate_client.lock().unwrap().put(data);
                },
                "get" => {
                    let index : usize = match v[1].trim().parse().ok() { Some(index) => index, _ => 0 };
                    if index < ori_packets.len() {
                        println!("getting chunk {} from network ", ori_packets[index].name());
                        let _ = mutate_client.lock().unwrap().get(110, ori_packets[index].name());
                    } else {
                        println!("only has {} packets in record ", ori_packets.len());
                    }
                },
                _ => println!("Invalid Option")
            }
        }
    }
}

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
use std::sync::{Arc, mpsc, Mutex};
use std::thread;

use docopt::Docopt;
use rand::random;
use sodiumoxide::crypto;

use crust::Endpoint;
use routing::generic_sendable_type;
use routing::NameType;
use routing::node_interface::*;
use routing::routing_node::{RoutingNode};
use routing::sendable::Sendable;
use routing::types;
use routing::{Action, RoutingError};


// ==========================   Program Options   =================================
static USAGE: &'static str = "
Usage: routing -h
       routing -o

Options:
    -h, --help       Display the help message.
    -o, --origin     Startup the first testing node
";

// cargo run --example routing -- GET -s 60

#[derive(RustcDecodable, Debug)]
struct Args {
    flag_origin : bool,
    flag_help : bool
}

// ==========================   Test Data Structure   =================================
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

struct TestNode {
    pub stats: Arc<Mutex<Stats>>,
    pub ori_packets: Vec<TestData>
}

impl Interface for TestNode {
    fn handle_get(&mut self, type_id: u64, name : NameType, our_authority: types::Authority,
                  from_authority: types::Authority, from_address: NameType) -> Result<Action, RoutingError> {
        let stats = self.stats.clone();
        let mut stats_value = stats.lock().unwrap();
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
        for data in stats_value.stats.iter_mut().filter(|data| data.1 == in_coming_data) {
            data.0 += 1;
            return Ok(Action::Reply(data_in));
        }
        stats_value.stats.push((1, TestData::new(data_in.clone())));
        Ok(Action::Reply(data_in))
    }
    fn handle_post(&mut self, our_authority: types::Authority, from_authority: types::Authority,
                   from_address: NameType, data: Vec<u8>) -> Result<Action, RoutingError> {
        Err(RoutingError::Success)
    }
    fn handle_get_response(&mut self, from_address: NameType, response: Result<Vec<u8>,
                           RoutingError>) {
        unimplemented!();
    }
    fn handle_put_response(&mut self, from_authority: types::Authority, from_address: NameType,
                           response: Result<Vec<u8>, RoutingError>) {
        unimplemented!();
    }
    fn handle_post_response(&mut self, from_authority: types::Authority, from_address: NameType,
                            response: Result<Vec<u8>, RoutingError>) {
        unimplemented!();
    }
    fn handle_churn(&mut self, close_group: Vec<NameType>)
        -> Vec<generic_sendable_type::GenericSendableType> {
        unimplemented!();
    }
    fn handle_cache_get(&mut self, type_id: u64, name : NameType, from_authority: types::Authority,
                        from_address: NameType) -> Result<Action, RoutingError> {
        Err(RoutingError::Success)
    }
    fn handle_cache_put(&mut self, from_authority: types::Authority, from_address: NameType,
                        data: Vec<u8>) -> Result<Action, RoutingError> {
        Err(RoutingError::Success)
    }
}

fn main() {
    let args : Args = Docopt::new(USAGE)
                     .and_then(|d| d.decode())
                     .unwrap_or_else(|e| e.exit());
    if args.flag_help {
        println!("{:?}", args);
        // return;
    }
    println!("constructing routing_node");
    let mut testing_node = RoutingNode::new(TestNode { stats: Arc::new(Mutex::new(Stats {stats: Vec::<(u32, TestData)>::new()})),
                                                       ori_packets: Vec::<TestData>::new() });
    println!("preparing interaction interface");
    let mut command = String::new();
    loop {
        command.clear();
        println!("Input command (stop, put <msg_length>, get <index>, bootstrap <endpoint>)");
        let _ = io::stdin().read_line(&mut command);
        let v: Vec<&str> = command.split(' ').collect();
        match v[0].trim() {
            "stop" => break,
            "put" => {
                println!("putting msg")
            },
            "get" => {
                println!("getting msg")
            },
            "bootstrap" => {
                let endpoint_address = match SocketAddr::from_str(v[1].trim()) {
                    Ok(addr) => addr,
                    Err(_) => continue
                };
                println!("bootstrapping to {} ", endpoint_address);
                let _ = testing_node.bootstrap(Some(vec![Endpoint::Tcp(endpoint_address)]), None);
            },
            _ => println!("Invalid Option")
        }
    }
}

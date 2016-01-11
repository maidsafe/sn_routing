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

use crust::{Endpoint, Port};
use std::collections::HashSet;
use std::net::SocketAddr;
use ip::IpAddr;

/// Holds the endpoints crust informs us were accepting on.
pub struct Acceptors {
    endpoints: HashSet<::crust::Endpoint>,
    bootstrap_ip: Option<IpAddr>,
    tcp_accepting_port: Option<Port>,
    utp_accepting_port: Option<Port>,
}

impl Acceptors {
    pub fn new() -> Acceptors {
        Acceptors {
            endpoints: HashSet::new(),
            bootstrap_ip: None,
            tcp_accepting_port: None,
            utp_accepting_port: None,
        }
    }

    /// If disconnected on our first call to connect, set our bootstrap nodes' ip from the returned endpoint.
    pub fn set_bootstrap_ip(&mut self, bootstrap_endpoint: Endpoint) {
        self.bootstrap_ip = Some(Self::ip_from_socketaddr(bootstrap_endpoint.get_address()));
    }

    /// The tcp port from the endpoint returned by crust on a call to start_accepting with our default tcp port.
    pub fn set_tcp_accepting_port(&mut self, accepting_port: Port) {
        match accepting_port {
            Port::Tcp(port) => {
                self.tcp_accepting_port = Some(Port::Tcp(port));
                if let Some(ref bootstrap_ip) = self.bootstrap_ip {
                    let _ = self.endpoints
                                .insert(Endpoint::new(bootstrap_ip.clone(), Port::Tcp(port)));
                }
            }
            _ => unreachable!(),
        }
    }

    #[allow(dead_code)]
    /// The utp port from the endpoint returned by crust on a call to start_accepting with our default utp port.
    pub fn set_utp_accepting_port(&mut self, accepting_port: Port) {
        match accepting_port {
            Port::Utp(port) => self.utp_accepting_port = Some(Port::Utp(port)),
            _ => unreachable!(),
        }
    }

    /// If `our_endpoint` port matches our accepting port add the endpoint if not already present.
    pub fn add(&mut self, our_endpoint: Endpoint) {
        match our_endpoint {
            Endpoint::Tcp(socket_addr) => {
                if let Some(ref port) = self.tcp_accepting_port {
                    let _ = self.endpoints
                                .insert(Endpoint::new(Self::ip_from_socketaddr(socket_addr),
                                                      port.clone()));
                }
            }
            Endpoint::Utp(socket_addr) => {
                if let Some(ref port) = self.utp_accepting_port {
                    let _ = self.endpoints
                                .insert(Endpoint::new(Self::ip_from_socketaddr(socket_addr),
                                                      port.clone()));
                }
            }
        }
    }

    /// Return the list of endpoints were accepting on.
    pub fn endpoints(&self) -> Vec<Endpoint> {
        self.endpoints.iter().cloned().collect()
    }

    fn ip_from_socketaddr(addr: SocketAddr) -> IpAddr {
        match addr {
            SocketAddr::V4(address) => IpAddr::V4(*address.ip()),
            SocketAddr::V6(address) => IpAddr::V6(*address.ip()),
        }
    }
}

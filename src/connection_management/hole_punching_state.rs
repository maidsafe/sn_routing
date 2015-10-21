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

/// HolePunchingState.
pub enum HolePunchingState {
    /// Mapping(NameType)
    Mapping(::NameType),
    // Mapped(::NameType, ::std::net::UdpSocket),
    
    /// Connecting(NameType, UdpSocket, secret)
    Connecting(::NameType, ::std::net::UdpSocket, Option<[u8; 4]>),
    
    /// Punching(NameType, UdpSocket, secret, number_of_failed_attempts)
    Punching(::NameType, ::std::net::UdpSocket, Option<[u8; 4]>, u32),
    
    /// RendezvousConnecting(NameType, UdpSocket)
    RendezvousConnecting(::NameType, ::std::net::UdpSocket)
}

#[cfg(test)]
mod test {

    #[test]
    fn hole_punching_state() {
        let name: ::name_type::NameType = ::test_utils::Random::generate_random();
        let state = ::connection_management::HolePunchingState::Mapping(name);
        match state {
            ::connection_management::HolePunchingState::Mapping(_) => assert!(true),
            ::connection_management::HolePunchingState::Connecting(_,_,_) => assert!(false),
            ::connection_management::HolePunchingState::Punching(_,_,_,_) => assert!(false),
            ::connection_management::HolePunchingState::RendezvousConnecting(_,_) => assert!(false),
        }
    }
}

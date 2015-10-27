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
#[allow(unused)]
pub enum HolePunchingState {
    /// Mapping(NameType)
    Mapping(::NameType),

    /// Connecting(NameType, UdpSocket, secret)
    Connecting(::NameType, ::std::net::UdpSocket, Option<[u8; 4]>),

    /// Punching(NameType, UdpSocket, secret, number_of_failed_attempts)
    Punching(::NameType, ::std::net::UdpSocket, Option<[u8; 4]>, u32),

    /// RendezvousConnecting(NameType, UdpSocket)
    RendezvousConnecting(::NameType, ::std::net::UdpSocket)
}

#[cfg(test)]
mod test {
    use rand;
    
    #[test]
    fn hole_punching_state() {
        let name: ::NameType = rand::random();
        let secret: Option<[u8; 4]> = None;
        let number_of_failed_attempts: u32 = 1;

        // test HolePunchingState::Mapping
        let mapping_state = super::HolePunchingState::Mapping(name);
        assert_match_state(mapping_state, true, false, false, false);

        // test HolePunchingState::Connecting
        let sr1: Result<::std::net::UdpSocket, _> = ::std::net::UdpSocket::bind("127.0.0.1:34254");
        match sr1 {
            Err(why) => panic!("{:?}", why),
            Ok(socket) => {
                let connecting_state = super::HolePunchingState::Connecting(
                    name,
                    socket,
                    secret);
                assert_match_state(connecting_state, false, true, false, false);
            }
        }

        // test HolePunchingState::Punching
        let sr2: Result<::std::net::UdpSocket, _> = ::std::net::UdpSocket::bind("127.0.0.1:34254");
        match sr2 {
            Err(why) => panic!("{:?}", why),
            Ok(socket) => {
                let punching_state = super::HolePunchingState::Punching(
                    name,
                    socket,
                    secret,
                    number_of_failed_attempts);
                assert_match_state(punching_state, false, false, true, false);
            }
        }

        // test HolePunchingState::RendezvousConnecting
        let sr3: Result<::std::net::UdpSocket, _> = ::std::net::UdpSocket::bind("127.0.0.1:34254");
        match sr3 {
            Err(why) => panic!("{:?}", why),
            Ok(socket) => {
                let rendezvous_state = super::HolePunchingState::RendezvousConnecting(
                    name,
                    socket);
                assert_match_state(rendezvous_state, false, false, false, true);
            }
        }
    }

    fn assert_match_state(
        state: ::connection_management::HolePunchingState,
        is_mapping: bool,
        is_connecting: bool,
        is_punching: bool,
        is_rendezvous_connecting: bool) {
        match state {
            ::connection_management::HolePunchingState::Mapping(_) => assert!(is_mapping),
            ::connection_management::HolePunchingState::Connecting(_,_,_) => assert!(is_connecting),
            ::connection_management::HolePunchingState::Punching(_,_,_,_) => assert!(is_punching),
            ::connection_management::HolePunchingState::RendezvousConnecting(_,_) =>
                assert!(is_rendezvous_connecting),
        }
    }
}

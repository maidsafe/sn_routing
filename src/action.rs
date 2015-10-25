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

/// An Action initiates a message flow < A | B > where we are (a part of) A.
///    1. Action::SendMessage hands a fully formed SignedMessage over to RoutingNode
///       for it to be sent on across the network.
///    2. Terminate indicates to RoutingNode that no new actions should be taken and all
///       pending events should be handled.
///       After completion RoutingNode will send Event::Terminated.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(unused)]
pub enum Action {
    SendMessage(::messages::SignedMessage),
    //          ~~|~~~~~~~~~~
    //            | a fully signed message with a given claimant
    SendContent(::authority::Authority, ::authority::Authority, ::messages::Content),
    SendConfirmationHello(::crust::Connection, ::types::Address),
    ClientSendContent(::authority::Authority, ::messages::Content),
    //          ~~|~~~~~~  ~~|~~~~
    //            |          | the bare content for a message to be formed
    //            | the destination authority
    // RoutingNode will form the RoutingMessage and sign it as its own identity
    Churn(::direct_messages::Churn, Vec<::crust::Connection>, ::NameType),
    SetCacheOptions(::types::CacheOptions),
    DropConnections(Vec<::crust::Connection>),
    MatchConnection(Option<(::routing_core::ExpectedConnection, Option<::crust::Connection>)>,
                    Option<(::crust::Connection, Option<::direct_messages::Hello>)>),
    Rebootstrap,
    Terminate,
}

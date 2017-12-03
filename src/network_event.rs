// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use peer_id::PeerId;
use routing_table::Prefix;

/// Will create `Block`s we keep in a chain, transitions happens in pairs e.g. (`Lost` -> `Live`),
/// (`Gone` -> `Live`), (`Killed` -> `Live`), etc.  Merge and split (`PrefixChange`) sparks pairs of
/// (`Gone` -> `Live`) pairs (possibly none, but unlikely).  `Lost` is out of the blue but pairs
/// with `Live` or possibly `PrefixChange` as can `Live` create `PrefixChange` and then more pairs.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum SectionState {
    /// Accepted but not yet lost.  May have joined or been relocated here, or may have come back
    /// via a merge or restart.
    Live(PeerId),
    /// Cannot ever become live again.
    Killed(PeerId),
    /// Lost (disconnected) and can become live here (restart) to be relocated (ONLY UNFORSEEABLE
    /// STATE).  Can happen out of order, but forces next state.
    Lost(PeerId),
    /// Gone to another section via "split" or become an Adult (Demoted).  Can again become live
    /// here.
    Gone(PeerId),
    /// Cannot ever become live here again.  Could be relocated to the same section it's leaving
    /// during network start up or for balancing the network.
    Relocated(PeerId),
    /// Our section split or merged.  Prefix is "to" for split and "from" for merge to ensure
    /// block's uniqueness.
    PrefixChange(Prefix),
}


/// Treat this just like ValidPeers - i.e. every new Elder must give us its `Vote` for all of these
/// to be accepted.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum DataIdentifier {
    Temp,
}

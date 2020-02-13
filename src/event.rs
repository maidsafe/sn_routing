// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    location::{DstLocation, SrcLocation},
    xor_space::{Prefix, XorName},
};
use hex_fmt::HexFmt;
use std::fmt::{self, Debug, Formatter};

/// An Event raised as node complete joining
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Connected {
    /// Node first joining the network
    First,
    /// Node relocating from one section to another
    Relocate,
}

/// An Event raised by a `Node` or `Client` via its event sender.
///
/// These are sent by routing to the library's user. It allows the user to handle requests and
/// responses, and to react to changes in the network.
///
/// `Request` and `Response` events from section locations are only raised once the quorum has
/// been reached, i.e. enough members of the section have sent the same message.
#[derive(Clone, Eq, PartialEq)]
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
pub enum Event {
    /// Received a message.
    MessageReceived {
        /// The content of the message.
        content: Vec<u8>,
        /// The source location that sent the message.
        src: SrcLocation,
        /// The destination location that receives the message.
        dst: DstLocation,
    },
    /// Our own section has been split, resulting in the included `Prefix` for our new section.
    SectionSplit(Prefix<XorName>),
    /// The client has successfully connected to a proxy node on the network.
    Connected(Connected),
    /// Disconnected or failed to connect - restart required.
    RestartRequired,
    /// Startup failed - terminate.
    Terminated,
    /// Consensus on a custom event.
    Consensus(Vec<u8>),
}

impl Debug for Event {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Self::MessageReceived {
                ref content,
                ref src,
                ref dst,
            } => write!(
                formatter,
                "Event::MessageReceived {{ content: \"{:<8}\", src: {:?}, dst: {:?} }}",
                HexFmt(content),
                src,
                dst
            ),
            Self::SectionSplit(ref prefix) => {
                write!(formatter, "Event::SectionSplit({:?})", prefix)
            }
            Self::Connected(ref connect_type) => {
                write!(formatter, "Event::Connected({:?})", connect_type)
            }
            Self::RestartRequired => write!(formatter, "Event::RestartRequired"),
            Self::Terminated => write!(formatter, "Event::Terminated"),
            Self::Consensus(ref payload) => {
                write!(formatter, "Event::Consensus({:<8})", HexFmt(payload))
            }
        }
    }
}

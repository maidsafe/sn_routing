// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Bootstrapped;
use crate::{
    chain::SectionInfo,
    error::{Result, RoutingError},
    id::PublicId,
    messages::{RoutingMessage, SignedMessage},
    routing_table::Authority,
};
#[cfg(feature = "mock")]
use fake_clock::FakeClock as Instant;
use std::collections::BTreeSet;
#[cfg(not(feature = "mock"))]
use std::time::Instant;

pub fn send_routing_message_via_route<T>(
    client: &mut T,
    proxy_pub_id: &PublicId,
    routing_msg: RoutingMessage,
    src_section: Option<SectionInfo>,
    route: u8,
    expires_at: Option<Instant>,
) -> Result<()>
where
    T: Bootstrapped,
{
    if routing_msg.dst.is_client() && client.in_authority(&routing_msg.dst) {
        return Ok(()); // Message is for us.
    }

    // Get PublicId of the proxy node
    match routing_msg.src {
        Authority::Client {
            ref proxy_node_name,
            ..
        } => {
            if *proxy_pub_id.name() != *proxy_node_name {
                error!(
                    "{} Unable to find connection to proxy node in proxy map",
                    client
                );
                return Err(RoutingError::ProxyConnectionNotFound);
            }
        }
        _ => {
            error!("{} Source should be client if our state is Client", client);
            return Err(RoutingError::InvalidSource);
        }
    };

    let signed_msg = SignedMessage::new(routing_msg, client.full_id(), None)?;

    if client.add_to_pending_acks(signed_msg.routing_message(), src_section, route, expires_at)
        && !client.filter_outgoing_routing_msg(signed_msg.routing_message(), proxy_pub_id, route)
    {
        let bytes = client.to_hop_bytes(signed_msg.clone(), route, BTreeSet::new())?;
        client.send_or_drop(&proxy_pub_id, bytes, signed_msg.priority());
    }

    Ok(())
}

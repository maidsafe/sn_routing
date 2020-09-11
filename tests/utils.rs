// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use routing::{event::Event, EventStream, FullId, Node, NodeConfig, Result, TransportConfig};
use std::{collections::HashSet, io::Write, net::SocketAddr, sync::Once};
use xor_name::XorName;

static LOG_INIT: Once = Once::new();

// -----  TestNode and builder  -----

pub struct TestNode {
    node: Node,
    event_stream: EventStream,
}

impl TestNode {
    pub fn builder(config: Option<NodeConfig>) -> TestNodeBuilder {
        // We initialise the logger but only once for all tests
        LOG_INIT.call_once(|| {
            env_logger::builder()
                // the test framework will capture the log output and show it only on failure.
                // Run the tests with --nocapture to override.
                .is_test(true)
                .format(|buf, record| {
                    writeln!(
                        buf,
                        "{:.1} {} ({}:{})",
                        record.level(),
                        record.args(),
                        record.file().unwrap_or("<unknown>"),
                        record.line().unwrap_or(0)
                    )
                })
                .init()
        });
        TestNodeBuilder::new(config.unwrap_or_else(|| NodeConfig::default()))
    }

    pub async fn next_event(&mut self) -> Option<Event> {
        self.event_stream.next().await
    }

    pub async fn endpoint(&self) -> Result<SocketAddr> {
        let mut local_addr = self.node.our_connection_info().await?;
        // FIXME: we are currently getting an IP == 0.0.0.0
        local_addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
        Ok(local_addr)
    }

    pub async fn name(&self) -> XorName {
        self.node.name().await
    }
}

pub struct TestNodeBuilder {
    config: NodeConfig,
}

impl<'a> TestNodeBuilder {
    pub(crate) fn new(config: NodeConfig) -> Self {
        Self { config }
    }

    pub fn first(mut self) -> Self {
        self.config.first = true;
        self
    }

    pub fn with_contact(mut self, contact: SocketAddr) -> Self {
        let mut contacts = HashSet::default();
        contacts.insert(contact);
        self.config.transport_config.hard_coded_contacts = contacts;
        self
    }

    pub fn elder_size(&mut self, size: usize) -> &mut Self {
        self.config.network_params.elder_size = size;
        self
    }

    pub fn recommended_section_size(&mut self, size: usize) -> &mut Self {
        self.config.network_params.recommended_section_size = size;
        self
    }

    pub fn transport_config(mut self, config: TransportConfig) -> Self {
        self.config.transport_config = config;
        self
    }

    pub fn full_id(mut self, full_id: FullId) -> Self {
        self.config.full_id = Some(full_id);
        self
    }

    pub async fn create(self) -> Result<TestNode> {
        let node = Node::new(self.config).await?;
        let event_stream = node.listen_events().await?;

        Ok(TestNode { node, event_stream })
    }
}

/// Expect that the next event raised by the node matches the given pattern.
/// Errors if no event, or an event that does not match the pattern is raised.
#[macro_export]
macro_rules! expect_next_event {
    ($node:expr, $pattern:pat) => {
        match $node.next_event().await {
            Some($pattern) => Ok(()),
            other => Err(Error::Unexpected(format!(
                "Expecting {} at {}, got {:?}",
                stringify!($pattern),
                $node.name().await,
                other
            ))),
        }
    };
}

// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    error::Result, event::Event, location::DstLocation, messages::Message, node::stage::Stage,
};
use bytes::Bytes;
use futures::lock::Mutex;
use qp2p::{IncomingConnections, IncomingMessages, Message as QuicP2pMsg};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::mpsc;
use xor_name::XorName;

/// Stream of routing node events
pub struct EventStream {
    events_rx: mpsc::UnboundedReceiver<Event>,
}

impl EventStream {
    pub(crate) async fn new(
        stage: Arc<Mutex<Stage>>,
        xorname: XorName,
        incoming_conns: IncomingConnections,
        timer_rx: mpsc::UnboundedReceiver<u64>,
        events_rx: mpsc::UnboundedReceiver<Event>,
    ) -> Result<Self> {
        Self::spawn_connections_handler(Arc::clone(&stage), incoming_conns, xorname);
        Self::spawn_timer_handler(stage, timer_rx);

        Ok(Self { events_rx })
    }

    /// Returns next event
    pub async fn next(&mut self) -> Option<Event> {
        self.events_rx.recv().await
    }

    // Spawns a task which handles each new incoming connection from peers
    fn spawn_connections_handler(
        stage: Arc<Mutex<Stage>>,
        mut incoming_conns: IncomingConnections,
        xorname: XorName,
    ) {
        let _ = tokio::spawn(async move {
            while let Some(incoming_msgs) = incoming_conns.next().await {
                trace!(
                    "New connection established by peer {}",
                    incoming_msgs.remote_addr()
                );
                Self::spawn_messages_handler(stage.clone(), incoming_msgs, xorname)
            }
        });
    }

    // Spawns a task which handles each new incoming message from a connection with a peer
    fn spawn_messages_handler(
        stage: Arc<Mutex<Stage>>,
        mut incoming_msgs: IncomingMessages,
        xorname: XorName,
    ) {
        let _ = tokio::spawn(async move {
            while let Some(msg) = incoming_msgs.next().await {
                match msg {
                    QuicP2pMsg::UniStream { bytes, src, .. } => {
                        trace!(
                            "New message ({} bytes) received on a uni-stream from: {}",
                            bytes.len(),
                            src
                        );
                        // Since it's arriving on a uni-stream we treat it as a Node
                        // message which we need to be processed by us, as well as
                        // reported to the event stream consumer.
                        spawn_node_message_handler(stage.clone(), bytes, src);
                    }
                    QuicP2pMsg::BiStream {
                        bytes,
                        src,
                        send,
                        recv,
                    } => {
                        trace!(
                            "New message ({} bytes) received on a bi-stream from: {}",
                            bytes.len(),
                            src
                        );

                        // Since it's arriving on a bi-stream we treat it as a Client
                        // message which we report directly to the event stream consumer
                        // without doing any intermediate processing.
                        let event = Event::ClientMessageReceived {
                            content: bytes,
                            src,
                            dst: DstLocation::Node(xorname),
                            send,
                            recv,
                        };

                        stage.lock().await.send_event(event);
                    }
                }
            }
        });
    }

    fn spawn_timer_handler(stage: Arc<Mutex<Stage>>, mut rx: mpsc::UnboundedReceiver<u64>) {
        let _ = tokio::spawn(async move {
            while let Some(token) = rx.recv().await {
                if let Err(err) = stage.lock().await.process_timeout(token).await {
                    error!("Error encountered when processing timeout: {}", err);
                }
            }
        });
    }
}

fn spawn_node_message_handler(stage: Arc<Mutex<Stage>>, msg_bytes: Bytes, sender: SocketAddr) {
    let _ = tokio::spawn(async move {
        match Message::from_bytes(&msg_bytes) {
            Err(error) => {
                debug!("Failed to deserialize message: {:?}", error);
            }
            Ok(msg) => {
                trace!("try handle message {:?}", msg);
                // Process the message according to our stage
                if let Err(err) = stage
                    .lock()
                    .await
                    .process_message(sender, msg.clone())
                    .await
                {
                    error!(
                        "Error encountered when processing message {:?}: {}",
                        msg, err
                    );
                }
            }
        }
    });
}

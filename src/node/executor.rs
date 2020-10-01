// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Command;
use crate::{
    cancellation::{cancellable, CancellationHandle, CancellationToken},
    event::Event,
    messages::Message,
    node::stage::Stage,
};
use bytes::Bytes;
use qp2p::{IncomingConnections, IncomingMessages, Message as QuicP2pMsg};
use std::{net::SocketAddr, sync::Arc};

pub struct Executor {
    _cancellation_handle: CancellationHandle,
}

impl Executor {
    pub(crate) fn new(stage: Arc<Stage>, incoming_conns: IncomingConnections) -> Self {
        let (handle, token) = CancellationHandle::new();
        spawn_connections_handler(stage, incoming_conns, token);

        Self {
            _cancellation_handle: handle,
        }
    }
}

// Spawns a task which handles each new incoming connection from peers
fn spawn_connections_handler(
    stage: Arc<Stage>,
    mut incoming_conns: IncomingConnections,
    cancel_token: CancellationToken,
) {
    let _ = tokio::spawn(cancellable(cancel_token.clone(), async move {
        while let Some(incoming_msgs) = incoming_conns.next().await {
            trace!(
                "New connection established by peer {}",
                incoming_msgs.remote_addr()
            );
            spawn_messages_handler(stage.clone(), incoming_msgs, cancel_token.clone())
        }
    }));
}

// Spawns a task which handles each new incoming message from a connection with a peer
fn spawn_messages_handler(
    stage: Arc<Stage>,
    mut incoming_msgs: IncomingMessages,
    cancel_token: CancellationToken,
) {
    let _ = tokio::spawn(cancellable(cancel_token, async move {
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
                        send,
                        recv,
                    };

                    stage.send_event(event);
                }
            }
        }
    }));
}

fn spawn_node_message_handler(stage: Arc<Stage>, msg_bytes: Bytes, sender: SocketAddr) {
    let _ = tokio::spawn(async move {
        match Message::from_bytes(&msg_bytes) {
            Ok(message) => {
                let command = Command::HandleMessage {
                    message,
                    sender: Some(sender),
                };
                let _ = stage.handle_commands(command).await;
            }
            Err(error) => {
                debug!("Failed to deserialize message: {}", error);
            }
        }
    });
}

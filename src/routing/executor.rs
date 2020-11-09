// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    comm::{ConnectionEvent, IncomingConnections},
    Command, Stage,
};
use crate::{event::Event, messages::Message};
use bytes::Bytes;
use std::{net::SocketAddr, sync::Arc};
use tokio::{sync::oneshot, task};

pub struct Executor {
    cancel_tx: Option<oneshot::Sender<()>>,
}

impl Drop for Executor {
    fn drop(&mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Executor {
    pub(crate) async fn new(stage: Arc<Stage>, incoming_conns: IncomingConnections) -> Self {
        let (cancel_tx, cancel_rx) = oneshot::channel();

        let _ = task::spawn(async move {
            tokio::select! {
                _ = handle_incoming_messages(stage, incoming_conns) => (),
                _ = cancel_rx => (),
            }
        });

        Self {
            cancel_tx: Some(cancel_tx),
        }
    }
}

async fn handle_incoming_messages(stage: Arc<Stage>, mut incoming_conns: IncomingConnections) {
    while let Some(event) = incoming_conns.next().await {
        match event {
            ConnectionEvent::Received(qp2p::Message::UniStream { bytes, src, .. }) => {
                trace!(
                    "New message ({} bytes) received on a uni-stream from: {}",
                    bytes.len(),
                    src
                );
                // Since it's arriving on a uni-stream we treat it as a Node
                // message which needs to be processed by us, as well as
                // potentially reported to the event stream consumer.
                spawn_node_message_handler(stage.clone(), bytes, src);
            }
            ConnectionEvent::Received(qp2p::Message::BiStream {
                bytes,
                src,
                send,
                recv,
            }) => {
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

                stage.send_event(event).await;
            }
            ConnectionEvent::Disconnected(addr) => trace!("Connection lost: {}", addr),
        }
    }
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

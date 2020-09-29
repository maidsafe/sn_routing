// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{event::Event, messages::Message, node::stage::Stage};
use bytes::Bytes;
use qp2p::{IncomingConnections, IncomingMessages, Message as QuicP2pMsg};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::{mpsc, Mutex};

pub struct Executor {
    _terminate_tx: terminate::Sender,
}

impl Executor {
    pub(crate) fn new(
        stage: Arc<Mutex<Stage>>,
        incoming_conns: IncomingConnections,
        timer_rx: mpsc::UnboundedReceiver<u64>,
    ) -> Self {
        let (terminate_tx, terminate_rx) = terminate::channel();

        spawn_connections_handler(Arc::clone(&stage), incoming_conns, terminate_rx.clone());
        spawn_timer_handler(stage, timer_rx, terminate_rx);

        Self {
            _terminate_tx: terminate_tx,
        }
    }
}

// Spawns a task which handles each new incoming connection from peers
fn spawn_connections_handler(
    stage: Arc<Mutex<Stage>>,
    mut incoming_conns: IncomingConnections,
    mut terminate_rx: terminate::Receiver,
) {
    let _ = tokio::spawn(async move {
        while let Some(incoming_msgs) = terminate_rx.run(incoming_conns.next()).await {
            trace!(
                "{}New connection established by peer {}",
                stage.lock().await.log_ident(),
                incoming_msgs.remote_addr()
            );
            spawn_messages_handler(stage.clone(), incoming_msgs, terminate_rx.clone())
        }

        trace!(
            "{}Connections handler terminated",
            stage.lock().await.log_ident()
        );
    });
}

// Spawns a task which handles each new incoming message from a connection with a peer
fn spawn_messages_handler(
    stage: Arc<Mutex<Stage>>,
    mut incoming_msgs: IncomingMessages,
    mut terminate_rx: terminate::Receiver,
) {
    let _ = tokio::spawn(async move {
        while let Some(msg) = terminate_rx.run(incoming_msgs.next()).await {
            match msg {
                QuicP2pMsg::UniStream { bytes, src, .. } => {
                    trace!(
                        "{}New message ({} bytes) received on a uni-stream from: {}",
                        stage.lock().await.log_ident(),
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
                        "{}New message ({} bytes) received on a bi-stream from: {}",
                        stage.lock().await.log_ident(),
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

                    stage.lock().await.send_event(event);
                }
            }
        }

        trace!(
            "{}Messages handler for {} terminated",
            stage.lock().await.log_ident(),
            incoming_msgs.remote_addr()
        );
    });
}

fn spawn_node_message_handler(stage: Arc<Mutex<Stage>>, msg_bytes: Bytes, sender: SocketAddr) {
    let _ = tokio::spawn(async move {
        match Message::from_bytes(&msg_bytes) {
            Ok(msg) => {
                // Process the message according to our stage
                let mut stage = stage.lock().await;
                if let Err(err) = stage.process_message(sender, msg.clone()).await {
                    error!(
                        "{}Error encountered when processing message {:?}: {}",
                        stage.log_ident(),
                        msg,
                        err
                    );
                }
            }
            Err(error) => {
                debug!(
                    "{}Failed to deserialize message: {:?}",
                    stage.lock().await.log_ident(),
                    error
                );
            }
        }
    });
}

fn spawn_timer_handler(
    stage: Arc<Mutex<Stage>>,
    mut timer_rx: mpsc::UnboundedReceiver<u64>,
    mut terminate_rx: terminate::Receiver,
) {
    let _ = tokio::spawn(async move {
        while let Some(token) = terminate_rx.run(timer_rx.recv()).await {
            if let Err(err) = stage.lock().await.process_timeout(token).await {
                error!(
                    "{}Error encountered when processing timeout: {}",
                    stage.lock().await.log_ident(),
                    err
                );
            }
        }

        trace!("{}Timer handler terminated", stage.lock().await.log_ident());
    });
}

// A single consumer, multiple producer one-shot channel that sends when the sender gets dropped.
// Used to observe termination of some object from any number of tasks simultaneously.
//
// Note: it seems we could have used `tokio::sync::watch` for this exact purpose. The reason why we
// didn't is that `watch` interacts poorly with the `select!` macro. It requires the future
// returned from `recv` to be pinned which leads to convoluted code.
mod terminate {
    use super::*;
    use futures::Future;
    use tokio::sync::{Mutex, OwnedMutexGuard};

    // Value that notifies all corresponding `Receiver`s when dropped.
    pub struct Sender(OwnedMutexGuard<()>);

    // Value that gets notified when the corresponding `Sender` gets dropped.
    #[derive(Clone)]
    pub struct Receiver(Arc<Mutex<()>>);

    impl Receiver {
        // Yields until the corresponding `Sender` gets dropped.
        pub async fn recv(&mut self) {
            let _ = self.0.lock().await;
        }

        // Runs `future` into completion or return immediately when the corresponding `Sender`
        // gets dropped, whichever comes first.
        pub async fn run<F, R>(&mut self, future: F) -> F::Output
        where
            F: Future<Output = Option<R>>,
        {
            tokio::select! {
                value = future => value,
                _ = self.recv() => None,
            }
        }
    }

    pub fn channel() -> (Sender, Receiver) {
        let mutex = Arc::new(Mutex::new(()));
        let guard = mutex
            .clone()
            .try_lock_owned()
            .expect("the mutex shouldn't be locked yet");

        (Sender(guard), Receiver(mutex))
    }
}

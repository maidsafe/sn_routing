// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// TODO: convert the tests in these module to use the Command paradigm.
#[cfg(feature = "mock")]
mod adult;
#[cfg(feature = "mock")]
mod bootstrapping;
#[cfg(feature = "mock")]
mod elder;
#[cfg(feature = "mock")]
mod utils;

use super::{Command, Context, Stage};
use crate::{
    crypto,
    location::DstLocation,
    messages::{BootstrapResponse, Message, Variant},
    peer::Peer,
    rng,
    section::EldersInfo,
    ELDER_SIZE,
};
use anyhow::Result;
use assert_matches::assert_matches;
use ed25519_dalek::Keypair;
use itertools::Itertools;
use std::{
    collections::HashSet,
    iter,
    net::{Ipv4Addr, SocketAddr},
};
use tokio::sync::mpsc;
use xor_name::Prefix;

#[tokio::test]
async fn send_bootstrap_request() -> Result<()> {
    let env = Env::new()?;

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let mut cx = Context::new(event_tx.clone());

    let (node, _) = Stage::bootstrap(
        &mut cx,
        env.transport_config(),
        gen_keypair(),
        Default::default(),
        event_tx,
    )
    .await?;

    let recipients = assert_matches!(
        cx.pop_command(),
        Some(Command::SendBootstrapRequest(recipients)) => recipients
    );
    assert_eq!(recipients, [env.bootstrap_addr]);
    assert!(cx.pop_command().is_none());

    node.handle_command(&mut cx, Command::SendBootstrapRequest(recipients))
        .await?;

    let (recipients, delivery_group_size, message) = assert_matches!(
        cx.pop_command(),
        Some(Command::SendMessage {
            recipients,
            delivery_group_size,
            message,
        }) => (recipients, delivery_group_size, message)
    );
    assert_eq!(recipients, [env.bootstrap_addr]);
    assert_eq!(delivery_group_size, 1);

    let message = Message::from_bytes(&message)?;
    assert_matches!(
        message.variant(),
        Variant::BootstrapRequest(name) => assert_eq!(*name, node.name().await)
    );

    assert!(cx.pop_command().is_none());

    Ok(())
}

#[tokio::test]
async fn receive_bootstrap_request() -> Result<()> {
    let env = Env::new()?;

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let mut cx = Context::new(event_tx.clone());

    let (node, _) = Stage::first_node(
        env.transport_config(),
        gen_keypair(),
        Default::default(),
        event_tx,
    )?;

    let new_node_keypair = gen_keypair();
    let new_node_addr = ([192, 0, 2, 0], 2000).into();

    let message = Message::single_src(
        &new_node_keypair,
        DstLocation::Direct,
        Variant::BootstrapRequest(crypto::name(&new_node_keypair.public)),
        None,
        None,
    )?;

    node.handle_command(
        &mut cx,
        Command::HandleMessage {
            message,
            sender: Some(new_node_addr),
        },
    )
    .await?;

    let (recipients, message) = assert_matches!(
        cx.pop_command(),
        Some(Command::SendMessage {
            recipients,
            message, ..
        }) => (recipients, message)
    );

    assert_eq!(recipients, [new_node_addr]);

    let message = Message::from_bytes(&message)?;
    assert_matches!(
        message.variant(),
        Variant::BootstrapResponse(BootstrapResponse::Join { .. })
    );

    Ok(())
}

#[tokio::test]
async fn receive_bootstrap_response_join() -> Result<()> {
    let env = Env::new()?;

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let mut cx = Context::new(event_tx.clone());

    let (node, _) = Stage::bootstrap(
        &mut cx,
        env.transport_config(),
        gen_keypair(),
        Default::default(),
        event_tx,
    )
    .await?;

    let _ = cx.take_commands();

    let message = Message::single_src(
        &env.elder_keypairs[0],
        DstLocation::Direct,
        Variant::BootstrapResponse(BootstrapResponse::Join {
            elders_info: env.elders_info.clone(),
            section_key: env.section_key,
        }),
        None,
        None,
    )?;
    node.handle_command(
        &mut cx,
        Command::HandleMessage {
            sender: Some(env.elder(0).addr),
            message,
        },
    )
    .await?;

    let (recipients, delivery_group_size, message) = assert_matches!(
        cx.pop_command(),
        Some(Command::SendMessage {
            recipients,
            delivery_group_size,
            message,
        }) => (recipients, delivery_group_size, message)
    );
    assert_eq!(delivery_group_size, env.elders_info.elders.len());
    let expected_recipients: HashSet<_> = env
        .elders_info
        .elders
        .values()
        .map(|peer| &peer.addr)
        .collect();
    let actual_recipients: HashSet<_> = recipients.iter().collect();
    assert_eq!(actual_recipients, expected_recipients);

    let message = Message::from_bytes(&message)?;
    let payload = assert_matches!(message.variant(), Variant::JoinRequest(payload) => payload);
    assert_eq!(payload.section_key, env.section_key);
    assert!(payload.relocate_payload.is_none());

    Ok(())
}

// TODO: add more tests here

fn gen_keypair() -> Keypair {
    let mut rng = rng::new();
    Keypair::generate(&mut rng)
}

// Test environment. Contains info about the rest of the network.
struct Env {
    _bootstrap_endpoint: qp2p::Endpoint,
    // Socket address of the node to bootstrap against.
    bootstrap_addr: SocketAddr,

    // EldersInfo of the assumed section the node under test is a member of.
    elders_info: EldersInfo,
    // Keypairs of all the section elders.
    elder_keypairs: Vec<Keypair>,
    // BLS public key of the section.
    section_key: bls::PublicKey,
}

impl Env {
    fn new() -> Result<Self> {
        let bootstrap_qp2p = qp2p::QuicP2p::with_config(
            Some(qp2p::Config {
                ip: Some(Ipv4Addr::LOCALHOST.into()),
                ..Default::default()
            }),
            Default::default(),
            false,
        )?;
        let bootstrap_endpoint = bootstrap_qp2p.new_endpoint()?;
        let bootstrap_addr = bootstrap_endpoint.local_addr()?;

        let (elders_info, elder_keypairs) = gen_elders_info();

        let secret_key = bls::SecretKey::random();
        let public_key = secret_key.public_key();

        Ok(Self {
            _bootstrap_endpoint: bootstrap_endpoint,
            bootstrap_addr,
            elders_info,
            elder_keypairs,
            section_key: public_key,
        })
    }

    // Peer of the `index`-th elder. Panics if index out of range.
    fn elder(&self, index: usize) -> &Peer {
        self.elders_info
            .elders
            .values()
            .nth(index)
            .expect("elder index our of range")
    }

    // Transport config to use by the node under test.
    fn transport_config(&self) -> qp2p::Config {
        qp2p::Config {
            hard_coded_contacts: iter::once(self.bootstrap_addr).collect(),
            ..Default::default()
        }
    }
}

// Generate random EldersInfo and the corresponding Keypairs.
fn gen_elders_info() -> (EldersInfo, Vec<Keypair>) {
    let mut rng = rng::new();
    let keypairs: Vec<_> = (0..ELDER_SIZE)
        .map(|_| Keypair::generate(&mut rng))
        .sorted_by_key(|keypair| crypto::name(&keypair.public))
        .collect();
    let elders = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            let addr = ([192, 0, 2, 0], 1000 + index as u16).into();
            Peer::new(crypto::name(&keypair.public), addr)
        })
        .map(|p2p_node| (*p2p_node.name(), p2p_node))
        .collect();
    let elders_info = EldersInfo {
        elders,
        prefix: Prefix::default(),
    };

    (elders_info, keypairs)
}

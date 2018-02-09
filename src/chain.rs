// Copyright 2015 MaidSafe.net limited.
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

// FIXME: remove when this module is finished
#![allow(dead_code)]

use block::{Block, PeersAndAge};
use error::RoutingError;
use fs2::FileExt;
use maidsafe_utilities::serialisation;
use network_event::{DataIdentifier, SectionState};
use peer_id::PeerId;
use proof::Proof;
use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use vote::Vote;

// Vote -> Quorum Block -> FullBlock (or nearly full Block + Accusation)

#[allow(unused)]
#[derive(Default, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
pub struct DataChain {
    blocks: Vec<Block<SectionState>>,
    group_size: usize,
    path: Option<PathBuf>,
    valid_peers: Vec<Block<SectionState>>, // save to aid network catastrophic failure and restart.
    data: Vec<Block<DataIdentifier>>,
}

impl DataChain {
    /// Create a new chain backed up on disk
    /// Provide the directory to create the files in
    pub fn create_in_path(path: &PathBuf, group_size: usize) -> io::Result<DataChain> {
        let path = path.join("data_chain");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        // hold a lock on the file for the whole session
        file.lock_exclusive()?;
        Ok(DataChain {
            blocks: Vec::<Block<SectionState>>::default(),
            group_size: group_size,
            path: Some(path),
            valid_peers: Vec::<Block<SectionState>>::default(),
            data: Vec::<Block<DataIdentifier>>::default(),
        })
    }

    /// Open from existing directory
    pub fn from_path(path: &PathBuf) -> Result<DataChain, RoutingError> {
        let path = path.join("data_chain");
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(&path)?;
        // hold a lock on the file for the whole session
        file.lock_exclusive()?;
        let mut buf = Vec::<u8>::new();
        let _ = file.read_to_end(&mut buf)?;
        Ok(serialisation::deserialise::<DataChain>(&buf[..])?)
    }

    /// Create chain in memory from some blocks
    pub fn from_blocks(blocks: Vec<Block<SectionState>>, group_size: usize) -> DataChain {
        DataChain {
            blocks: blocks,
            group_size: group_size,
            path: None,
            valid_peers: Vec::<Block<SectionState>>::default(),
            data: Vec::<Block<DataIdentifier>>::default(),
        }
    }

    /// Write current data chain to supplied path
    pub fn write(&self) -> Result<(), RoutingError> {
        if let Some(path) = self.path.to_owned() {
            let mut file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(false)
                .open(&path.as_path())?;
            return Ok(file.write_all(&serialisation::serialise(&self)?)?);
        }
        Err(RoutingError::CannotWriteFile)
    }

    /// Write current data chain to supplied path
    pub fn write_to_new_path(&mut self, path: PathBuf) -> Result<(), RoutingError> {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(path.as_path())?;
        file.write_all(&serialisation::serialise(&self)?)?;
        self.path = Some(path);
        Ok(file.lock_exclusive()?)
    }

    /// Unlock the lock file
    pub fn unlock(&self) {
        if let Some(ref path) = self.path.to_owned() {
            if let Ok(file) = fs::File::open(path.as_path()) {
                let _ = file.unlock();
            }
        }
    }


    fn add_vote(
        &mut self,
        vote: &Vote<SectionState>,
        peer_id: &PeerId,
    ) -> Option<(SectionState, PeersAndAge)> {
        if !vote.validate_signature(peer_id) {
            return None;
        }

        let pub_key_matches = |x: &Proof| x.peer_id().pub_key() == peer_id.pub_key();
        for blk in &mut self.blocks.iter_mut() {
            if blk.payload() == vote.payload() {
                if blk.proofs().iter().any(pub_key_matches) {
                    info!("duplicate proof");
                    return None;
                }
                // TODO: use proper valid voters list instead of the empty list.
                let _ = blk.add_proof(vote.proof(peer_id).unwrap(), &BTreeSet::new())
                    .unwrap();

                let p_age = PeersAndAge::new(blk.num_proofs(), blk.total_age());
                return Some((blk.payload().clone(), p_age));
            }
        }
        if let Ok(ref mut blk) = Block::new(vote, peer_id) {
            self.blocks.push(blk.clone());
            return Some((
                blk.payload().clone(),
                PeersAndAge::new(1, peer_id.age() as usize),
            ));
        }
        info!("Could not find any block for this proof");
        None
    }



    /// Assumes we trust the first `Block`
    fn validate_quorums(&self) -> bool {
        if let Some(mut prev) = self.blocks.first() {
            for blk in self.blocks.iter().skip(1) {
                // TODO, don't count like this use a loop and check quorum age as well
                if blk.get_peer_ids()
                    .intersection(&prev.get_peer_ids())
                    .count() <= self.group_size / 2
                {
                    return false;
                } else {
                    prev = blk;
                    // TODO check `NetworkEvent` as we may need to add to prev or remove a possible
                    // voter we can probably use a CurrentPeers / SectionState list here to be more
                    // specific. Also which `NetworkEvent`s can follow a sequence, i.e. a lost must
                    // be followed with a promote if its an elder or a merge if peers drops to group
                    // size. Most events will follow a sequence that is allowed. if blocks are out
                    // of sequence when net is running a peer should sequence them properly. Here we
                    // would fail the chain.
                }
            }
            true
        } else {
            false
        }
    }
}

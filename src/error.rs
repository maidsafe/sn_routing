// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use routing::RoutingError;
use std::io;

#[derive(Debug)]
pub enum Error {
    Routing(RoutingError),
    Io(io::Error),
}

impl From<RoutingError> for Error {
    fn from(error: RoutingError) -> Error {
        Error::Routing(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::Io(error)
    }
}

#[derive(Debug)]
pub enum ChunkStoreError {
    // Report Input/Output error.
    Io(::std::io::Error),
}

impl From<::std::io::Error> for ChunkStoreError {
    fn from(error: ::std::io::Error) -> ChunkStoreError {
        ChunkStoreError::Io(error)
    }
}

// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// Mock version of Crust.
pub mod crust;

/// Mock version of Parsec.
#[cfg(feature = "mock_parsec")]
pub(crate) mod parsec;

/// Mock version of Quick-P2P
// TODO: remove this `allow(unused)`
#[allow(unused)]
pub(crate) mod quick_p2p;

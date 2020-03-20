// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod bootstrapping;
mod joining;

pub use self::{
    bootstrapping::Bootstrapping,
    joining::{JoinType, Joining, JOIN_TIMEOUT},
};

#[cfg(feature = "mock_base")]
pub use self::bootstrapping::BOOTSTRAP_TIMEOUT;

// Type to represent the various stages a node goes through during its lifetime.
pub enum Stage {
    Bootstrapping(Bootstrapping),
    Joining(Joining),
}

impl Stage {
    pub fn is_bootstrapping(&self) -> bool {
        matches!(self, Self::Bootstrapping(_))
    }

    pub fn is_joining(&self) -> bool {
        matches!(self, Self::Joining(_))
    }
}

// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod approved;
mod bootstrapping;
mod joining;

pub(crate) use self::{
    approved::{Approved, RelocateParams},
    bootstrapping::{Bootstrapping, JoinParams},
    joining::Joining,
};

#[cfg(feature = "mock")]
pub use self::{bootstrapping::BOOTSTRAP_TIMEOUT, joining::JOIN_TIMEOUT};

// Type to represent the various stages a node goes through during its lifetime.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Stage {
    Bootstrapping(Bootstrapping),
    Joining(Joining),
    Approved(Approved),
    Terminated,
}

impl Stage {
    pub fn approved(&self) -> Option<&Approved> {
        match self {
            Self::Approved(stage) => Some(stage),
            _ => None,
        }
    }

    #[cfg(all(test, feature = "mock"))]
    pub fn approved_mut(&mut self) -> Option<&mut Approved> {
        match self {
            Self::Approved(stage) => Some(stage),
            _ => None,
        }
    }
}

// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Errors in operations involving Core and Vaults
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum ClientError {
    /// Access is denied for a given requester
    AccessDenied,
    /// SAFE Account does not exist for client
    NoSuchAccount,
    /// Attempt to take an account network name that already exists
    AccountExists,
    /// Requested data not found
    NoSuchData,
    /// Attempt to create a mutable data when data with such a name already exists
    DataExists,
    /// Attempt to create/post a data exceeds size limit
    DataTooLarge,
    /// Requested entry not found
    NoSuchEntry,
    /// Exceeded a limit on a number of entries
    TooManyEntries,
    /// Some entry actions are not valid.
    InvalidEntryActions(BTreeMap<Vec<u8>, EntryError>),
    /// Key does not exist
    NoSuchKey,
    /// The list of owner keys is invalid
    InvalidOwners,
    /// Invalid version for performing a given mutating operation. Contains the
    /// current data version.
    InvalidSuccessor(u64),
    /// Invalid Operation such as a POST on ImmutableData
    InvalidOperation,
    /// Wrong invitation token specified by the client
    InvalidInvitation,
    /// Invitation token already used
    InvitationAlreadyClaimed,
    /// Insufficient balance for performing a given mutating operation
    LowBalance,
    /// The loss of sacrificial copies indicates the network as a whole is no longer having
    /// enough space to accept further put request so have to wait for more nodes to join
    NetworkFull,
    /// Network error occurring at Vault level which has no bearing on clients, e.g. serialisation
    /// failure or database failure
    NetworkOther(String),
}

impl<T: Into<String>> From<T> for ClientError {
    fn from(err: T) -> Self {
        ClientError::NetworkOther(err.into())
    }
}

impl Display for ClientError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            ClientError::AccessDenied => write!(f, "Access denied"),
            ClientError::NoSuchAccount => write!(f, "Account does not exist for client"),
            ClientError::AccountExists => write!(f, "Account already exists for client"),
            ClientError::NoSuchData => write!(f, "Requested data not found"),
            ClientError::DataExists => write!(f, "Data given already exists"),
            ClientError::DataTooLarge => write!(f, "Data given is too large"),
            ClientError::NoSuchEntry => write!(f, "Requested entry not found"),
            ClientError::TooManyEntries => write!(f, "Exceeded a limit on a number of entries"),
            ClientError::InvalidEntryActions(ref errors) => {
                write!(f, "Entry actions are invalid: {:?}", errors)
            }
            ClientError::NoSuchKey => write!(f, "Key does not exists"),
            ClientError::InvalidOwners => write!(f, "The list of owner keys is invalid"),
            ClientError::InvalidOperation => write!(f, "Requested operation is not allowed"),
            ClientError::InvalidInvitation => write!(f, "Invitation token not found"),
            ClientError::InvitationAlreadyClaimed => {
                write!(f, "Invitation token has already been used")
            }
            ClientError::InvalidSuccessor(_) => {
                write!(f, "Data given is not a valid successor of stored data")
            }
            ClientError::LowBalance => write!(f, "Insufficient account balance for this operation"),
            ClientError::NetworkFull => write!(f, "Network cannot store any further data"),
            ClientError::NetworkOther(ref error) => write!(f, "Error on Vault network: {}", error),
        }
    }
}

impl Error for ClientError {
    fn description(&self) -> &str {
        match *self {
            ClientError::AccessDenied => "Access denied",
            ClientError::NoSuchAccount => "No such account",
            ClientError::AccountExists => "Account exists",
            ClientError::NoSuchData => "No such data",
            ClientError::DataExists => "Data exists",
            ClientError::DataTooLarge => "Data is too large",
            ClientError::NoSuchEntry => "No such entry",
            ClientError::TooManyEntries => "Too many entries",
            ClientError::InvalidEntryActions(_) => "Invalid entry actions",
            ClientError::NoSuchKey => "No such key",
            ClientError::InvalidOwners => "Invalid owners",
            ClientError::InvalidSuccessor(_) => "Invalid data successor",
            ClientError::InvalidOperation => "Invalid operation",
            ClientError::InvalidInvitation => "Invalid invitation token",
            ClientError::InvitationAlreadyClaimed => "Invitation token already claimed",
            ClientError::LowBalance => "Low account balance",
            ClientError::NetworkFull => "Network full",
            ClientError::NetworkOther(ref error) => error,
        }
    }
}

/// Entry error for `ClientError::InvalidEntryActions`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum EntryError {
    /// Entry does not exists.
    NoSuchEntry,
    /// Entry already exists. Contains the current entry version.
    EntryExists(u64),
    /// Invalid version when updating an entry. Contains the current entry version.
    InvalidSuccessor(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_from_str_literal() {
        fn mutate() -> Result<(), ClientError> {
            Err("Mutation")?
        }

        let err_get = ClientError::from("Get");
        let err_mutation = mutate().unwrap_err();
        match (err_get, err_mutation) {
            (ClientError::NetworkOther(val0), ClientError::NetworkOther(val1)) => {
                assert_eq!(&val0, "Get");
                assert_eq!(&val1, "Mutation");
            }
            err => panic!("Unexpected conversion: {:?}", err),
        }
    }
}

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

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Errors in Get (non-mutating) operations involving Core and Vaults
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, RustcEncodable, RustcDecodable)]
pub enum GetError {
    /// SAFE Account does not exist for client
    NoSuchAccount,
    /// Requested data not found
    NoSuchData,
    /// Network error occurring at Vault level which has no bearing on clients, e.g. serialisation
    /// failure or database failure
    NetworkOther(String),
}

impl<T: Into<String>> From<T> for GetError {
    fn from(err: T) -> Self {
        GetError::NetworkOther(err.into())
    }
}

impl Display for GetError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            GetError::NoSuchAccount => write!(formatter, "Account does not exist for client"),
            GetError::NoSuchData => write!(formatter, "Requested data not found"),
            GetError::NetworkOther(ref error) => {
                write!(formatter, "Error on Vault network: {}", error)
            }
        }
    }
}

impl Error for GetError {
    fn description(&self) -> &str {
        match *self {
            GetError::NoSuchAccount => "No such account",
            GetError::NoSuchData => "No such data",
            GetError::NetworkOther(ref error) => error,
        }
    }
}



/// Errors in Put/Post/Delete (mutating) operations involving Core and Vaults
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, RustcEncodable, RustcDecodable)]
pub enum MutationError {
    /// SAFE Account does not exist for client
    NoSuchAccount,
    /// Attempt to take an account network name that already exists
    AccountExists,
    /// Requested data not found
    NoSuchData,
    /// Attempt to create a mutable data when data with such a name already exists
    DataExists,
    /// Insufficient balance for performing a given mutating operation
    LowBalance,
    /// Invalid successor for performing a given mutating operation, e.g. signature mismatch or
    /// invalid data versioning
    InvalidSuccessor,
    /// Invalid Operation such as a POST on ImmutableData
    InvalidOperation,
    /// The loss of sacrificial copies indicates the network as a whole is no longer having
    /// enough space to accept further put request so have to wait for more nodes to join
    NetworkFull,
    /// Network error occurring at Vault level which has no bearing on clients, e.g. serialisation
    /// failure or database failure
    NetworkOther(String),
}

impl<T: Into<String>> From<T> for MutationError {
    fn from(err: T) -> Self {
        MutationError::NetworkOther(err.into())
    }
}

impl Display for MutationError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            MutationError::NoSuchAccount => write!(formatter, "Account does not exist for client"),
            MutationError::AccountExists => write!(formatter, "Account already exists for client"),
            MutationError::NoSuchData => write!(formatter, "Requested data not found"),
            MutationError::DataExists => write!(formatter, "Data given already exists"),
            MutationError::LowBalance => {
                write!(formatter, "Insufficient account balance for this operation")
            }
            MutationError::InvalidSuccessor => {
                write!(formatter,
                       "Data given is not a valid successor of stored data")
            }
            MutationError::InvalidOperation => {
                write!(formatter, "Requested operation is not allowed")
            }
            MutationError::NetworkFull => {
                write!(formatter, "Network cannot store any further data")
            }
            MutationError::NetworkOther(ref error) => {
                write!(formatter, "Error on Vault network: {}", error)
            }
        }
    }
}

impl Error for MutationError {
    fn description(&self) -> &str {
        match *self {
            MutationError::NoSuchAccount => "No such account",
            MutationError::AccountExists => "Account exists",
            MutationError::NoSuchData => "No such data",
            MutationError::DataExists => "Data exists",
            MutationError::LowBalance => "Low account balance",
            MutationError::InvalidSuccessor => "Invalid data successor",
            MutationError::InvalidOperation => "Invalid operation",
            MutationError::NetworkFull => "Network full",
            MutationError::NetworkOther(ref error) => error,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn conversion_from_str_literal() {
        fn mutate() -> Result<(), MutationError> {
            try!(Err("Mutation"))
        }

        let err_get = GetError::from("Get");
        let err_mutation = mutate().unwrap_err();
        match (err_get, err_mutation) {
            (GetError::NetworkOther(val0), MutationError::NetworkOther(val1)) => {
                assert_eq!(&val0, "Get");
                assert_eq!(&val1, "Mutation");
            }
            err => panic!("Unexpected conversion: {:?}", err),
        }
    }
}

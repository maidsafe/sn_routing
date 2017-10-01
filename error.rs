// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0 This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use maidsafe_utilities::serialisation;
use std::{error, fmt, io};

/// Error types.
///
/// Hopefully `rust_sodium` eventually defines errors properly, otherwise this makes little sense.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum Error {
    Serialisation(serialisation::SerialisationError),
    Io(io::Error),
    Crypto,
    Validation,
    Signature,
    Majority,
    NoLink,
    NoSpace,
    NoFile,
    BadIdentifier,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Serialisation(ref err) => err.fmt(f),
            Error::Io(ref err) => err.fmt(f),
            Error::Crypto => write!(f, "Crypto failure."),
            Error::Validation => write!(f, "Not enough signatures."),
            Error::Signature => write!(f, "Invalid signature."),
            Error::Majority => write!(f, "Not enough signatures for validation."),
            Error::NoLink => write!(f, "Could not get a valid link."),
            Error::NoSpace => write!(f, "Not enough space."),
            Error::NoFile => write!(f, "No file."),
            Error::BadIdentifier => write!(f, "Invalid identifier type."),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Serialisation(ref err) => err.description(),
            Error::Io(ref err) => err.description(),
            Error::Crypto => "Crypto failure.",
            Error::Validation => "Not enough signatures.",
            Error::Signature => "Invalid signature.",
            Error::Majority => "Not enough signatures for validation.",
            Error::NoLink => "Could not get a valid link.",
            Error::NoSpace => "No space.",
            Error::NoFile => "No file.",
            Error::BadIdentifier => "Invalid identifier type.",
        }
    }
}

impl From<io::Error> for Error {
    fn from(orig_error: io::Error) -> Self {
        Error::Io(orig_error)
    }
}

impl From<serialisation::SerialisationError> for Error {
    fn from(orig_error: serialisation::SerialisationError) -> Self {
        Error::Serialisation(orig_error)
    }
}

impl From<()> for Error {
    fn from(_: ()) -> Self {
        Error::Crypto
    }
}

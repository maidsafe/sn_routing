// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{error::RoutingError, Message, NetworkBytes};
use maidsafe_utilities::serialisation;
mod approved;
mod base;

pub(crate) use self::{approved::Approved, base::Base};

pub(crate) fn to_network_bytes(
    message: &Message,
) -> Result<NetworkBytes, (serialisation::SerialisationError, &Message)> {
    #[cfg(not(feature = "mock_serialise"))]
    let result = Ok(NetworkBytes::from(
        serialisation::serialise(message).map_err(|err| (err, message))?,
    ));

    #[cfg(feature = "mock_serialise")]
    let result = Ok(NetworkBytes::new(message.clone()));

    result
}

pub(crate) fn from_network_bytes(data: NetworkBytes) -> Result<Message, RoutingError> {
    #[cfg(not(feature = "mock_serialise"))]
    let result = serialisation::deserialise(&data[..]).map_err(RoutingError::SerialisationError);

    #[cfg(feature = "mock_serialise")]
    let result = Ok((*data).clone());

    result
}

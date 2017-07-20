// Copyright 2017 MaidSafe.net limited.
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

use RoutingError;
use config_file_handler::{self, FileHandler};

/// Configuration for routing
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Config {
    /// Developer options
    pub dev: Option<DevConfig>,
}

/// Extra configuration options intended for developers
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DevConfig {
    /// Disables rate limiting
    pub disable_client_rate_limiter: bool,
    /// Disables requirement to provide a resource proof to bootstrap
    pub disable_resource_proof: bool,
}

/// Reads the default routing config file.
pub fn read_config_file() -> Result<DevConfig, RoutingError> {
    let mut name = config_file_handler::exe_file_stem()?;
    name.push(".routing.config");
    // if the config file is not present, a default one will be generated
    let file_handler = FileHandler::new(&name, false)?;
    let cfg: Config = file_handler.read_file()?;
    Ok(cfg.dev.unwrap_or_else(DevConfig::default))
}

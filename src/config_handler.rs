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
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct Config {
    /// Developer options
    pub dev: Option<DevConfig>,
}

/// Extra configuration options intended for developers
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct DevConfig {
    /// Allow multiple nodes to run on a single machine or LAN
    pub allow_multiple_lan_nodes: bool,
    /// Disables rate limiting and disables single client per IP restriction
    pub disable_client_rate_limiter: bool,
    /// Disables requirement to provide a resource proof to bootstrap
    pub disable_resource_proof: bool,
    /// Overrides default `MIN_SECTION_SIZE`
    pub min_section_size: Option<usize>,
}

/// Reads the routing config file and returns it or a default if this fails
pub fn get_config() -> Config {
    read_config_file().unwrap_or_else(|error| {
        warn!("Failed to parse routing config file: {:?}", error);
        Config::default()
    })
}

fn read_config_file() -> Result<Config, RoutingError> {
    let mut name = config_file_handler::exe_file_stem()?;
    name.push(".routing.config");
    // if the config file is not present, a default one will be generated
    let file_handler = FileHandler::new(&name, false)?;
    Ok(file_handler.read_file()?)
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json;
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    #[test]
    fn parse_sample_config_file() {
        let path = Path::new("sample_config/sample.routing.config").to_path_buf();
        let mut file = unwrap!(File::open(&path), "Error opening {}:", path.display());
        let mut encoded_contents = String::new();
        let _ = unwrap!(
            file.read_to_string(&mut encoded_contents),
            "Error reading {}:",
            path.display()
        );
        let config: Config = unwrap!(
            serde_json::from_str(&encoded_contents),
            "Error parsing {} as JSON:",
            path.display()
        );

        let dev_config = unwrap!(config.dev, "{} is missing `dev` field.", path.display());
        assert!(
            dev_config.min_section_size.is_some(),
            "{} is missing `dev.min_section_size` field.",
            path.display()
        );
    }
}

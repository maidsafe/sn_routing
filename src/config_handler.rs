// Copyright 2016 MaidSafe.net limited.
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

use config_file_handler::{self, FileHandler};
use error::InternalError;
use routing::XorName;
use std::ffi::OsString;

/// Lets a vault configure a wallet address and storage limit.
#[derive(Clone, Debug, RustcDecodable, RustcEncodable)]
pub struct Config {
    /// Used to store the address where SafeCoin will be sent.
    pub wallet_address: Option<XorName>,
    /// Upper limit for allowed network storage on this vault.
    pub max_capacity: Option<u64>, // measured by Bytes
}

impl Default for Config {
    fn default() -> Config {
        Config {
            wallet_address: None,
            max_capacity: None,
        }
    }
}

/// Reads the default vault config file.
#[allow(dead_code)]
pub fn read_config_file() -> Result<Config, InternalError> {
    // if the config file is not present, a default one will be generated
    let file_handler = try!(FileHandler::new(&try!(get_file_name())));
    let cfg = try!(file_handler.read_file());
    Ok(cfg)
}

/// Writes a Vault config file **for use by tests and examples**.
///
/// The file is written to the `current_bin_dir()`
/// with the appropriate file name.
///
/// N.B. This method should only be used as a utility for test and examples.  In normal use cases,
/// the config file should be created by the Vault's installer.
#[cfg(test)]
#[allow(dead_code)]
pub fn write_config_file(config: Config) -> Result<::std::path::PathBuf, InternalError> {
    use rustc_serialize::json;
    use std::fs::File;
    use std::io::Write;

    let mut config_path = try!(config_file_handler::current_bin_dir());
    config_path.push(try!(get_file_name()));
    let mut file = try!(File::create(&config_path));
    try!(write!(&mut file, "{}", json::as_pretty_json(&config)));
    try!(file.sync_all());
    Ok(config_path)
}

fn get_file_name() -> Result<OsString, InternalError> {
    let mut name = try!(config_file_handler::exe_file_stem());
    name.push(".vault.config");
    Ok(name)
}

#[cfg(test)]
mod test {
    #[test]
    fn parse_sample_config_file() {
        use std::path::Path;
        use std::fs::File;
        use std::io::Read;
        use super::Config;
        use rustc_serialize::json;

        let path = Path::new("installer/common/sample.vault.config").to_path_buf();

        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(what) => {
                panic!(format!("Error opening safe_vault.vault.config: {:?}", what));
            }
        };

        let mut encoded_contents = String::new();

        if let Err(what) = file.read_to_string(&mut encoded_contents) {
            panic!(format!("Error reading safe_vault.vault.config: {:?}", what));
        }

        if let Err(what) = json::decode::<Config>(&encoded_contents) {
            panic!(format!("Error parsing safe_vault.vault.config: {:?}", what));
        }
    }
}

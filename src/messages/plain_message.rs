// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::SignableView;
use sn_messaging::node::PlainMessage;

/// Section-source message without signature and proof.
pub trait PlainMessageUtils {
    fn as_signable(&self) -> SignableView;
}

impl PlainMessageUtils for PlainMessage {
    fn as_signable(&self) -> SignableView {
        SignableView {
            dst: &self.dst,
            variant: &self.variant,
        }
    }
}

// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// Information about a member of our section.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub struct MemberInfo {
    pub persona: MemberPersona,
    pub age: u8,
    pub state: MemberState,
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub enum MemberPersona {
    #[allow(unused)]
    Infant,
    #[allow(unused)]
    Adult,
    Elder,
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub enum MemberState {
    Joined,
    // TODO: we should track how long the node has been away. If longer than some limit, remove it
    // from the list. Otherwise we allow it to return.
    #[allow(unused)]
    Left,
}

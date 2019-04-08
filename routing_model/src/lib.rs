// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// This is used two ways: inline tests, and integration tests (with mock).
// There's no point configuring each item which is only used in one of these.

#![allow(dead_code)]
#![allow(unused_imports)]

mod actions;
mod flows_dst;
mod flows_node;
mod flows_src;
mod scenario_tests;
mod state;
mod utilities;

#[macro_use]
extern crate lazy_static;
extern crate unwrap;

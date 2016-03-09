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

#![cfg_attr(feature="clippy", allow(print_stdout))]

pub struct TestGroup {
    name: Option<String>,
    case: Option<String>,
}

impl TestGroup {
    pub fn new(name: &str) -> TestGroup {
        println!("{} ...", name);
        TestGroup {
            name: Some(name.to_owned()),
            case: None,
        }
    }

    pub fn start_case(&mut self, case: &str) {
        if let Some(ref case) = self.case {
            println!("    {} ... ok", case);
        }
        println!("    {} ...", case);
        self.case = Some(case.to_owned());
    }

    pub fn release(&mut self) {
        if let Some(ref case) = self.case {
            println!("    {} ... ok", case);
        }
        if let Some(ref name) = self.name {
            println!("{} ... ok\n", name);
        }
        self.case = None;
        self.name = None;
    }
}

impl Drop for TestGroup {
    fn drop(&mut self) {
        if let Some(ref case) = self.case {
            println!("    {} ... FAILED", case);
        }
        if let Some(ref name) = self.name {
            println!("{} ... FAILED\n", name);
        }
    }
}

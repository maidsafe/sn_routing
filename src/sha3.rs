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

use tiny_keccak::Keccak;

/// Simple wrapper around tiny-keccak
pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut sha3 = Keccak::new_sha3_256();
    sha3.update(data);
    let mut res = [0u8; 32];
    sha3.finalize(&mut res);
    res
}


#[cfg(test)]
mod tests {
    use super::hash;

    #[test]
    fn empty() {
        let res = [];
        let empty_hash = hash(&res);

        let expected = vec![0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47,
                            0x56, 0xa0, 0x61, 0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b,
                            0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a];

        assert_eq!(expected, empty_hash);
    }
    // http://www.di-mgt.com.au/sha_testvectors.html
    #[test]
    fn abc_string() {
        let data: Vec<u8> = From::from("abc");
        let res = hash(&data);

        let expected = vec![0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17,
                            0x2d, 0x6b, 0xd3, 0x90, 0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d,
                            0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32];


        assert_eq!(expected, res);
    }

    #[test]
    fn string() {
        let data: Vec<u8> = From::from("hello");
        let res = hash(&data);

        let expected = vec![0x33, 0x38, 0xbe, 0x69, 0x4f, 0x50, 0xc5, 0xf3, 0x38, 0x81, 0x49,
                            0x86, 0xcd, 0xf0, 0x68, 0x64, 0x53, 0xa8, 0x88, 0xb8, 0x4f, 0x42,
                            0x4d, 0x79, 0x2a, 0xf4, 0xb9, 0x20, 0x23, 0x98, 0xf3, 0x92];

        assert_eq!(expected, res);
    }

}

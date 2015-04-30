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

use std::collections::BTreeMap;

pub struct Frequency<K: Ord + Clone> {
    map: BTreeMap<K, usize>
}

impl<Key: Ord + Clone> Frequency<Key> {
    pub fn new() -> Frequency<Key> {
        Frequency {
            map: BTreeMap::<Key, usize>::new()
        }
    }

    pub fn update(&mut self, key: Key) {
        *self.map.entry(key).or_insert(0) += 1;
    }

    pub fn sort_by_highest(&self) -> Vec<(Key, usize)> {
        let mut kvs = self.to_vector();
        kvs.sort_by(|a,b| b.1.cmp(&a.1));
        kvs
    }

    fn to_vector(&self) -> Vec<(Key, usize)> {
        self.map.iter().map(|(k,v)| (k.clone(), v.clone())).collect::<Vec<_>>()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{thread_rng, Rng};

    #[test]
    fn fill_monotonic_distribution() {
        let mut rng = thread_rng();

        // ensure a monotonic decreasing function
        let domain_low = 0u32;
        let domain_high = 500u32;
        assert!(domain_low < domain_high);
        let mut all_counts : Vec<u32> = Vec::with_capacity(3000); // simple approx upperbound
        for _ in 0..100 {
            let x : u32 = rng.gen_range(domain_low, domain_high);
            if all_counts.contains(&x) { continue; } // avoid double counting
            let fx : f64 = x.clone() as f64;
            // use monotonic descending range of gaussian
            let y : f64 = 30f64 * (- (fx.powi(2i32) / 100000f64)).exp();
            let count : usize = y.trunc() as usize + 1;
            // duplicate the keys for
            for _ in 0usize..count { all_counts.push(x.clone()); };
        };

        // shuffle duplicated keys
        rng.shuffle(&mut all_counts[..]);
        let mut freq = Frequency::new();
        for occurance in all_counts {
            // and register each key multiple times in random order
            freq.update(occurance);
        };
        // sort the counts
        let ordered_counts = freq.sort_by_highest();
        let mut max_count = 31usize;
        let mut min_x = 0u32;
        for value in ordered_counts {
            let fx : f64 = value.0.clone() as f64;
            let y : f64 = 30f64 * (- (fx.powi(2i32) / 100000f64)).exp();
            let count : usize = y.trunc() as usize + 1;
            // because we started with random keys whos occurance monotonically decreased
            // for increasing key, the keys should now increase, as the count increases.
            assert!(value.0 >= min_x);
            assert_eq!(value.1, count);
            assert!(value.1 <= max_count);
            min_x = value.0.clone();
            max_count = value.1.clone();
        };
    }
}

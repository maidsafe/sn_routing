
use std::collections::BTreeMap;

pub struct Histogram<K: Ord + Clone> {
    map: BTreeMap<K, usize>
}

impl<Key: Ord + Clone> Histogram<Key> {
    pub fn new() -> Histogram<Key> {
        Histogram {
            map: BTreeMap::<Key, usize>::new()
        }
    }

    pub fn update(&mut self, key: Key) {
        *self.map.entry(key).or_insert(0) += 1;
    }

    pub fn sort_by_highest(&self) -> Vec<(Key, usize)> {
        let mut kvs = self.map.iter().map(|(k,v)| (k.clone(), v.clone())).collect::<Vec<_>>();
        kvs.sort_by(|a,b| b.1.cmp(&a.1));
        kvs
    }
}

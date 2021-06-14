// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod item;

use self::item::Item;
use itertools::Itertools;
use std::collections::BTreeMap;
use std::hash::Hash;
use std::time::Duration;
use tokio::sync::RwLock;

/// A [`BTreeMap`]-backed cache supporting capacity- and duration-based expiry.
#[derive(Debug)]
pub struct Cache<T, V>
where
    T: Hash + Eq + Copy,
{
    items: RwLock<BTreeMap<T, Item<V>>>,
    item_duration: Option<Duration>,
    capacity: usize,
}

#[allow(clippy::len_without_is_empty)]
impl<T, V> Cache<T, V>
where
    T: Ord + Hash + Copy,
{
    /// Creating capacity based `Cache`.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            items: RwLock::new(BTreeMap::new()),
            item_duration: None,
            capacity,
        }
    }

    /// Creating time based `Cache`.
    pub fn with_expiry_duration(duration: Duration) -> Self {
        Self {
            items: RwLock::new(BTreeMap::new()),
            item_duration: Some(duration),
            capacity: usize::MAX,
        }
    }

    /// Creating dual-feature capacity and time based `Cache`.
    pub fn with_expiry_duration_and_capacity(duration: Duration, capacity: usize) -> Self {
        Self {
            items: RwLock::new(BTreeMap::new()),
            item_duration: Some(duration),
            capacity,
        }
    }

    /// Returns the number of items in the cache.
    pub async fn len(&self) -> usize {
        self.items.read().await.len()
    }

    /// Returns `true` if the cache contains no items.
    pub async fn is_empty(&self) -> bool {
        self.items.read().await.is_empty()
    }

    /// Returns the number of items in the cache that match the given predicate.
    pub async fn count<P>(&self, predicate: P) -> usize
    where
        P: FnMut(&(&T, &Item<V>)) -> bool,
    {
        self.items.read().await.iter().filter(predicate).count()
    }

    /// Get a value from the cache if one is set and not expired.
    ///
    /// A clone of the value is returned, so this is only implemented when `V: Clone`.
    pub async fn get(&self, key: &T) -> Option<V>
    where
        T: Eq + Hash,
        V: Clone,
    {
        self.items
            .read()
            .await
            .get(key)
            .filter(|&item| !item.expired())
            .map(|k| k.object.clone())
    }

    /// Set a value in the cache and return the previous value, if any.
    ///
    /// This will override an existing value for the same key, if there is one. `custom_duration`
    /// can be set to override `self.item_duration`. If the new item causes the cache to exceed its
    /// capacity, the oldest entry in the cache will be removed.
    pub async fn set(&self, key: T, value: V, custom_duration: Option<Duration>) -> Option<V>
    where
        T: Eq + Hash + Clone,
    {
        let replaced = self
            .items
            .write()
            .await
            .insert(
                key,
                Item::new(value, custom_duration.or(self.item_duration)),
            )
            .and_then(|item| (!item.expired()).then(|| item.object));
        self.remove_expired().await;
        self.drop_excess().await;
        replaced
    }

    /// Remove expired items from the cache storage.
    pub async fn remove_expired(&self) {
        let expired_keys: Vec<_>;
        {
            let read_items = self.items.read().await;
            expired_keys = read_items
                .iter()
                .filter(|(_, item)| item.expired())
                .map(|(key, _)| *key)
                .collect();
        }

        for key in expired_keys {
            let _ = self.items.write().await.remove(&key);
        }
    }

    /// Remove items that exceed capacity, oldest first.
    async fn drop_excess(&self) {
        let len = self.len().await;
        if len > self.capacity {
            let excess = len - self.capacity;
            let excess_keys: Vec<_>;
            {
                let read_items = self.items.read().await;
                let mut items = read_items.iter().collect_vec();

                // reversed sort
                items.sort_by(|(_, item_a), (_, item_b)| item_b.elapsed().cmp(&item_a.elapsed()));

                // take the excess
                excess_keys = items.iter().take(excess).map(|(key, _)| **key).collect();
            }
            for key in excess_keys {
                let _ = self.items.write().await.remove(&key);
            }
        }
    }

    /// Remove an item from the cache, returning the removed value.
    pub async fn remove(&self, key: &T) -> Option<V>
    where
        T: Eq + Hash,
    {
        self.items.write().await.remove(key).map(|item| item.object)
    }

    /// Clear the cache, removing all items.
    pub async fn clear(&self) {
        self.items.write().await.clear()
    }
}

#[cfg(test)]
mod tests {
    use crate::cache::Cache;
    use std::time::Duration;

    const KEY: i8 = 0;
    const VALUE: &str = "VALUE";

    #[tokio::test]
    async fn set_and_get_value_with_default_duration() {
        let cache = Cache::with_expiry_duration(Duration::from_secs(2));
        let _ = cache.set(KEY, VALUE, None).await;
        let value = cache.get(&KEY).await;
        assert_eq!(value, Some(VALUE), "value was not found in cache");
    }

    #[tokio::test]
    async fn set_and_get_value_without_duration() {
        let cache = Cache::with_capacity(usize::MAX);
        let _ = cache.set(KEY, VALUE, None).await;
        let value = cache.get(&KEY).await;
        assert_eq!(value, Some(VALUE), "value was not found in cache");
    }

    #[tokio::test]
    async fn set_and_get_value_with_custom_duration() {
        let cache = Cache::with_expiry_duration(Duration::from_secs(0));
        let _ = cache.set(KEY, VALUE, Some(Duration::from_secs(2))).await;
        let value = cache.get(&KEY).await;
        assert_eq!(value, Some(VALUE), "value was not found in cache");
    }

    #[tokio::test]
    async fn set_do_not_get_expired_value() {
        let cache = Cache::with_expiry_duration(Duration::from_secs(0));
        let _ = cache.set(KEY, VALUE, None).await;
        let value = cache.get(&KEY).await;
        assert!(value.is_none(), "found expired value in cache");
    }

    #[tokio::test]
    async fn set_do_not_return_expired_value() {
        let timeout = Duration::from_millis(1);
        let cache = Cache::with_expiry_duration(timeout);
        let _ = cache.set(KEY, VALUE, None).await;
        tokio::time::sleep(timeout).await;
        let value = cache.get(&KEY).await;
        assert!(value.is_none(), "found expired value in cache");
        let value = cache.set(KEY, VALUE, None).await;
        assert!(value.is_none(), "exposed expired value from cache");
    }

    #[tokio::test]
    async fn set_replace_existing_value() {
        const NEW_VALUE: &str = "NEW_VALUE";
        let cache = Cache::with_expiry_duration(Duration::from_secs(2));
        let _ = cache.set(KEY, VALUE, None).await;
        let _ = cache.set(KEY, NEW_VALUE, None).await;
        let value = cache.get(&KEY).await;
        assert_eq!(value, Some(NEW_VALUE), "value was not found in cache");
    }

    #[tokio::test]
    async fn remove_expired_item() {
        let cache = Cache::with_expiry_duration(Duration::from_secs(0));
        assert!(cache.set(KEY, VALUE, None).await.is_none());
        cache.remove_expired().await;
        assert!(
            cache.items.read().await.get(&KEY).is_none(),
            "found expired value in cache"
        );
    }

    #[tokio::test]
    async fn remove_expired_do_not_remove_not_expired_item() {
        let cache = Cache::with_expiry_duration(Duration::from_secs(2));
        let _ = cache.set(KEY, VALUE, None).await;
        cache.remove_expired().await;
        assert!(
            cache.items.read().await.get(&KEY).is_some(),
            "could not find not expired item in cache"
        );
    }

    #[tokio::test]
    async fn clear_not_expired_item() {
        let cache = Cache::with_expiry_duration(Duration::from_secs(2));
        let _ = cache.set(KEY, VALUE, None).await;
        cache.clear().await;
        assert!(
            cache.items.read().await.get(&KEY).is_none(),
            "found item in cache"
        );
    }

    #[tokio::test]
    async fn remove_remove_expired_item() {
        let cache = Cache::with_expiry_duration(Duration::from_secs(2));
        let _ = cache.set(KEY, VALUE, None).await;
        assert!(
            cache.remove(&KEY).await.is_some(),
            "none returned from removing existing value"
        );
        assert!(
            cache.items.read().await.get(&KEY).is_none(),
            "found not expired item in cache"
        );
    }

    #[tokio::test]
    async fn remove_return_none_if_not_found() {
        let cache: Cache<i8, &str> = Cache::with_expiry_duration(Duration::from_secs(2));
        assert!(
            cache.remove(&KEY).await.is_none(),
            "some value was returned from remove"
        );
    }

    #[tokio::test]
    async fn drop_excess_entry_zero_entry() {
        let cache = Cache::with_capacity(0);
        let _ = cache.set(KEY, VALUE, None).await;
        assert!(cache.get(&KEY).await.is_none());
    }

    #[tokio::test]
    async fn drop_excess_entry_one_entry() {
        let cache = Cache::with_capacity(1);
        let _ = cache.set(KEY, VALUE, None).await;
        let key: i8 = 1;
        let value: &str = "hello";
        let _ = cache.set(key, value, None).await;
        assert!(cache.get(&KEY).await.is_none());
        assert_eq!(cache.get(&key).await, Some(value));
    }
}

// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod item;

use self::item::Item;
use std::collections::BTreeMap;
use std::hash::Hash;
use std::time::Duration;
use tokio::sync::RwLock;

///
#[derive(Debug)]
pub struct Cache<T, V>
where
    T: Hash + Eq,
{
    items: RwLock<BTreeMap<T, Item<V>>>,
    item_duration: Option<Duration>,
}

#[allow(clippy::len_without_is_empty)]
impl<T, V> Cache<T, V>
where
    T: Ord + Hash,
{
    ///
    pub fn new(item_duration: Option<Duration>) -> Self {
        Cache {
            items: RwLock::new(BTreeMap::new()),
            item_duration,
        }
    }

    ///
    pub async fn len(&self) -> usize {
        self.items.read().await.len()
    }

    ///
    pub async fn is_empty(&self) -> bool {
        self.items.read().await.is_empty()
    }

    ///
    pub async fn count<P>(&self, predicate: P) -> usize
    where
        P: FnMut(&(&T, &Item<V>)) -> bool,
    {
        self.items.read().await.iter().filter(predicate).count()
    }

    ///
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

    ///
    pub async fn set(&self, key: T, value: V, custom_duration: Option<Duration>) -> Option<V>
    where
        T: Eq + Hash,
    {
        self.items
            .write()
            .await
            .insert(
                key,
                Item::new(value, custom_duration.or(self.item_duration)),
            )
            .map(|item| item.object)
    }

    ///
    pub async fn remove_expired(&self)
    where
        T: Eq + Hash + Clone,
    {
        let expired_keys: Vec<T> = self
            .items
            .read()
            .await
            .iter()
            .filter(|(_, item)| item.expired())
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired_keys {
            let _ = self.items.write().await.remove(&key);
        }
    }

    ///
    pub async fn remove(&self, key: &T) -> Option<V>
    where
        T: Eq + Hash,
    {
        self.items.write().await.remove(key).map(|item| item.object)
    }

    ///
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
        let cache = Cache::new(Some(Duration::from_secs(2)));
        let _ = cache.set(KEY, VALUE, None).await;
        let value = cache.get(&KEY).await;
        assert_eq!(value, Some(VALUE), "value was not found in cache");
    }

    #[tokio::test]
    async fn set_and_get_value_without_duration() {
        let cache = Cache::new(None);
        let _ = cache.set(KEY, VALUE, None).await;
        let value = cache.get(&KEY).await;
        assert_eq!(value, Some(VALUE), "value was not found in cache");
    }

    #[tokio::test]
    async fn set_and_get_value_with_custom_duration() {
        let cache = Cache::new(Some(Duration::from_secs(0)));
        let _ = cache.set(KEY, VALUE, Some(Duration::from_secs(2))).await;
        let value = cache.get(&KEY).await;
        assert_eq!(value, Some(VALUE), "value was not found in cache");
    }

    #[tokio::test]
    async fn set_do_not_get_expired_value() {
        let cache = Cache::new(Some(Duration::from_secs(0)));
        let _ = cache.set(KEY, VALUE, None).await;
        let value = cache.get(&KEY).await;
        assert!(value.is_none(), "found expired value in cache");
    }

    #[tokio::test]
    async fn set_replace_existing_value() {
        const NEW_VALUE: &str = "NEW_VALUE";
        let cache = Cache::new(Some(Duration::from_secs(2)));
        let _ = cache.set(KEY, VALUE, None).await;
        let _ = cache.set(KEY, NEW_VALUE, None).await;
        let value = cache.get(&KEY).await;
        assert_eq!(value, Some(NEW_VALUE), "value was not found in cache");
    }

    #[tokio::test]
    async fn remove_expired_item() {
        let cache = Cache::new(Some(Duration::from_secs(0)));
        let _ = cache.set(KEY, VALUE, None).await;
        cache.remove_expired().await;
        assert!(
            cache.items.read().await.get(&KEY).is_none(),
            "found expired value in cache"
        );
    }

    #[tokio::test]
    async fn remove_expired_do_not_remove_not_expired_item() {
        let cache = Cache::new(Some(Duration::from_secs(2)));
        let _ = cache.set(KEY, VALUE, None).await;
        cache.remove_expired().await;
        assert!(
            cache.items.read().await.get(&KEY).is_some(),
            "could not find not expired item in cache"
        );
    }

    #[tokio::test]
    async fn clear_not_expired_item() {
        let cache = Cache::new(Some(Duration::from_secs(2)));
        let _ = cache.set(KEY, VALUE, None).await;
        cache.clear().await;
        assert!(
            cache.items.read().await.get(&KEY).is_none(),
            "found item in cache"
        );
    }

    #[tokio::test]
    async fn remove_remove_expired_item() {
        let cache = Cache::new(Some(Duration::from_secs(2)));
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
        let cache: Cache<i8, &str> = Cache::new(Some(Duration::from_secs(2)));
        assert!(
            cache.remove(&KEY).await.is_none(),
            "some value was returned from remove"
        );
    }
}

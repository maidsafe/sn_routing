use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Item<T> {
    pub object: T,
    expiry: Option<Instant>,
}

impl<T> Item<T> {
    pub fn new(object: T, item_duration: Option<Duration>) -> Self {
        let expiry = item_duration.map(|duration| Instant::now() + duration);
        Item { object, expiry }
    }

    pub fn expired(&self) -> bool {
        self.expiry
            .map(|expiry| expiry < Instant::now())
            .unwrap_or(false)
    }

    pub fn elapsed(&self) -> u128 {
        self.expiry
            .map(|expiry| Instant::now() - expiry)
            .unwrap_or_default()
            .as_millis()
    }
}

#[cfg(test)]
mod tests {
    use super::Item;
    use std::time::Duration;

    const OBJECT: &str = "OBJECT";

    #[tokio::test]
    async fn not_expired_when_duration_is_none() {
        let item = Item::new(OBJECT, None);
        assert_eq!(item.expired(), false);
    }

    #[tokio::test]
    async fn expired_when_duration_is_zero() {
        let item = Item::new(OBJECT, Some(Duration::new(0, 0)));
        assert_eq!(item.expired(), true);
    }
}

use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Item<T> {
    pub object: T,
    time: Option<Time>,
}

#[derive(Clone, Copy, Debug)]
struct Time {
    pub(crate) start: Instant,
    pub(crate) expiry: Instant,
}

impl<T> Item<T> {
    pub fn new(object: T, item_duration: Option<Duration>) -> Self {
        let time = item_duration.map(|duration| {
            let start = Instant::now();
            Time {
                start,
                expiry: start + duration,
            }
        });
        Item { object, time }
    }

    pub fn expired(&self) -> bool {
        self.time
            .map(|time| time.expiry < Instant::now())
            .unwrap_or(false)
    }

    pub fn elapsed(&self) -> u128 {
        self.time
            .map(|time| Instant::now() - time.start)
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
        tokio::time::sleep(Duration::new(0, 0)).await;
        assert_eq!(item.expired(), true);
    }
}

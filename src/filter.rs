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

pub type ClaimantFilter = ::sodiumoxide::crypto::sign::Signature;
pub type RoutingMessageFilter = ::sodiumoxide::crypto::hash::sha256::Digest;

/// Filter combines a double filter.  The first layer validates that this exact message, as sent by
/// the claimant has not been seen before.  The second layer validates that the routing message
/// (which is content and source plus destination) is not already already resolved and as such
/// should no longer be handled.
pub struct Filter {
    claimant_filter: ::message_filter::MessageFilter<ClaimantFilter>,
    message_filter: ::message_filter::MessageFilter<RoutingMessageFilter>,
}

impl Filter {
    /// Set up a new filter with a exipry duration
    pub fn with_expiry_duration(duration: ::time::Duration) -> Filter {
        Filter {
            claimant_filter: ::message_filter::MessageFilter::with_expiry_duration(duration),
            message_filter: ::message_filter::MessageFilter::with_expiry_duration(duration),
        }
    }

    /// Returns true if this message is to be processed.  It will check if the signature of the
    /// message has been seen before, which filters on repeated signed messages.  If this is a new
    /// signed message, it will store the signature to the filter.  Secondly the hash of the
    /// contained routing message is calculated and checked.
    pub fn check(&mut self, signed_message: &::messages::SignedMessage) -> bool {

        // if the signature has been stored, we have processed this message before
        if self.claimant_filter.check(signed_message.signature()) { return false; };
        // add signature to filter
        self.claimant_filter.add(signed_message.signature().clone());

        let digest = match ::utils::encode(signed_message.get_routing_message()) {
            Ok(bytes) => ::sodiumoxide::crypto::hash::sha256::hash(&bytes[..]),
            Err(_) => return false,
        };
        // already get the return value, but continue processing the analytics
        let blocked = self.message_filter.check(&digest);

        // TODO (ben 24/08/2015) calculate the effective group size to set the
        // accumulator threshold

        !blocked
    }

    /// Block adds the digest of the routing message to the message blocker.  A blocked message will
    /// be held back by the filter, regardless of the claimant.
    pub fn block(&mut self, digest: RoutingMessageFilter) {

        self.message_filter.add(digest);
    }

    /// Generate the SHA256 digest of the routing message.  If it fails to encode the
    /// routing message, None is returned.
    pub fn message_digest(routing_message: &::messages::RoutingMessage)
        -> Option<RoutingMessageFilter> {

        match ::utils::encode(routing_message) {
            Ok(bytes) => Some(::sodiumoxide::crypto::hash::sha256::hash(&bytes[..])),
            Err(_) => None,
        }
    }
}

pub struct RunningAverage {
    average: f64,
    block_average: f64,
    counter: u32,
    block_counter: u32,
    block_size: u32,
}

impl RunningAverage {
    pub fn new(block_size: u32) -> RunningAverage {
        RunningAverage {
            average: 0f64,
            block_average: 0f64,
            counter: 0u32,
            block_counter: 0u32,
            block_size: block_size,
        }
    }

    pub fn add_value(&mut self, value: f64) -> f64 {
        if self.counter == self.block_size {
            let next_block: f64 = self.block_counter as f64 + 1f64;
            let block_weight: f64 = (self.block_counter as f64) / next_block;
            let new_block_average: f64 = self.average / next_block
                + block_weight * self.block_average;
            self.block_average = new_block_average.clone();
            self.block_counter += 1u32;
            self.counter = 0u32;
            self.average = 0f64;
        }
        let next: f64 = self.counter as f64 + 1f64;
        let weight: f64 = (self.counter as f64) / next;
        let new_average: f64 = value / next + weight * self.average;
        self.average = new_average.clone();
        self.counter += 1u32;
        // FIXME (ben 11/9/2015) to ensure a smoother transition over blocks the exact average
        // can be calculated, but this might induce new numerical problems with the accuracy
        // of the weighting, so for now this largely works for our purposes with an appropriate
        // block size chosen bigger than the range of the expected variable you will be measuring.
        if self.block_counter > 0 {
            self.block_average.clone()
        } else {
            new_average.clone()
        }
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn filter_check_before_duration_end() {
        let duration = ::time::Duration::seconds(3);
        let mut filter = super::Filter::with_expiry_duration(duration);
        let claimant = ::types::Address::Node(::test_utils::Random::generate_random());
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message =
            ::test_utils::messages_util::arbitrary_routing_message(&keys.0, &keys.1);
        let signed_message =
            ::messages::SignedMessage::new(claimant.clone(), routing_message.clone(), &keys.1);
        let signed_message = signed_message.unwrap();

        assert!(filter.check(&signed_message));
        assert!(!filter.check(&signed_message));
    }

    #[test]
    fn filter_check_after_duration_end() {
        let duration = ::time::Duration::milliseconds(1);
        let mut filter = super::Filter::with_expiry_duration(duration);
        let claimant = ::types::Address::Node(::test_utils::Random::generate_random());
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message =
            ::test_utils::messages_util::arbitrary_routing_message(&keys.0, &keys.1);
        let signed_message =
            ::messages::SignedMessage::new(claimant.clone(), routing_message.clone(), &keys.1);
        let signed_message = signed_message.unwrap();

        assert!(filter.check(&signed_message));
        ::std::thread::sleep_ms(2);
        assert!(filter.check(&signed_message));
    }

    #[test]
    fn filter_check_message_digest() {
        let duration = ::time::Duration::seconds(3);
        let mut filter = super::Filter::with_expiry_duration(duration);
        let claimant = ::types::Address::Node(::test_utils::Random::generate_random());
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message =
            ::test_utils::messages_util::arbitrary_routing_message(&keys.0, &keys.1);
        let signed_message =
            ::messages::SignedMessage::new(claimant.clone(), routing_message.clone(), &keys.1);
        let signed_message = signed_message.unwrap();

        assert!(filter.check(&signed_message));

        let signed_message_routing_message = signed_message.get_routing_message();
        let encode_message = ::utils::encode(signed_message_routing_message);

        assert!(encode_message.is_ok());

        let encode_message = encode_message.unwrap();
        let message_digest = ::sodiumoxide::crypto::hash::sha256::hash(&encode_message[..]);
        let filter_message_digest = super::Filter::message_digest(&routing_message);

        assert!(filter_message_digest.is_some());

        let filter_message_digest = filter_message_digest.unwrap();

        assert_eq!(filter_message_digest, message_digest);
    }

    #[test]
    fn filter_block() {
        let duration = ::time::Duration::seconds(3);
        let mut filter = super::Filter::with_expiry_duration(duration);
        let claimant = ::types::Address::Node(::test_utils::Random::generate_random());
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message =
            ::test_utils::messages_util::arbitrary_routing_message(&keys.0, &keys.1);
        let signed_message =
            ::messages::SignedMessage::new(claimant.clone(), routing_message.clone(), &keys.1);
        let signed_message = signed_message.unwrap();
        let encode_message = ::utils::encode(&routing_message);

        assert!(encode_message.is_ok());

        let encode_message = encode_message.unwrap();
        let message_digest = ::sodiumoxide::crypto::hash::sha256::hash(&encode_message[..]);

        filter.block(message_digest);

        assert!(!filter.check(&signed_message));
    }

    #[test]
    fn running_average_exact() {
        // import the trait
        use ::rand::Rng;

        let mut rng = ::rand::thread_rng();
        let mut running_average = super::RunningAverage::new(1000u32);
        let average = |set: &Vec<f64>| {
            let sum = set.iter().fold(0f64, |acc, &item| acc + &item);
            sum / (set.len() as f64) };
        let mut set: Vec<f64> = Vec::new();
        for i in 0..5000u32 {
            let new_value = rng.gen::<u8>() as f64;
            set.push(new_value.clone());
            let result = running_average.add_value(new_value);
            let average = average(&set);
            if average > 0.0000001f64 {
                let error = (1f64 - (result / average)).abs();
                assert!(error < 0.05f64);
            }
        }
    }

    #[test]
    fn running_average_long() {
        // import the trait
        use ::rand::Rng;
        let mut rng = ::rand::thread_rng();
        let mut running_average = super::RunningAverage::new(1000u32);
        for i in 0..100000u32 {
            let new_value = rng.gen::<u8>() as f64;
            let _ = running_average.add_value(new_value);
        }
        let new_value = rng.gen::<u8>() as f64;
        let result = running_average.add_value(new_value);
        let error = (1f64 - (result / 127.5f64)).abs();
        assert!(error < 0.01f64);
    }
}

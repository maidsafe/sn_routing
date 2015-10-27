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
#[allow(unused)]
pub struct Filter {
    claimant_filter: ::message_filter::MessageFilter<ClaimantFilter>,
    message_filter: ::message_filter::MessageFilter<RoutingMessageFilter>,
    threshold: SimpleThresholdCalculator,
}

impl Filter {
    /// Set up a new filter with a exipry duration
    pub fn with_expiry_duration(duration: ::time::Duration) -> Filter {
        Filter {
            claimant_filter: ::message_filter::MessageFilter::with_expiry_duration(duration),
            message_filter: ::message_filter::MessageFilter::with_expiry_duration(duration),
            threshold: SimpleThresholdCalculator::new(10000u16, ::types::QUORUM_SIZE / 2 + 1 ),
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
        // TODO (ben 17/09/2015) the results from the threshold calculations are not yet used
        // as such these are currently manually deactivated
        // if signed_message.get_routing_message().from_authority.is_group() {
        //     self.threshold.hit_message(blocked); };
        !blocked
    }

    /// Block adds the digest of the routing message to the message blocker.  A blocked message will
    /// be held back by the filter, regardless of the claimant.
    pub fn block(&mut self, routing_message: &::messages::RoutingMessage) {

        let digest = match ::utils::encode(routing_message) {
            Ok(bytes) => ::sodiumoxide::crypto::hash::sha256::hash(&bytes[..]),
            Err(_) => return,
        };

        // TODO (ben 17/09/2015) the results from the threshold calculations are not yet used
        // as such these are currently manually deactivated
        // if routing_message.from_authority.is_group()
        //     && !self.message_filter.check(&digest) {
        //     self.threshold.hit_uniquemessage();
        // };
        self.message_filter.add(digest);
    }
}

#[allow(unused)]
pub struct SimpleThresholdCalculator {
    total_messages: u32,
    total_blockedmessages: u32,
    total_uniquemessages: u32,
    blocked_percentage: RunningAverage,
    multiplicity: RunningAverage,
    cap: u32,
    current_threshold: usize,
}

#[allow(unused)]
impl SimpleThresholdCalculator {
    /// Start a new calculator.
    pub fn new(cap: u16, start_threshold: usize) -> SimpleThresholdCalculator {
        SimpleThresholdCalculator {
            total_messages: 0u32,
            total_blockedmessages: 0u32,
            total_uniquemessages: 0u32,
            blocked_percentage: RunningAverage::new(10000u32),
            multiplicity: RunningAverage::new(10000u32),
            cap: cap as u32,
            current_threshold: start_threshold,
        }
    }

    /// Register a new blocked message.
    pub fn hit_message(&mut self, blocked: bool) {
        if blocked { self.total_blockedmessages += 1u32; };
        self.total_messages += 1u32;
        // let debug_average = self.total_blockedmessages as f64 / self.total_messages as f64;
        // println!("BLOCKED {:?}% of group messages ({:?}/{:?})", (debug_average * 100f64).round(),
        //     self.total_blockedmessages, self.total_messages);
        if self.total_messages >= self.cap {
            self.calculate_average();
        }
    }

    /// Register a new unique message.
    pub fn hit_uniquemessage(&mut self) {
        self.total_uniquemessages += 1u32;
        let message_multiplicity = self.total_messages as f64 / self.total_uniquemessages as f64;
        // let debug_blocked = self.total_blockedmessages as f64 / self.total_messages as f64;
        // let debug_threshold = message_multiplicity * debug_blocked;
        // println!("MULTIPLICITY {:?} for group messages ({:?}/{:?})",
        //     (message_multiplicity * 100f64).round() / 100f64,
        //     self.total_messages, self.total_uniquemessages);
        // println!("DEBUG THRESHOLD would be {:?} - NOT EFFECTUATED",
        //     debug_threshold);
        // println!("RUNNING AVERAGE BLOCKED {:?} - MULTIPLICITY {:?}",
        //     self.blocked_percentage.get_average(),
        //     self.multiplicity.get_average());
    }

    fn calculate_average(&mut self) {
        let average_blocked: f64 = self.total_blockedmessages as f64
            / self.total_messages as f64;
        let running_average = self.blocked_percentage.add_value(average_blocked);

        if self.total_uniquemessages > 0u32 {
            let message_multiplicity = self.total_messages as f64
                / self.total_uniquemessages as f64;
            let running_multiplicity = self.multiplicity.add_value(message_multiplicity);
        };
        self.total_messages = 0u32;
        self.total_blockedmessages = 0u32;
        self.total_uniquemessages = 0u32;
    }
}

#[allow(unused)]
pub struct RunningAverage {
    average: f64,
    block_average: f64,
    counter: u32,
    block_counter: u32,
    block_size: u32,
}

#[allow(unused)]
impl RunningAverage {

    /// Create a new running average object.
    pub fn new(block_size: u32) -> RunningAverage {
        RunningAverage {
            average: 0f64,
            block_average: 0f64,
            counter: 0u32,
            block_counter: 0u32,
            block_size: block_size,
        }
    }

    /// Add a new value to the running average.
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

    /// Return the current running average.
    pub fn get_average(&self) -> f64 {
        if self.block_counter > 0 {
            self.block_average.clone()
        } else {
            self.average.clone()
        }
    }
}

#[cfg(test)]
mod test {
    use rand;

    #[test]
    fn filter_check_before_duration_end() {
        let duration = ::time::Duration::seconds(3);
        let mut filter = super::Filter::with_expiry_duration(duration);
        let claimant = ::types::Address::Node(rand::random());
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
        let claimant = ::types::Address::Node(rand::random());
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
    fn filter_block() {
        let duration = ::time::Duration::seconds(3);
        let mut filter = super::Filter::with_expiry_duration(duration);
        let claimant = ::types::Address::Node(rand::random());
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let routing_message =
            ::test_utils::messages_util::arbitrary_routing_message(&keys.0, &keys.1);
        let signed_message =
            ::messages::SignedMessage::new(claimant.clone(), routing_message.clone(), &keys.1);
        let signed_message = signed_message.unwrap();

        filter.block(signed_message.get_routing_message());

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
        for _ in 0..5000u32 {
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
        for _ in 0..100000u32 {
            let new_value = rng.gen::<u8>() as f64;
            let _ = running_average.add_value(new_value);
        }
        let new_value = rng.gen::<u8>() as f64;
        let result = running_average.add_value(new_value);
        let error = (1f64 - (result / 127.5f64)).abs();
        assert!(error < 0.01f64);
    }
}

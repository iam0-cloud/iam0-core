use std::time::{Duration, SystemTime};
use rand::Rng;
use rand::rngs::ThreadRng;

const TIMESTAMP_BITS: u8 = 64;
const SEQUENCE_BITS: u8 = 12;
const SERVICE_ID_BITS: u8 = 16;
const WORKER_ID_BITS: u8 = 16;
const RANDOM_BITS: u8 = 20;

const _: () = assert!(TIMESTAMP_BITS + SEQUENCE_BITS + SERVICE_ID_BITS + WORKER_ID_BITS + RANDOM_BITS == 128);

const TIMESTAMP_OFFSET: u8 = SEQUENCE_OFFSET + SEQUENCE_BITS;
const SEQUENCE_OFFSET: u8 = SERVICE_ID_OFFSET + SERVICE_ID_BITS;
const SERVICE_ID_OFFSET: u8 = WORKER_ID_OFFSET + WORKER_ID_BITS;
const WORKER_ID_OFFSET: u8 = RANDOM_BITS;

const _: () = assert!(128 == TIMESTAMP_OFFSET + TIMESTAMP_BITS);

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Identifier {
    timestamp: SystemTime,
    sequence: u16,
    service_id: u16,
    worker_id: u16,
    random: u16,
}

impl From<u128> for Identifier {
    fn from(id: u128) -> Self {
        Self {
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis((id >> TIMESTAMP_OFFSET) as u64),
            sequence: ((id >> SEQUENCE_OFFSET) & 0xffff) as u16,
            service_id: ((id >> SERVICE_ID_OFFSET) & 0xffff) as u16,
            worker_id: ((id >> WORKER_ID_BITS) & 0xffff) as u16,
            random: (id & 0xffff) as u16,
        }
    }
}

impl From<Identifier> for u128 {
    fn from(id: Identifier) -> u128 {
        id.timestamp.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() << TIMESTAMP_OFFSET |
            (id.sequence as u128) << SEQUENCE_OFFSET |
            (id.service_id as u128) << SERVICE_ID_OFFSET |
            (id.worker_id as u128) << WORKER_ID_BITS |
            id.random as u128
    }
}

pub struct IdentifierGenerator {
    timestamp: u64,
    sequence: u16,
    service_id: u16,
    worker_id: u16,
    rng: ThreadRng,
}

impl IdentifierGenerator {
    fn new(service_id: u16, worker_id: u16) -> Self {
        Self {
            timestamp: 0,
            sequence: 0,
            service_id,
            worker_id,
            rng: rand::thread_rng(),
        }
    }

    fn generate(&mut self) -> Identifier {
        self.generate_bits().into()
    }

    fn generate_bits(&mut self) -> u128 {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let sequence = if timestamp == self.timestamp {
            self.sequence + 1
        } else {
            0
        };
        self.timestamp = timestamp;
        self.sequence = sequence;
        let random = self.rng.gen::<u16>();
        (timestamp as u128) << TIMESTAMP_OFFSET |
            (sequence as u128) << SEQUENCE_OFFSET |
            (self.service_id as u128) << SERVICE_ID_OFFSET |
            (self.worker_id as u128) << WORKER_ID_BITS |
            random as u128
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_bits() {
        let mut generator = IdentifierGenerator::new(0, 0);
        let ids = (0..10).map(|_| generator.generate_bits()).collect::<Vec<_>>();
        assert_eq!(ids.len(), ids.iter().collect::<std::collections::HashSet<_>>().len());
    }

    #[test]
    fn test_generate() {
        let mut generator = IdentifierGenerator::new(0, 0);
        let ids = (0..10).map(|_| generator.generate()).collect::<Vec<_>>();
        assert_eq!(ids.len(), ids.iter().collect::<std::collections::HashSet<_>>().len());
    }

    #[test]
    fn test_speed() {
        let mut generator = IdentifierGenerator::new(0, 0);
        let count = 1000000;
        let start = SystemTime::now();
        for _ in 0..count {
            generator.generate();
        }
        let end = SystemTime::now();
        let duration = end.duration_since(start).unwrap();
        assert!(duration / count * 3000 < Duration::from_millis(1), "Duration: {:?}", duration / count * 3000);
    }
}
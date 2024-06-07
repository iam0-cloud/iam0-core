use std::time::{Duration, SystemTime};
use rand::Rng;
use rand::rngs::ThreadRng;

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
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis((id >> 64) as u64),
            service_id: ((id >> 48) & 0xffff) as u16,
            worker_id: ((id >> 32) & 0xffff) as u16,
            sequence: ((id >> 16) & 0xffff) as u16,
            random: (id & 0xffff) as u16,
        }
    }
}

impl From<Identifier> for u128 {
    fn from(id: Identifier) -> u128 {
        (id.timestamp.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u128) << 64 |
            (id.service_id as u128) << 48 |
            (id.worker_id as u128) << 32 |
            (id.sequence as u128) << 16 |
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
        (timestamp as u128) << 64 |
            (self.service_id as u128) << 48 |
            (self.worker_id as u128) << 32 |
            (sequence as u128) << 16 |
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
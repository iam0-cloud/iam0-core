use std::fmt::Display;
use std::time::{Duration, SystemTime};
use base64::Engine;
use rand::Rng;
use rand::rngs::ThreadRng;
use base64::prelude::BASE64_URL_SAFE;

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

const TIMESTAMP_MASK: u128 = (1 << TIMESTAMP_BITS) - 1;
const SEQUENCE_MASK: u128 = (1 << SEQUENCE_BITS) - 1;
const SERVICE_ID_MASK: u128 = (1 << SERVICE_ID_BITS) - 1;
const WORKER_ID_MASK: u128 = (1 << WORKER_ID_BITS) - 1;
const RANDOM_MASK: u128 = (1 << RANDOM_BITS) - 1;

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub struct Identifier {
    timestamp: SystemTime,
    sequence: u16,
    service_id: u16,
    worker_id: u16,
    random: u16,
}

impl Identifier {
    pub fn as_base64(&self) -> String {
        let id: u128 = (*self).into();
        let bytes = id.to_be_bytes();
        BASE64_URL_SAFE.encode(&bytes)
    }

    pub fn from_base64(base64: &str) -> Option<Self> {
        let bytes = BASE64_URL_SAFE.decode(base64).ok()?;
        let (bytes, rest) = bytes.split_at(std::mem::size_of::<u128>());
        if !rest.is_empty() {
            return None;
        }
        let id = u128::from_be_bytes(bytes.try_into().unwrap());
        Some(id.into())
    }

    pub fn as_hex(&self) -> String {
        format!("{:032x}", u128::from(*self))
    }

    pub fn from_hex(hex: &str) -> Option<Self> {
        let id = u128::from_str_radix(hex, 16).ok()?;
        Some(id.into())
    }
}

impl Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_hex())
    }
}

impl From<u128> for Identifier {
    fn from(id: u128) -> Self {
        Self {
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(((id >> TIMESTAMP_OFFSET) & TIMESTAMP_MASK) as u64),
            sequence: ((id >> SEQUENCE_OFFSET) & SEQUENCE_MASK) as u16,
            service_id: ((id >> SERVICE_ID_OFFSET) & SERVICE_ID_MASK) as u16,
            worker_id: ((id >> WORKER_ID_BITS) & WORKER_ID_MASK) as u16,
            random: (id & RANDOM_MASK) as u16,
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

    #[test]
    fn test_base64() {
        let id = Identifier {
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(1),
            sequence: 2,
            service_id: 3,
            worker_id: 4,
            random: 5,
        };
        let base64 = id.as_base64();
        let id2 = Identifier::from_base64(&base64).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn test_hex() {
        let id = Identifier {
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(1),
            sequence: 2,
            service_id: 3,
            worker_id: 4,
            random: 5,
        };
        let hex = id.as_hex();
        let id2 = Identifier::from_hex(&hex).unwrap();
        assert_eq!(id, id2);
    }
}
use elliptic_curve::rand_core::block::BlockRngCore;
use elliptic_curve::rand_core::{CryptoRng, RngCore};
use getrandom::getrandom;

const CHACHA_BLOCK_SIZE: usize = 64;
const CHACHA_KEY_SIZE: usize = 32;
const CHACHA_NONCE_SIZE: usize = 12;
const CHACHA_ROUNDS: usize = 20;

fn rotate_left(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

fn chacha_quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = rotate_left(x[d] ^ x[a], 16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = rotate_left(x[b] ^ x[c], 12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = rotate_left(x[d] ^ x[a], 8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = rotate_left(x[b] ^ x[c], 7);
}

fn chacha_block(key: &[u8; CHACHA_KEY_SIZE], nonce: &[u8; CHACHA_NONCE_SIZE], counter: u32) -> [u8; CHACHA_BLOCK_SIZE] {
    let mut state = [0u32; 16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for i in 0..CHACHA_KEY_SIZE >> 2 {
        state[4 + i] = u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    state[12] = counter;
    for i in 0..CHACHA_NONCE_SIZE >> 2 {
        state[13 + i] = u32::from_le_bytes([nonce[i * 4], nonce[i * 4 + 1], nonce[i * 4 + 2], nonce[i * 4 + 3]]);
    }
    let initial_state = state;
    for _ in 0..CHACHA_ROUNDS >> 1 {
        chacha_quarter_round(&mut state, 0, 4, 8, 12);
        chacha_quarter_round(&mut state, 1, 5, 9, 13);
        chacha_quarter_round(&mut state, 2, 6, 10, 14);
        chacha_quarter_round(&mut state, 3, 7, 11, 15);
        chacha_quarter_round(&mut state, 0, 5, 10, 15);
        chacha_quarter_round(&mut state, 1, 6, 11, 12);
        chacha_quarter_round(&mut state, 2, 7, 8, 13);
        chacha_quarter_round(&mut state, 3, 4, 9, 14);
    }
    let mut output = [0u8; CHACHA_BLOCK_SIZE];
    for i in 0..16 {
        let result = state[i].wrapping_add(initial_state[i]);
        output[4 * i..4 * i + 4].copy_from_slice(&result.to_le_bytes());
    }
    output
}

pub struct ChaChaRng {
    key: [u8; CHACHA_KEY_SIZE],
    nonce: [u8; CHACHA_NONCE_SIZE],
    counter: u32,
    block: [u8; CHACHA_BLOCK_SIZE],
    offset: usize,
}

impl ChaChaRng {
    pub fn new() -> Self {
        let mut key = [0u8; CHACHA_KEY_SIZE];
        getrandom(&mut key).expect("Failed to generate random key");
        let mut nonce = [0u8; CHACHA_NONCE_SIZE];
        getrandom(&mut nonce).expect("Failed to generate random nonce");

        ChaChaRng {
            key,
            nonce,
            counter: 0,
            block: [0u8; CHACHA_BLOCK_SIZE],
            offset: CHACHA_BLOCK_SIZE,
        }
    }

    fn refill(&mut self) {
        self.block = chacha_block(&self.key, &self.nonce, self.counter);
        self.counter = self.counter.wrapping_add(1);
        self.offset = 0;
    }

    pub fn next_u8(&mut self) -> u8 {
        if self.offset == CHACHA_BLOCK_SIZE {
            self.refill();
        }
        let result = self.block[self.offset];
        self.offset += 1;
        result
    }
}

impl RngCore for ChaChaRng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([self.next_u8(), self.next_u8(), self.next_u8(), self.next_u8()])
    }

    fn next_u64(&mut self) -> u64 {
        let low = self.next_u32() as u64;
        let high = self.next_u32() as u64;
        (high << 32) | low
    }

    fn fill_bytes(&mut self, buffer: &mut [u8]) {
        for chunk in buffer.chunks_mut(CHACHA_BLOCK_SIZE) {
            let remaining = CHACHA_BLOCK_SIZE - self.offset;

            if chunk.len() > remaining {
                chunk[..remaining].copy_from_slice(&self.block[self.offset..]);
                self.refill();
                let take = chunk.len() - remaining;
                chunk[remaining..].copy_from_slice(&self.block[..take]);
                self.offset = take;
            } else {
                chunk.copy_from_slice(&self.block[self.offset..self.offset + chunk.len()]);
                self.offset += chunk.len();
            }
        }
    }

    fn try_fill_bytes(&mut self, buffer: &mut [u8]) -> Result<(), elliptic_curve::rand_core::Error> {
        self.fill_bytes(buffer);
        Ok(())
    }
}

impl BlockRngCore for ChaChaRng {
    type Item = u32;
    type Results = [u32; 16];

    fn generate(&mut self, results: &mut Self::Results) {
        let bytes = chacha_block(&self.key, &self.nonce, self.counter);
        self.counter = self.counter.wrapping_add(1);
        for (i, chunk) in bytes.chunks(4).enumerate() {
            results[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
    }
}

impl CryptoRng for ChaChaRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fill_bytes() {
        let mut rng = ChaChaRng::new();
        for _ in 0..CHACHA_BLOCK_SIZE - 1 {
            rng.next_u8();
        }
        let mut buffer = [0u8; CHACHA_BLOCK_SIZE];
        rng.fill_bytes(&mut buffer);
        assert_ne!(buffer, [0u8; CHACHA_BLOCK_SIZE]);
    }
}
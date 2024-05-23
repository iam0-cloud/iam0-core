use digest::{FixedOutput, HashMarker, Update};
use elliptic_curve::rand_core::CryptoRngCore;

pub trait Shnorr<PrivateKey, PublicKey> {
    fn proof<T, Hasher>(&self, payload: &T, x: &PrivateKey, rng: &mut impl CryptoRngCore) -> (PrivateKey, PublicKey)
        where
            T: AsRef<[u8]>,
            Hasher: FixedOutput + Default + Update + HashMarker;
    fn verify<T, Hasher>(&self, payload: &T, public_key: &PublicKey, proof: &PrivateKey, commitment: &PublicKey) -> bool
        where
            T: AsRef<[u8]>,
            Hasher: FixedOutput + Default + Update + HashMarker;
}
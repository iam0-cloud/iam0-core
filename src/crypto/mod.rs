use num_bigint::BigUint;
use crate::crypto::elliptic_curve::{EllipticCurveParams, EllipticCurvePoint};

pub mod elliptic_curve;
pub mod csprng;
pub mod schnorr;

#[derive(Debug, PartialEq)]
pub struct KeyPair<PrivateKey, PublicKey> {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
}

pub trait CryptoProvider<PrivateKey, PublicKey> {
    fn generate_key_pair(&self) -> KeyPair<PrivateKey, PublicKey>;
    fn random_scalar(&self) -> PrivateKey;
    fn random_scalar_key(&self) -> PrivateKey;
    fn derive_public_key(&self, private_key: &PrivateKey) -> PublicKey;
    fn zkp_rhs(&self, commitment: &PublicKey, challenge: &PrivateKey, public_key: &PublicKey) -> PublicKey;
    fn module(&self, value: PrivateKey) -> PrivateKey;
}
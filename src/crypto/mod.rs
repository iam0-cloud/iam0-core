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
    fn derive_public_key_with_g(&self, g: &PublicKey, private_key: &PrivateKey) -> PublicKey;
    fn compose(&self, a: &PublicKey, b: &PublicKey) -> PublicKey;
    fn module(&self, value: PrivateKey) -> PrivateKey;
    fn private_key_from_bytes(&self, bytes: &[u8]) -> PrivateKey;
}
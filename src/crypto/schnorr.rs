use crate::crypto::{CryptoProvider, KeyPair};
use std::ops::{Add, Mul};

fn commitment<PrivateKey, PublicKey, Crypto>(crypto: &Crypto) -> KeyPair<PrivateKey, PublicKey>
where
    Crypto: CryptoProvider<PrivateKey, PublicKey>,
{
    crypto.generate_key_pair()
}

fn challenge<PrivateKey, PublicKey, Crypto>(crypto: &Crypto) -> PrivateKey
where
    Crypto: CryptoProvider<PrivateKey, PublicKey>,
{
    crypto.random_scalar()
}

fn proof<PrivateKey, Crypto, T>(crypto: &Crypto, k: &PrivateKey, c: &PrivateKey, x: &PrivateKey) -> PrivateKey
where
    Crypto: CryptoProvider<PrivateKey, T>,
    for<'a> &'a PrivateKey: Mul<&'a PrivateKey, Output = PrivateKey>,
    for<'a> &'a PrivateKey: Add<PrivateKey, Output = PrivateKey>,
{
    crypto.module(k + c * x)
}

fn verify<PrivateKey, PublicKey, Crypto>(
    crypto: &Crypto,
    proof: &PrivateKey,
    commitment: &PublicKey,
    challenge: &PrivateKey,
    public_key: &PublicKey,
) -> bool
where
    Crypto: CryptoProvider<PrivateKey, PublicKey>,
    PublicKey: PartialEq,
{
    let lhs = crypto.derive_public_key(&proof);
    let rhs = crypto.zkp_rhs(commitment, challenge, public_key);
    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::elliptic_curve;

    #[test]
    fn test_proof() {
        let crypto = elliptic_curve::EllipticCurve::secp256r1;
        let key_pair = crypto.generate_key_pair();

        let KeyPair { private_key: k, public_key: commitment } = commitment(&crypto);
        let challenge = challenge(&crypto);
        let proof = proof(&crypto, &k, &challenge, &key_pair.private_key);
        assert!(verify(&crypto, &proof, &commitment, &challenge, &key_pair.public_key));
    }
}

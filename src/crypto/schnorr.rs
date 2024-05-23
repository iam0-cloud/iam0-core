#![allow(dead_code)]

use crate::crypto::{CryptoProvider, KeyPair};
use std::ops::{Add, Mul};
use sha3::Digest;
use sha3::digest::{FixedOutput, HashMarker, Update};

fn commitment<PrivateKey, PublicKey, Crypto>(crypto: &Crypto) -> KeyPair<PrivateKey, PublicKey>
where
    Crypto: CryptoProvider<PrivateKey, PublicKey>,
{
    crypto.generate_key_pair()
}

fn challenge<PrivateKey, PublicKey, Payload, Crypto, Hasher>(
    crypto: &Crypto,
    public_key: &PublicKey,
    payload: &Payload,
) -> PrivateKey
where
    PublicKey: AsRef<[u8]>,
    Payload: AsRef<[u8]>,
    Crypto: CryptoProvider<PrivateKey, PublicKey>,
    Hasher: FixedOutput + Default + Update + HashMarker
{
    let hash = &Hasher::default()
        .chain(public_key)
        .chain(payload)
        .finalize()[..];
    crypto.module(crypto.private_key_from_bytes(hash))
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
    let rhs = crypto.compose(commitment, &crypto.derive_public_key_with_g(public_key, challenge));
    lhs == rhs
}

#[cfg(test)]
mod tests {
    use sha3::digest::core_api::CoreWrapper;
    use sha3::Sha3_512Core;
    use super::*;
    use crate::crypto::elliptic_curve;

    #[test]
    fn test_proof() {
        let crypto = elliptic_curve::EllipticCurve::secp256r1;
        let key_pair = crypto.generate_key_pair();

        let KeyPair { private_key: k, public_key: commitment } = commitment(&crypto);
        let challenge = challenge::<_, _, _, _, CoreWrapper<Sha3_512Core>>(&crypto, &key_pair.public_key, &commitment);
        let proof = proof(&crypto, &k, &challenge, &key_pair.private_key);
        assert!(verify(&crypto, &proof, &commitment, &challenge, &key_pair.public_key));
    }
}

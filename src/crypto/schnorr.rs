use std::mem::size_of;
use std::ops::Mul;
use digest::{Digest, Update};
use elliptic_curve::{AffinePoint, CurveArithmetic, Field, Group, ProjectivePoint, Scalar, ScalarPrimitive};
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};

fn commitment<Curve: CurveArithmetic>() -> (Scalar<Curve>, AffinePoint<Curve>) {
    let nonce = Scalar::<Curve>::random(&mut rand::thread_rng());
    let commitment = ProjectivePoint::<Curve>::generator() * nonce;
    (nonce, commitment.into())
}

fn challenge<Curve, T>(public_key: &AffinePoint<Curve>, payload: &T) -> Scalar<Curve>
    where
        Curve: CurveArithmetic + PointCompression,
        <Curve as CurveArithmetic>::AffinePoint: FromEncodedPoint<Curve> + ToEncodedPoint<Curve>,
        <Curve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
        T: AsRef<[u8]>,
{
    let hash = sha2::Sha512::default()
        .chain(public_key.to_encoded_point(true).as_bytes())
        .chain(payload.as_ref())
        .finalize();
    let result = ScalarPrimitive::<Curve>::from_slice(&hash.as_slice()[..size_of::<ScalarPrimitive::<Curve>>()]).unwrap();
    result.into()
}

pub trait Shnorr<PrivateKey, PublicKey> {
    fn proof<T>(&self, payload: &T, x: &PrivateKey) -> (PrivateKey, PublicKey)
        where
            T: AsRef<[u8]>;
    fn verify<T>(&self, payload: &T, public_key: &PublicKey, proof: &PrivateKey, commitment: &PublicKey) -> bool
        where
            T: AsRef<[u8]>;
}

pub enum ShnorrProof {
    CurveNistP256 { commitment: AffinePoint<p256::NistP256>, proof: Scalar<p256::NistP256>, public_key: AffinePoint<p256::NistP256> },
}

impl<Curve> Shnorr<Scalar<Curve>, AffinePoint<Curve>> for Curve
    where
        Curve: CurveArithmetic + PointCompression,
        <Curve as CurveArithmetic>::AffinePoint: FromEncodedPoint<Curve> + ToEncodedPoint<Curve>,
        <Curve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize
{
    fn proof<T>(&self, payload: &T, x: &Scalar<Curve>) -> (Scalar<Curve>, AffinePoint<Curve>)
        where
            T: AsRef<[u8]>,
    {
        let (c, commitment) = commitment::<Curve>();
        let challenge = challenge::<Curve, T>(&commitment.into(), payload);
        let proof = c + x.mul(&challenge);
        (proof, commitment)
    }

    fn verify<T>(&self, payload: &T, public_key: &AffinePoint<Curve>, proof: &Scalar<Curve>, commitment: &AffinePoint<Curve>) -> bool
        where
            T: AsRef<[u8]>,
    {
        let challenge = challenge::<Curve, T>(commitment.into(), payload);
        let lhs = ProjectivePoint::<Curve>::generator() * proof;
        let commitment = ProjectivePoint::<Curve>::from(*commitment);
        let public_key = ProjectivePoint::<Curve>::from(*public_key);
        let rhs = commitment + public_key.mul(&challenge);
        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use p256::NistP256;

    use crate::crypto::schnorr::{commitment, Shnorr};

    #[test]
    fn test_zkp() {
        let (private_key, public_key) = commitment::<NistP256>();
        let (proof, commitment) = NistP256.proof(
            b"hello world",
            &private_key,
        );
        assert!(NistP256.verify(
            b"hello world",
            &public_key,
            &proof,
            &commitment
        ));
    }
}
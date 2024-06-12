use std::mem::size_of;
use std::ops::Mul;

use digest::{Digest, Update};
use elliptic_curve::{AffinePoint, CurveArithmetic, Field, Group, ProjectivePoint, Scalar, ScalarPrimitive};
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};   
use serde::Deserialize;

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

// NOTE(cdecompilador): This should check too that the point is inside the p256 curve
fn deserialize_p256_affine_point_from_ec1<'de, D>(
    deserializer: D,
) -> Result<AffinePoint<p256::NistP256>, D::Error> 
where
    D: serde::Deserializer<'de>
{

    let s = hex::decode(<String>::deserialize(deserializer)?)
        .map_err(|_| serde::de::Error::custom("the provided affine point isn't a valid hex byte array"))?;
    let encoded_point = p256::EncodedPoint::from_bytes(&s)
        .map_err(|_| serde::de::Error::custom("invalid sec1 encoded affine point"))?;

    // NOTE(cdecompilador): Since p256 uses a custom Option type named CtOption there is no workaround to this
    let affine_point = p256::AffinePoint::from_encoded_point(&encoded_point);
    if affine_point.is_some().into() {
        Ok(affine_point.unwrap())
    } else {
        Err(serde::de::Error::custom("invalid affine point"))
    }
}

#[derive(Debug, serde::Deserialize, PartialEq)]
#[serde(tag = "spec")]
pub enum ShnorrProof {
    /// This variant is selected with the "spec" field "p256"
    #[serde(rename = "p256")]
    CurveNistP256 {
        #[serde(deserialize_with = "deserialize_p256_affine_point_from_ec1")]
        commitment: AffinePoint<p256::NistP256>,

        // TODO
        proof: Scalar<p256::NistP256>,

        #[serde(deserialize_with = "deserialize_p256_affine_point_from_ec1")]
        public_key: AffinePoint<p256::NistP256> 
    },
}

impl ShnorrProof {
    pub fn verify<'a, T>(&self, payload: &'a T) -> bool 
    where
        Vec<u8>: From<&'a T> 
    {
        match self {
            Self::CurveNistP256 { commitment, proof, public_key } => {
                p256::NistP256.verify(
                    &Vec::from(payload),
                    &public_key,
                    &proof,
                    &commitment,
                )
            }
        }
    }
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
    use super::*;

    #[test]
    fn valid_shnorr_proof() {
        let (private_key, public_key) = commitment::<NistP256>();
        let (proof, commitment) = NistP256.proof(
            b"payload",
            &private_key,
        );
        assert!(NistP256.verify(
            b"payload",
            &public_key,
            &proof,
            &commitment
        ));
    }

    #[test]
    fn invalid_payload_shnorr_proof() {
        let (private_key, public_key) = commitment::<NistP256>();
        let (proof, commitment) = NistP256.proof(
            b"payload",
            &private_key,
        );
        assert!(NistP256.verify(
            b"corrupted_payload",
            &public_key,
            &proof,
            &commitment
        ) == false);
    }
        
    #[test]
    fn valid_serialize_deserialize_shnorr_proof() {
        let (private_key, public_key) = commitment::<NistP256>();
        let (proof, commitment) = NistP256.proof(
            b"payload",
            &private_key
        );

        let json_request = serde_json::json!({
            "spec": "p256",
            "commitment": hex::encode(commitment.to_encoded_point(false)),
            "proof": hex::encode(proof.to_bytes()),
            "public_key": hex::encode(public_key.to_encoded_point(false)),
        }).to_string();

        let Ok(ShnorrProof::CurveNistP256 { 
            commitment, 
            proof, 
            public_key 
        }) = serde_json::from_str::<ShnorrProof>(&json_request)
            else {
                panic!("failed to deserialize");
            };

        assert!(
            NistP256.verify(
                b"payload",
                &public_key,
                &proof,
                &commitment
            )
        );
    }

    #[test]
    fn invalid_deserialize_shnorr_proof() {        
        let (private_key, public_key) = commitment::<NistP256>();
        let (proof, commitment) = NistP256.proof(
            b"payload",
            &private_key
        );

        let json_request = serde_json::json!({
            "spec": "p256",
            "commitment": "ff",
            "proof": hex::encode(proof.to_bytes()),
            "public_key": hex::encode(public_key.to_encoded_point(false)),
        }).to_string();
        assert!(serde_json::from_str::<ShnorrProof>(&json_request).is_err());

        let json_request = serde_json::json!({
            "spec": "p256",            
            "commitment": hex::encode(commitment.to_encoded_point(false)),
            "proof": hex::encode(proof.to_bytes()),
            "public_key": "04ff",
        }).to_string();
        assert!(serde_json::from_str::<ShnorrProof>(&json_request).is_err());      
    }
}
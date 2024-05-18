use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::crypto::csprng::ChaChaRng;
use crate::crypto::{CryptoProvider, KeyPair};

#[derive(Clone)]
pub struct EllipticCurveParams {
    pub p: BigUint,
    pub a: BigUint,
    pub b: BigUint,
    pub g: EllipticCurvePoint,
    pub n: BigUint,
}

pub enum EllipticCurve {
    Custom {
        p: BigUint,
        a: BigUint,
        b: BigUint,
        g: EllipticCurvePoint,
        n: BigUint,
    },
    secp256r1,
}

impl EllipticCurve {
    fn params(&self) -> EllipticCurveParams {
        match self {
            EllipticCurve::Custom { p, a, b, g, n } => EllipticCurveParams {
                p: p.clone(),
                a: a.clone(),
                b: b.clone(),
                g: g.clone(),
                n: n.clone(),
            },
            EllipticCurve::secp256r1 => EllipticCurveParams {
                p: BigUint::parse_bytes(
                    b"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                    16,
                )
                    .unwrap(),
                a: BigUint::parse_bytes(
                    b"ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                    16,
                )
                    .unwrap(),
                b: BigUint::parse_bytes(
                    b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                    16,
                )
                    .unwrap(),
                g: EllipticCurvePoint::new(
                    BigUint::parse_bytes(
                        b"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                        16,
                    )
                        .unwrap(),
                    BigUint::parse_bytes(
                        b"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                        16,
                    )
                        .unwrap(),
                ),
                n: BigUint::parse_bytes(
                    b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                    16,
                )
                    .unwrap(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EllipticCurvePoint {
    x: BigUint,
    y: BigUint,
    infinity: bool,
}

impl EllipticCurvePoint {
    pub fn new(x: BigUint, y: BigUint) -> Self {
        EllipticCurvePoint {
            x,
            y,
            infinity: false,
        }
    }

    pub fn infinity() -> Self {
        EllipticCurvePoint {
            x: BigUint::zero(),
            y: BigUint::zero(),
            infinity: true,
        }
    }

    pub fn add(&self, other: &EllipticCurvePoint, p: &BigUint) -> EllipticCurvePoint {
        if self.infinity {
            return other.clone();
        }
        if other.infinity {
            return self.clone();
        }

        if self.x == other.x && self.y != other.y {
            return EllipticCurvePoint::infinity();
        }

        let lambda = if self.x == other.x {
            (BigUint::from(3u32) * &self.x * &self.x + BigUint::from(1u32)) * mod_inv(&(BigUint::from(2u32) * &self.y), p)
        } else {
            let dx = (&other.x + p - &self.x) % p;
            let dy = (&other.y + p - &self.y) % p;
            dy * mod_inv(&dx, p)
        } % p;

        let x3 = (&lambda * &lambda - &self.x - &other.x) % p;
        let dx = (&self.x + p - &x3) % p;
        let y3 = &lambda * dx;
        let y3 = (y3 + p - &self.y) % p;

        EllipticCurvePoint::new(x3, y3)
    }

    pub fn mul(&self, k: &BigUint, params: &EllipticCurveParams) -> EllipticCurvePoint {
        let mut k = k.clone();
        let mut current = self.clone();
        let mut result = EllipticCurvePoint::infinity();

        while k > BigUint::zero() {
            if &k & BigUint::one() == BigUint::one() {
                result = result.add(&current, &params.p);
            }
            current = current.add(&current, &params.p);
            k >>= 1;
        }

        result
    }
}

fn mod_inv(a: &BigUint, p_field: &BigUint) -> BigUint {
    a.modpow(&(p_field - BigUint::from(2u8)), p_field)
}

impl CryptoProvider<BigUint, EllipticCurvePoint> for EllipticCurve {
    fn generate_key_pair(&self) -> KeyPair<BigUint, EllipticCurvePoint> {
        let params = self.params();
        let private_key = self.random_scalar_key();
        let public_key = self.derive_public_key(&private_key);

        KeyPair { private_key, public_key }
    }

    fn random_scalar(&self) -> BigUint {
        let mut rng = ChaChaRng::new();
        let n = self.params().n;
        loop {
            let mut bytes = vec![0u8; (n.bits() >> 3) as usize];
            rng.fill_bytes(&mut bytes);
            let k = BigUint::from_bytes_le(&bytes);

            if k < n {
                return k;
            }
        }
    }

    fn random_scalar_key(&self) -> BigUint {
        loop {
            let result = self.random_scalar();
            if result != BigUint::zero() {
                return result;
            }
        }
    }

    fn derive_public_key(&self, private_key: &BigUint) -> EllipticCurvePoint {
        self.params().g.mul(private_key, &self.params())
    }

    fn zkp_rhs(&self, commitment: &EllipticCurvePoint, challenge: &BigUint, public_key: &EllipticCurvePoint) -> EllipticCurvePoint {
        commitment.add(&public_key.mul(challenge, &self.params()), &self.params().p)
    }

    fn module(&self, value: BigUint) -> BigUint {
        value % self.params().n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_gen() {
        let elliptic_curve = EllipticCurve::secp256r1;
        let pair = elliptic_curve.generate_key_pair();
        assert_ne!(pair, KeyPair{ private_key: BigUint::zero(), public_key: EllipticCurvePoint::infinity() });
    }
}

use aead::{Aead, AeadCore, AeadInPlace, Nonce};
use aead::generic_array::ArrayLength;
use aead::generic_array::typenum::Unsigned;
use aead::rand_core::CryptoRngCore;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use cipher::{Key, KeyInit};
use ecdsa::{Signature, SignatureSize};
use signature::{Signer, Verifier};

pub struct Token<Payload: AsRef<[u8]>, Curve: elliptic_curve::PrimeCurve>
where
    SignatureSize<Curve>: ArrayLength<u8>
{
    payload: Payload,
    signature: Option<Signature<Curve>>,
}

impl<Payload: AsRef<[u8]>, Curve: elliptic_curve::PrimeCurve> Token<Payload, Curve>
where
    SignatureSize<Curve>: ArrayLength<u8>
{
    pub fn new(payload: Payload, signature: Signature<Curve>) -> Self {
        Self {
            payload,
            signature: Some(signature),
        }
    }

    pub fn sign(payload: Payload, signer: &impl Signer<Signature<Curve>>) -> Self {
        let signature = signer.sign(payload.as_ref());
        Self::new(payload, signature)
    }

    pub fn verify(&self, verifier: &impl Verifier<Signature<Curve>>) -> bool {
        verifier.verify(self.payload.as_ref(), self.signature.as_ref().unwrap()).is_ok()
    }

    pub fn encrypt<Cipher>(&self, key: &Key<Cipher>, rng: &mut impl CryptoRngCore) -> aead::Result<String>
    where
        Cipher: KeyInit + AeadInPlace,
    {
        let cipher = Cipher::new(key);
        let nonce = Cipher::generate_nonce(rng);
        let payload = self.payload.as_ref();
        let signature = self.signature.as_ref().unwrap().to_bytes();
        let signature = signature.as_ref();
        let bytes = [&(payload.len() as u32).to_le_bytes(), payload, signature].concat();
        let bytes = cipher.encrypt(&nonce, bytes.as_slice())?;
        let bytes = [nonce.as_ref(), &bytes].concat();
        Ok(BASE64_STANDARD.encode(bytes))
    }

    pub fn decrypt<Cipher>(
        token: &str,
        key: &Key<Cipher>,
        map_fn: impl FnOnce(&[u8]) -> Payload
    ) -> Result<Self, &'static str>
    where
        Cipher: KeyInit + AeadInPlace + AeadCore,
    {
        let nonce_size = Cipher::NonceSize::to_usize();
        let cipher = Cipher::new(key);
        let bytes = BASE64_STANDARD.decode(token).map_err(|_| "Invalid token")?;
        let nonce = Nonce::<Cipher>::from_slice(&bytes[..nonce_size]);
        let bytes = &bytes[nonce_size..];
        let bytes = cipher.decrypt(&nonce, bytes).map_err(|_| "Decryption failed")?;
        let length_bytes = &bytes[..4];
        let length = u32::from_le_bytes(length_bytes.try_into().unwrap()) as usize;
        let payload = &bytes[4..4 + length];
        let signature = &bytes[4 + length..];
        let signature = Signature::from_slice(signature).map_err(|_| "Invalid signature")?;
        Ok(Self::new(map_fn(payload), signature))
    }
}

trait TokenSigner<Payload: AsRef<[u8]>, Curve: elliptic_curve::PrimeCurve>: Signer<Signature<Curve>>
where
    SignatureSize<Curve>: ArrayLength<u8>
{
    fn sign(&self, payload: Payload) -> Token<Payload, Curve> {
        let signature = Signer::sign(self, payload.as_ref());
        Token::new(payload, signature)
    }
}

trait TokenVerifier<Payload: AsRef<[u8]>, Curve: elliptic_curve::PrimeCurve>: Verifier<Signature<Curve>>
where
    SignatureSize<Curve>: ArrayLength<u8>
{
    fn verify(&self, token: Token<Payload, Curve>) -> bool {
        let payload = token.payload.as_ref();
        Verifier::verify(self, payload, token.signature.as_ref().unwrap()).is_ok()
    }
}

impl<
    Payload: AsRef<[u8]>,
    Curve: elliptic_curve::PrimeCurve,
    Signer: signature::Signer<Signature<Curve>>,
> TokenSigner<Payload, Curve> for Signer
where
    SignatureSize<Curve>: ArrayLength<u8>
{}

impl<
    Payload: AsRef<[u8]>,
    Curve: elliptic_curve::PrimeCurve,
    Verifier: signature::Verifier<Signature<Curve>>,
> TokenVerifier<Payload, Curve> for Verifier
where
    SignatureSize<Curve>: ArrayLength<u8>
{}

#[cfg(test)]
mod tests {
    use aes_gcm::Aes256Gcm;
    use p256::ecdsa::{SigningKey, VerifyingKey};
    use p256::NistP256;

    use crate::crypto::csprng::ChaChaRng;

    use super::*;

    #[test]
    fn test_token() {
        let mut rng = ChaChaRng::new();

        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let payload = b"Hello, World!";
        let token = Token::sign(payload, &signing_key);
        assert!(token.verify(&verifying_key));

        let key = Aes256Gcm::generate_key(&mut rng);
        let encrypted = token.encrypt::<Aes256Gcm>(&key, &mut rng).unwrap();
        let decrypted: Token<_, NistP256> = Token::decrypt::<Aes256Gcm>(
            &encrypted,
            &key,
            |payload| payload.to_vec()
        ).expect("Decryption failed");
        assert!(decrypted.verify(&verifying_key));
    }
}
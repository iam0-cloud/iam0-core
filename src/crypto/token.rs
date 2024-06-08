use aead::{Aead, AeadInPlace, Nonce};
use aead::generic_array::ArrayLength;
use aead::generic_array::typenum::Unsigned;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE;
use cipher::KeyInit;
use ecdsa::{Signature, SignatureSize};
use serde::{Deserialize, Serialize};
use signature::{Signer, Verifier};

pub struct Token<T, Curve: elliptic_curve::PrimeCurve>
where
    SignatureSize<Curve>: ArrayLength<u8>
{
    payload: T,
    signature: Option<Signature<Curve>>,
}

impl<T, Curve: elliptic_curve::PrimeCurve> Token<T, Curve>
where
    SignatureSize<Curve>: ArrayLength<u8>
{
    pub fn new(payload: T, signature: Signature<Curve>) -> Self {
        Self {
            payload,
            signature: Some(signature),
        }
    }
}

pub trait TokenSigner<T: Serialize, Curve: elliptic_curve::PrimeCurve>: Signer<Signature<Curve>>
where
    SignatureSize<Curve>: ArrayLength<u8>
{
    fn sign(&self, payload: T) -> Token<T, Curve> {
        let serialized = bincode::serialize(&payload).unwrap();
        let signature = Signer::sign(self, serialized.as_slice());
        Token::new(payload, signature)
    }
}

pub trait TokenVerifier<T: Serialize, Curve: elliptic_curve::PrimeCurve>: Verifier<Signature<Curve>>
where
    SignatureSize<Curve>: ArrayLength<u8>
{
    fn verify(&self, token: &Token<T, Curve>) -> bool {
        let payload = bincode::serialize(&token.payload).unwrap();
        Verifier::verify(self, payload.as_slice(), token.signature.as_ref().unwrap()).is_ok()
    }
}

pub trait TokenCipher<Curve: elliptic_curve::PrimeCurve>: KeyInit + AeadInPlace
where
    SignatureSize<Curve>: ArrayLength<u8>
{
    fn encrypt_token<T: Serialize>(&self, token: &Token<T, Curve>) -> aead::Result<String> {
        let nonce = Self::generate_nonce(&mut rand::thread_rng());
        let payload_bytes = bincode::serialize(&token.payload).unwrap();
        let signature_bytes = bincode::serialize(&token.signature).unwrap();
        let bytes = [
            &(payload_bytes.len() as u32).to_le_bytes(),
            payload_bytes.as_slice(),
            &signature_bytes.as_slice()[1..],
        ].concat();
        let bytes = self.encrypt(&nonce, bytes.as_slice())?;
        let bytes = [
            nonce.as_slice(),
            bytes.as_slice(),
        ].concat();

        Ok(BASE64_URL_SAFE.encode(bytes))
    }

    fn decrypt_token<T: for<'de> Deserialize<'de>>(&self, encrypted: &str) -> aead::Result<Token<T, Curve>> {
        let bytes = BASE64_URL_SAFE.decode(encrypted).map_err(|_| aead::Error)?;
        let nonce = Nonce::<Self>::from_slice(&bytes[..Self::NonceSize::to_usize()]);
        let bytes = &bytes[Self::NonceSize::to_usize()..];
        let bytes = self.decrypt(&nonce, bytes)?;
        let length_bytes = &bytes[..4];
        let length = u32::from_le_bytes(length_bytes.try_into().unwrap()) as usize;
        let bytes = &bytes[4..];
        let payload_bytes = &bytes[..length];
        let signature_bytes = &bytes[length..];
        let payload: T = bincode::deserialize(payload_bytes).unwrap();
        let signature: Signature<Curve> = bincode::deserialize(signature_bytes).unwrap();
        Ok(Token::new(payload, signature))
    }
}

impl<
    T: Serialize,
    Curve: elliptic_curve::PrimeCurve,
    Signer: signature::Signer<Signature<Curve>>,
> TokenSigner<T, Curve> for Signer
where
    SignatureSize<Curve>: ArrayLength<u8>
{}

impl<
    T: Serialize,
    Curve: elliptic_curve::PrimeCurve,
    Verifier: signature::Verifier<Signature<Curve>>,
> TokenVerifier<T, Curve> for Verifier
where
    SignatureSize<Curve>: ArrayLength<u8>
{}

impl<
    Curve: elliptic_curve::PrimeCurve,
    Cipher: KeyInit + AeadInPlace,
> TokenCipher<Curve> for Cipher
where
    SignatureSize<Curve>: ArrayLength<u8>
{}

#[cfg(test)]
mod tests {
    use aes_gcm::Aes256Gcm;
    use p256::ecdsa::{SigningKey, VerifyingKey};
    use p256::NistP256;

    use super::*;

    #[test]
    fn test_token() {
        let mut rng = rand::thread_rng();

        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let payload = "Hello, World!".to_string();
        let token = TokenSigner::sign(&signing_key, payload);
        assert!(TokenVerifier::verify(&verifying_key, &token));

        let key = Aes256Gcm::generate_key(&mut rng);
        let cipher = Aes256Gcm::new(&key);
        let encrypted = cipher.encrypt_token(&token).unwrap();
        let decrypted: Token<String, NistP256> = cipher.decrypt_token(encrypted.as_str()).unwrap();
        assert!(TokenVerifier::verify(&verifying_key, &decrypted));
    }
}
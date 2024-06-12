use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use crate::crypto::schnorr::{Shnorr, ShnorrProof};
use crate::crypto::token::{Token, TokenSigner};
use crate::data::id::Identifier;
use crate::store::ClientStore;

#[derive(Debug, serde::Deserialize)]
pub struct UserLoginPayload {
    pub client_id: Identifier,
    pub email: String,
}

impl From<&UserLoginPayload> for Vec<u8> {
    fn from(value: &UserLoginPayload) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(u128::from(value.client_id).to_le_bytes().as_ref());
        bytes.extend_from_slice(value.email.as_bytes());
        bytes
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct UserLoginRequest {
    #[serde(flatten)]
    pub payload: UserLoginPayload,

    #[serde(flatten)]
    pub proof: ShnorrProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserTokenPayload {
    pub user_id: Identifier,
    pub client_id: Identifier,
    // roles: Vec<String>,
    // permissions: Vec<String>,
}

pub struct UserLoginResponse {
    pub token: Token<UserTokenPayload, p256::NistP256>,
}

#[async_trait::async_trait]
pub trait UserAuthentication<CS>
where
    CS: ClientStore {
    async fn login(
        &self,
        request: UserLoginRequest,
        client_store_state: CS::State,
    ) -> Result<UserLoginResponse, String> {
        if !request.proof.verify(&request.payload) {
            return Err("invalid proof".to_string());
        }

        let user = CS::get_user_by_email(client_store_state.clone(), &request.payload.email)
            .await
            .map_err(|_| "user not found".to_string())?;

        let token_payload = UserTokenPayload {
            user_id: user.id,
            client_id: request.payload.client_id,
            // TOOD: roles,
        };

        let signing_key_bytes = CS::get_signing_key_bytes(client_store_state)
            .await
            .map_err(|_| "failed to retrieve signing key")?;

        let signing_key = SigningKey::from_slice(signing_key_bytes.as_slice()).unwrap();
        let token = TokenSigner::sign(&signing_key, token_payload);

        Ok(UserLoginResponse { token })
    }
}
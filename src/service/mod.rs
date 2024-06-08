use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use crate::crypto::schnorr::{Shnorr, ShnorrProof};
use crate::crypto::token::{Token, TokenSigner};
use crate::data::id::Identifier;
use crate::model::store::{ClientStore, UserStore};
use crate::model::{Client, User};

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

trait UserAuthentication {
    fn login(
        &self,
        request: UserLoginRequest,
        response: UserLoginResponse,
        client_store: &impl ClientStore,
    ) -> Result<UserLoginResponse, String> {
        match request.proof {
            ShnorrProof::CurveNistP256 { commitment, proof, public_key } => {
                if p256::NistP256.verify(
                    &Vec::from(&request.payload),
                    &public_key,
                    &proof,
                    &commitment,
                ) {
                    let client = client_store.get(&request.payload.client_id)
                        .map_err(|_| "Client not found".to_string())?;
                    client.get_by_email(&request.payload.email)
                        .map(|user| {
                            let payload = UserTokenPayload {
                                user_id: user.get_id(),
                                client_id: request.payload.client_id,
                                // roles: user.get_roles(),
                                // permissions: user.get_permissions(),
                            };
                            let signing_key_bytes = client.get_signing_key();
                            let signing_key = SigningKey::from_slice(signing_key_bytes.as_slice()).unwrap();
                            let token = TokenSigner::sign(&signing_key, payload);
                            UserLoginResponse { token }
                        })
                        .map_err(|_| "User not found".to_string())
                } else {
                    Err("Invalid proof".to_string())
                }
            }
        }
    }
}
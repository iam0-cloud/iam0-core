use crate::data::id::Identifier;
use crate::model::store::UserStore;
use crate::model::store::StoreError;

#[async_trait::async_trait]
pub trait Client: UserStore {
    async fn get_id(&self) -> Result<Identifier, StoreError>;
    async fn get_parent_id(&self) -> Result<Identifier, StoreError>;

    async fn get_encryption_key(&self) -> Result<Vec<u8>, StoreError>;
    async fn get_signing_key_bytes(&self) -> Result<Vec<u8>, StoreError>;
    async fn get_verification_key(&self) -> Result<Vec<u8>, StoreError>;
}
use crate::data::id::Identifier;
use crate::store::Store;

pub struct UserQuery {
    pub email: String,
    pub id: Identifier
}

#[async_trait::async_trait]
pub trait ClientStore: Store {
    async fn get_user_by_email(state: Self::State, email: &str) -> Result<UserQuery, Self::Error>;
    async fn get_signing_key_bytes(state: Self::State) -> Result<Vec<u8>, Self::Error>;
}
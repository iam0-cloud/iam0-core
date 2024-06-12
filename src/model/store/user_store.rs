use crate::data::id::Identifier;
use crate::model::store::Store;
use crate::model::User;

#[async_trait::async_trait]
pub trait UserStore: Store<
    Object = Self::User,
    Identifier = Identifier,
> {
    type User: User + Send;

    async fn get_user_by_email(&self, email: &str) -> Result<Self::User, Self::Error>;
}
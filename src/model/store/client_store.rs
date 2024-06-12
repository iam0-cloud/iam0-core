use crate::model::Client;
use crate::model::store::Store;

pub trait ClientStore: Store
where
    Self: Clone + Send + Sync + 'static 
{
    async fn get_user_by_email(state: Self::State, email: String) -> Result<User, Self::Error>;
}
use crate::data::id::Identifier;
use crate::model::store::Store;
use crate::model::User;

pub trait UserStore: Store<
    Object = Self::User,
    Identifier = Identifier,
> {
    type User: User;

    fn get_by_email(&self, email: &str) -> Result<Self::User, Self::Error>;
}
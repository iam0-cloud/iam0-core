use crate::data::id::Identifier;

pub trait User {
    type UserMetadata;

    fn get_id(&self) -> Identifier;
    fn get_client_id(&self) -> Identifier;
    fn get_user_metadata(&self) -> Option<Self::UserMetadata>;
}
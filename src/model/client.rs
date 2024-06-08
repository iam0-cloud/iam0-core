use crate::data::id::Identifier;
use crate::model::store::UserStore;

pub trait Client: UserStore {
    fn get_id(&self) -> Identifier;
    fn get_parent_id(&self) -> Identifier;

    fn get_encryption_key(&self) -> Vec<u8>;
    fn get_signing_key(&self) -> Vec<u8>;
    fn get_verification_key(&self) -> Vec<u8>;
}
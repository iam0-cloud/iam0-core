use crate::store::Store;

#[async_trait::async_trait]
pub trait UserStore: Store {
}
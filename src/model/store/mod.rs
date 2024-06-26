mod user_store;
mod client_store;
mod error;

#[async_trait::async_trait]
pub trait Store {
    type Error: Into<StoreError> + Sized + Send + Sync + 'static;
    type State: Sized + Send + Sync + Clone + 'static;
}

pub use user_store::UserStore;
pub use client_store::ClientStore;
pub use error::StoreError;
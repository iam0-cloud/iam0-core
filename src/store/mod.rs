mod user_store;
mod client_store;
mod error;

#[async_trait::async_trait]
pub trait Store 
where
    Self: Sized + Send + Sync + 'static 
{
    type Error: Into<StoreError> + Sized + Send + Sync + 'static;
    type State: Sized + Send + Sync + Clone + 'static;
}

pub use user_store::*;
pub use client_store::*;
pub use error::StoreError;
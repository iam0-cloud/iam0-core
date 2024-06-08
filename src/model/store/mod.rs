pub mod user_store;
pub mod client_store;

pub trait Store {
    type Object;
    type Identifier;
    type Error;

    fn get(&self, id: &Self::Identifier) -> Result<Self::Object, Self::Error>;
    fn insert(&mut self, object: Self::Object) -> Result<(), Self::Error>;
    fn remove(&mut self, id: &Self::Identifier) -> Result<(), Self::Error>;
}

pub use user_store::UserStore;
pub use client_store::ClientStore;
use crate::data::id::Identifier;
use crate::model::Client;
use crate::model::store::Store;

pub trait ClientStore: Store<
    Object = Self::Client,
    Identifier = Identifier,
> {
    type Client: Client;
}
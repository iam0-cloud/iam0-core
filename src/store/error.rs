
/// Here we should have the generic errors for every store that we are expected to handle on the core, the
/// implementor may have more specific error types defined but they at the end and after tracing should be
/// converted to this generic error type
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// This kind of errors should be temporal and a release may not contain any of this
    #[error("unknown error")]
    Unknown,

    /// Dedicated to database connection errors, unexpected and could crash
    #[error("connection error")]
    ConnectionReset(Box<dyn std::error::Error>),

    #[error("element not found")]
    NotFound,
}

unsafe impl Send for StoreError {}
unsafe impl Sync for StoreError {}
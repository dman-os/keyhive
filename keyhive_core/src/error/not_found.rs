use crate::principal::document::id::DocumentId;
use keyhive_crypto::identifier::Identifier;
use thiserror::Error;

/// An identifier this instance cannot answer for.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NotFound {
    /// An identifier this instance has never received.
    #[error("{0} is not known to this keyhive")]
    Unknown(Box<Identifier>),

    /// A document this keyhive was opened without. Its store may hold it:
    /// [`Keyhive::hydrate`][crate::keyhive::Keyhive::hydrate] it, and try again.
    #[error("{0} is not loaded: hydrate it first")]
    NotLoaded(DocumentId),
}

impl NotFound {
    pub fn new(id: impl Into<Identifier>) -> Self {
        NotFound::Unknown(Box::new(id.into()))
    }
}

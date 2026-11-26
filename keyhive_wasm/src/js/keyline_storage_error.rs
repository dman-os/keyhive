use keyhive_core::{certificate::KeylineStorageError, store::HydrateError};
use std::convert::Infallible;
use thiserror::Error;
use wasm_bindgen::JsValue;

/// The Keyline store or the Keyhive store failed while answering a question.
/// The in-memory stores cannot fail, so this is never constructed today; it
/// keeps the JS signatures stable for a backend that can.
#[derive(Debug, Error)]
pub enum JsKeylineStorageError {
    /// Keyline failed.
    #[error(transparent)]
    Keyline(#[from] KeylineStorageError<Infallible>),

    /// Reading from the Keyhive store, or from Keyline for it, failed.
    #[error(transparent)]
    Store(#[from] HydrateError),
}

impl From<JsKeylineStorageError> for JsValue {
    fn from(err: JsKeylineStorageError) -> Self {
        // The message carries the store's own error, which a JS caller
        // cannot otherwise reach.
        let source = match &err {
            JsKeylineStorageError::Keyline(inner) => std::error::Error::source(inner),
            JsKeylineStorageError::Store(inner) => std::error::Error::source(inner),
        };
        let message = match source {
            Some(cause) => format!("{err}: {cause}"),
            None => err.to_string(),
        };
        let err = js_sys::Error::new(&message);
        err.set_name("KeylineStorageError");
        err.into()
    }
}

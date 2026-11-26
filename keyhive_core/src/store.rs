//! Per-entity persistence for a [`Keyhive`][crate::keyhive::Keyhive].
//!
//! A [`KeyhiveStore`] holds the state a keyhive cannot recompute, one entity
//! at a time: the identity's key pairs, each individual's prekey operations,
//! each document's CGKA operations, content heads and content keys, and the
//! events still waiting for a dependency. Group membership is not here: it is
//! the certificate set in the [`Keyline`][keyline::contract::Keyline] store.
//!
//! # Who reads and who writes
//!
//! A keyhive only ever *reads* its store: [`Keyhive::open`][crate::keyhive::Keyhive::open]
//! loads the identity, and a document's CGKA group is built from
//! [`KeyhiveStore::load_cgka_ops`] the first time that document is used. A
//! keyhive never writes to it. Whatever must outlive the process reaches the
//! caller instead, to write in its own transaction with the `append_*` and
//! `put_*` methods:
//!
//! - what a write prepares: [`Keyhive::prepare_encrypt_content`][crate::keyhive::Keyhive::prepare_encrypt_content]
//!   returns a [`PreparedContent`][crate::keyhive::PreparedContent] that carries the
//!   content key, the rotation and every CGKA operation and secret the write
//!   needed first;
//! - what the keyhive generates elsewhere, which it reports to its listener:
//!   CGKA operations ([`CgkaListener`][crate::listener::cgka::CgkaListener]), prekey
//!   operations with their secrets ([`PrekeyListener`][crate::listener::prekey::PrekeyListener]);
//! - what the caller handed in: the events it passed to `receive_*` and
//!   `ingest_*`, and the content heads it passed to `set_content_heads`;
//! - the identity of a keyhive that was just generated:
//!   [`Keyhive::identity`][crate::keyhive::Keyhive::identity].
//!
//! Persisting is idempotent in every case, so a caller that persists
//! something twice, or before the keyhive sees it, is correct.
//!
//! # Errors
//!
//! A failing read is not something a keyhive can recover from in the middle of
//! a call: it would have to answer from a state it cannot know. A keyhive
//! panics with the store's error instead of threading it through every
//! method.

pub mod memory;

use crate::{
    event::static_event::StaticEvent,
    principal::{
        document::id::DocumentId,
        individual::{id::IndividualId, op::KeyOp},
    },
};
use beekem::{keys::LeafKeyPair, operation::CgkaOperation};
use future_form::FutureForm;
use keyhive_content::reference::ContentRef;
use keyhive_crypto::{
    digest::Digest,
    share_key::{ShareKey, ShareSecretKey},
    symmetric_key::SymmetricKey,
    verified::Verified,
};
use std::{collections::BTreeMap, sync::Arc};

/// The state of one replica, entity by entity.
///
/// Every method takes `&self`: a store owns its concurrency control, as a
/// database has transactions. A store that writes inside the caller's
/// transaction does so ambiently.
///
/// What a store returns is verified: it checks signatures when it decodes what
/// it stored, as [`Verified`] and [`KeyOp`] can only be made by verifying.
pub trait KeyhiveStore<F: FutureForm, T: ContentRef> {
    /// What the backing storage can fail with. `Infallible` in memory.
    type Error: core::error::Error + Send + Sync + 'static;

    /// Every key pair this identity holds: its prekeys and the keys it has
    /// sampled for its leaves in CGKA groups. Small, global, and secret.
    fn load_key_pairs(
        &self,
    ) -> F::Future<'_, Result<BTreeMap<ShareKey, ShareSecretKey>, Self::Error>>;

    /// Keep key pairs. Setting a pair again changes nothing.
    fn put_key_pairs<'a>(
        &'a self,
        pairs: &'a [(ShareKey, ShareSecretKey)],
    ) -> F::Future<'a, Result<(), Self::Error>>;

    /// The prekey operations of `who`, in any order. Empty if `who` is unknown.
    fn load_prekey_ops(
        &self,
        who: IndividualId,
    ) -> F::Future<'_, Result<Vec<Arc<KeyOp>>, Self::Error>>;

    /// Keep prekey operations of `who`, which signed each of them.
    fn append_prekey_ops<'a>(
        &'a self,
        who: IndividualId,
        ops: &'a [Arc<KeyOp>],
    ) -> F::Future<'a, Result<(), Self::Error>>;

    /// The prekey operations of `who` with these digests, for a caller
    /// serving a peer the ones it may see. A backend indexes them by
    /// `(who, digest)`. Absent digests are left out.
    fn load_prekey_ops_by_digest<'a>(
        &'a self,
        who: IndividualId,
        digests: &'a [Digest<KeyOp>],
    ) -> F::Future<'a, Result<Vec<Arc<KeyOp>>, Self::Error>>;

    /// The digests of `who`'s prekey operations, without the operations.
    fn list_prekey_op_digests(
        &self,
        who: IndividualId,
    ) -> F::Future<'_, Result<Vec<Digest<KeyOp>>, Self::Error>>;

    /// Every individual with prekey operations here.
    fn list_individuals(&self) -> F::Future<'_, Result<Vec<IndividualId>, Self::Error>>;

    /// The CGKA operations of `doc`, in any order, and no other document's.
    /// Empty if the replica has never held `doc`'s CGKA graph.
    fn load_cgka_ops(
        &self,
        doc: DocumentId,
    ) -> F::Future<'_, Result<Vec<Arc<Verified<CgkaOperation>>>, Self::Error>>;

    /// The CGKA operations of `doc` with these digests, for a caller serving
    /// a peer the ones it may see. A backend indexes them by `(doc, digest)`.
    /// Absent digests are left out.
    fn load_cgka_ops_by_digest<'a>(
        &'a self,
        doc: DocumentId,
        digests: &'a [Digest<CgkaOperation>],
    ) -> F::Future<'a, Result<Vec<Arc<Verified<CgkaOperation>>>, Self::Error>>;

    /// The digest of each CGKA operation of `doc` with the digests of its
    /// predecessors, without the operations: the dependency graph a caller
    /// walks to decide which operations a peer may see. A backend keeps them
    /// as columns beside the operation, indexed by `doc` and by each
    /// predecessor.
    fn list_cgka_op_index(
        &self,
        doc: DocumentId,
    ) -> F::Future<'_, Result<Vec<CgkaOpIndexRow>, Self::Error>>;

    /// Keep CGKA operations of `doc`. Keeping one again changes nothing.
    fn append_cgka_ops<'a>(
        &'a self,
        doc: DocumentId,
        ops: &'a [Arc<Verified<CgkaOperation>>],
    ) -> F::Future<'a, Result<(), Self::Error>>;

    /// Every document with CGKA operations here, joined or not.
    fn list_documents(&self) -> F::Future<'_, Result<Vec<DocumentId>, Self::Error>>;

    /// The content heads the application last set for `doc`, or `None` if it
    /// never set any.
    fn load_content_heads(
        &self,
        doc: DocumentId,
    ) -> F::Future<'_, Result<Option<Vec<T>>, Self::Error>>;

    /// Keep `heads` as `doc`'s content heads, replacing the last.
    fn put_content_heads<'a>(
        &'a self,
        doc: DocumentId,
        heads: &'a [T],
    ) -> F::Future<'a, Result<(), Self::Error>>;

    /// The cached key of `content_ref`, content of `doc` this replica wrote
    /// or read.
    ///
    /// A cache that a keyhive reads on a write or a check: a store may evict
    /// any entry, and a keyhive then treats the content as one it never read.
    /// A key is a function of the content's ciphertext header and the CGKA
    /// epoch it was written in, so it can be re-derived while this replica
    /// has access to that epoch, but a keyhive does not do so unprompted: a
    /// caller that wants to reference older content re-reads it
    /// ([`Keyhive::try_decrypt_content_keyed`][crate::keyhive::Keyhive::try_decrypt_content_keyed])
    /// and caches the key again. For content of an epoch before this
    /// replica's access, whose key only arrived inside a descendant's
    /// envelope, the cache is the only copy.
    fn get_cached_content_key<'a>(
        &'a self,
        doc: DocumentId,
        content_ref: &'a T,
    ) -> F::Future<'a, Result<Option<SymmetricKey>, Self::Error>>;

    /// Cache the key of `content_ref`. A key is a function of the content, so
    /// caching it again changes nothing.
    fn cache_content_key<'a>(
        &'a self,
        doc: DocumentId,
        content_ref: &'a T,
        key: &'a SymmetricKey,
    ) -> F::Future<'a, Result<(), Self::Error>>;

    /// The events that were waiting for a dependency when they were kept.
    /// Unverified: a keyhive verifies them again.
    fn load_pending_events(&self) -> F::Future<'_, Result<Vec<StaticEvent<T>>, Self::Error>>;

    /// Keep waiting events, one row each under its digest. Keeping one again
    /// changes nothing. What waits is defined at [`Keyhive::pending_events`][crate::keyhive::Keyhive::pending_events].
    fn put_pending_events<'a>(
        &'a self,
        events: &'a [StaticEvent<T>],
    ) -> F::Future<'a, Result<(), Self::Error>>;

    /// Forget waiting events that have applied or can never apply. A caller
    /// finds them by comparing the digests
    /// [`Keyhive::pending_event_hashes`][crate::keyhive::Keyhive::pending_event_hashes]
    /// reports after an ingest with what it holds.
    fn drop_pending_events<'a>(
        &'a self,
        digests: &'a [Digest<StaticEvent<T>>],
    ) -> F::Future<'a, Result<(), Self::Error>>;
}

/// What a replica's identity holds: what to persist after generating it.
#[derive(Debug, Clone)]
pub struct Identity {
    /// Every secret key this identity holds.
    pub key_pairs: BTreeMap<ShareKey, ShareSecretKey>,

    /// This identity's own prekey operations, signed.
    pub prekey_ops: Vec<Arc<KeyOp>>,
}

/// What preparing a write did to this replica first, that the store must keep.
///
/// Bringing a document up to date for writing issues CGKA operations (the
/// adds and removes the certificates imply) and rotates this identity's leaf
/// away from a prekey that has been retired. The keyhive applies those at once
/// and announces the operations to its listener; the secret of a rotated leaf
/// reaches no listener. They are part of this replica's state whether or not
/// the write that caused them is applied, so persist them in any transaction
/// that commits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preliminary {
    /// The CGKA operations issued.
    pub cgka_ops: Vec<Arc<Verified<CgkaOperation>>>,

    /// The key pairs sampled for this identity's leaf. Secret.
    pub key_pairs: Vec<LeafKeyPair>,
}

impl Preliminary {
    /// Whether it holds nothing.
    pub fn is_empty(&self) -> bool {
        self.cgka_ops.is_empty() && self.key_pairs.is_empty()
    }
}

/// One row of a document's CGKA operation index: an operation's digest and
/// the digests of the operations it names as predecessors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgkaOpIndexRow {
    /// The operation's digest.
    pub digest: Digest<CgkaOperation>,

    /// Its predecessors' digests.
    pub predecessors: Vec<Digest<CgkaOperation>>,
}

#[cfg(test)]
mod tests;

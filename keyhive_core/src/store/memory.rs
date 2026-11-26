//! An in-memory [`KeyhiveStore`].

use super::{CgkaOpIndexRow, KeyhiveStore};
use crate::{
    event::static_event::StaticEvent,
    principal::{
        document::id::DocumentId,
        individual::{id::IndividualId, op::KeyOp},
    },
};
use beekem::operation::CgkaOperation;
use future_form::{future_form, FutureForm, Local, Sendable};
use keyhive_content::reference::ContentRef;
use keyhive_crypto::{
    digest::Digest,
    share_key::{ShareKey, ShareSecretKey},
    symmetric_key::SymmetricKey,
    verified::Verified,
};
use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    sync::{Arc, Mutex},
};

/// A [`KeyhiveStore`] in memory. A clone is a handle on the same store, so a
/// keyhive reopened over a clone sees what the first one's caller kept.
#[derive(Debug)]
pub struct MemoryKeyhiveStore<T: ContentRef>(Arc<Mutex<Inner<T>>>);

#[derive(Debug)]
struct Inner<T: ContentRef> {
    key_pairs: BTreeMap<ShareKey, ShareSecretKey>,
    prekey_ops: HashMap<IndividualId, HashMap<Digest<KeyOp>, Arc<KeyOp>>>,
    cgka_ops: HashMap<DocumentId, HashMap<Digest<CgkaOperation>, Arc<Verified<CgkaOperation>>>>,
    content_heads: HashMap<DocumentId, Vec<T>>,
    content_keys: HashMap<(DocumentId, T), SymmetricKey>,
    pending_events: HashMap<Digest<StaticEvent<T>>, StaticEvent<T>>,
    cgka_reads: Vec<DocumentId>,
    /// Prekey and CGKA operations ever appended, each counted once.
    total_ops: u64,
}

impl<T: ContentRef> Clone for MemoryKeyhiveStore<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: ContentRef> Default for MemoryKeyhiveStore<T> {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(Inner {
            key_pairs: BTreeMap::new(),
            prekey_ops: HashMap::new(),
            cgka_ops: HashMap::new(),
            content_heads: HashMap::new(),
            content_keys: HashMap::new(),
            pending_events: HashMap::new(),
            cgka_reads: Vec::new(),
            total_ops: 0,
        })))
    }
}

impl<T: ContentRef> MemoryKeyhiveStore<T> {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner<T>> {
        self.0.lock().expect("the store lock is not poisoned")
    }

    /// The documents [`KeyhiveStore::load_cgka_ops`] has been asked for, in
    /// order, for tests of laziness.
    pub fn cgka_reads(&self) -> Vec<DocumentId> {
        self.lock().cgka_reads.clone()
    }
}

#[future_form(Sendable where T: Send + Sync, Local)]
impl<F: FutureForm, T: ContentRef> KeyhiveStore<F, T> for MemoryKeyhiveStore<T> {
    type Error = Infallible;

    fn load_key_pairs(
        &self,
    ) -> F::Future<'_, Result<BTreeMap<ShareKey, ShareSecretKey>, Self::Error>> {
        F::ready(Ok(self.lock().key_pairs.clone()))
    }

    fn put_key_pairs<'a>(
        &'a self,
        pairs: &'a [(ShareKey, ShareSecretKey)],
    ) -> F::Future<'a, Result<(), Self::Error>> {
        self.lock().key_pairs.extend(pairs.iter().cloned());
        F::ready(Ok(()))
    }

    fn load_prekey_ops(
        &self,
        who: IndividualId,
    ) -> F::Future<'_, Result<Vec<Arc<KeyOp>>, Self::Error>> {
        let ops = self
            .lock()
            .prekey_ops
            .get(&who)
            .map(|ops| ops.values().cloned().collect())
            .unwrap_or_default();
        F::ready(Ok(ops))
    }

    fn append_prekey_ops<'a>(
        &'a self,
        who: IndividualId,
        ops: &'a [Arc<KeyOp>],
    ) -> F::Future<'a, Result<(), Self::Error>> {
        let mut inner = self.lock();
        let held = inner.prekey_ops.entry(who).or_default();
        let before = held.len();
        for op in ops {
            held.insert(op.digest(), op.clone());
        }
        let added = (held.len() - before) as u64;
        inner.total_ops += added;
        F::ready(Ok(()))
    }

    fn load_prekey_ops_by_digest<'a>(
        &'a self,
        who: IndividualId,
        digests: &'a [Digest<KeyOp>],
    ) -> F::Future<'a, Result<Vec<Arc<KeyOp>>, Self::Error>> {
        let inner = self.lock();
        let ops = inner.prekey_ops.get(&who).map(|held| {
            digests
                .iter()
                .filter_map(|digest| held.get(digest).cloned())
                .collect()
        });
        F::ready(Ok(ops.unwrap_or_default()))
    }

    fn list_prekey_op_digests(
        &self,
        who: IndividualId,
    ) -> F::Future<'_, Result<Vec<Digest<KeyOp>>, Self::Error>> {
        let digests = self
            .lock()
            .prekey_ops
            .get(&who)
            .map(|held| held.keys().copied().collect())
            .unwrap_or_default();
        F::ready(Ok(digests))
    }

    fn total_op_count(&self) -> F::Future<'_, Result<u64, Self::Error>> {
        F::ready(Ok(self.lock().total_ops))
    }

    fn list_individuals(&self) -> F::Future<'_, Result<Vec<IndividualId>, Self::Error>> {
        F::ready(Ok(self.lock().prekey_ops.keys().copied().collect()))
    }

    fn load_cgka_ops(
        &self,
        doc: DocumentId,
    ) -> F::Future<'_, Result<Vec<Arc<Verified<CgkaOperation>>>, Self::Error>> {
        let mut inner = self.lock();
        inner.cgka_reads.push(doc);
        let ops = inner
            .cgka_ops
            .get(&doc)
            .map(|ops| ops.values().cloned().collect())
            .unwrap_or_default();
        F::ready(Ok(ops))
    }

    fn load_cgka_ops_by_digest<'a>(
        &'a self,
        doc: DocumentId,
        digests: &'a [Digest<CgkaOperation>],
    ) -> F::Future<'a, Result<Vec<Arc<Verified<CgkaOperation>>>, Self::Error>> {
        let inner = self.lock();
        let ops = inner.cgka_ops.get(&doc).map(|held| {
            digests
                .iter()
                .filter_map(|digest| held.get(digest).cloned())
                .collect()
        });
        F::ready(Ok(ops.unwrap_or_default()))
    }

    fn list_cgka_op_index(
        &self,
        doc: DocumentId,
    ) -> F::Future<'_, Result<Vec<CgkaOpIndexRow>, Self::Error>> {
        let rows = self
            .lock()
            .cgka_ops
            .get(&doc)
            .map(|held| {
                held.iter()
                    .map(|(digest, op)| CgkaOpIndexRow {
                        digest: *digest,
                        predecessors: op.payload().predecessors().iter().copied().collect(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        F::ready(Ok(rows))
    }

    fn append_cgka_ops<'a>(
        &'a self,
        doc: DocumentId,
        ops: &'a [Arc<Verified<CgkaOperation>>],
    ) -> F::Future<'a, Result<(), Self::Error>> {
        let mut inner = self.lock();
        let held = inner.cgka_ops.entry(doc).or_default();
        let before = held.len();
        for op in ops {
            held.insert(op.digest(), op.clone());
        }
        let added = (held.len() - before) as u64;
        inner.total_ops += added;
        F::ready(Ok(()))
    }

    fn list_documents(&self) -> F::Future<'_, Result<Vec<DocumentId>, Self::Error>> {
        F::ready(Ok(self.lock().cgka_ops.keys().copied().collect()))
    }

    fn load_content_heads(
        &self,
        doc: DocumentId,
    ) -> F::Future<'_, Result<Option<Vec<T>>, Self::Error>> {
        F::ready(Ok(self.lock().content_heads.get(&doc).cloned()))
    }

    fn put_content_heads<'a>(
        &'a self,
        doc: DocumentId,
        heads: &'a [T],
    ) -> F::Future<'a, Result<(), Self::Error>> {
        self.lock().content_heads.insert(doc, heads.to_vec());
        F::ready(Ok(()))
    }

    fn get_cached_content_key<'a>(
        &'a self,
        doc: DocumentId,
        content_ref: &'a T,
    ) -> F::Future<'a, Result<Option<SymmetricKey>, Self::Error>> {
        F::ready(Ok(self
            .lock()
            .content_keys
            .get(&(doc, content_ref.clone()))
            .cloned()))
    }

    fn cache_content_key<'a>(
        &'a self,
        doc: DocumentId,
        content_ref: &'a T,
        key: &'a SymmetricKey,
    ) -> F::Future<'a, Result<(), Self::Error>> {
        self.lock()
            .content_keys
            .insert((doc, content_ref.clone()), key.clone());
        F::ready(Ok(()))
    }

    fn load_pending_events(&self) -> F::Future<'_, Result<Vec<StaticEvent<T>>, Self::Error>> {
        F::ready(Ok(self.lock().pending_events.values().cloned().collect()))
    }

    fn put_pending_events<'a>(
        &'a self,
        events: &'a [StaticEvent<T>],
    ) -> F::Future<'a, Result<(), Self::Error>> {
        let mut inner = self.lock();
        for event in events {
            inner.pending_events.insert(event.digest(), event.clone());
        }
        F::ready(Ok(()))
    }

    fn drop_pending_events<'a>(
        &'a self,
        digests: &'a [Digest<StaticEvent<T>>],
    ) -> F::Future<'a, Result<(), Self::Error>> {
        let mut inner = self.lock();
        for digest in digests {
            inner.pending_events.remove(digest);
        }
        F::ready(Ok(()))
    }
}

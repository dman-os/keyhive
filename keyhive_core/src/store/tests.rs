//! A keyhive driven through a store and reopened from it answers like one that
//! never restarted, and opening it reads no document.

use super::{memory::MemoryKeyhiveStore, KeyhiveStore};
use crate::{
    content::heads::ContentHeads,
    error::not_found::NotFound,
    event::static_event::StaticEvent,
    keyhive::{Keyhive, PreparedContent},
    listener::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener},
    principal::{
        active::LocalPrekeySecret,
        document::{id::DocumentId, DecryptError},
        individual::{
            id::IndividualId,
            op::{add_key::AddKeyOp, rotate_key::RotateKeyOp, KeyOp},
        },
    },
    test_utils::has_remove_citing_its_revocation,
};
use beekem::operation::{CgkaChange, CgkaOperation};
use future_form::{FutureForm, Sendable};
use futures::lock::Mutex;
use keyhive_content::{encrypted::EncryptedContent, store::memory::MemoryCiphertextStore};
use keyhive_crypto::{
    identifier::Identifier,
    signer::memory::MemorySigner,
    verified::{Signed, Verified},
};
use keyline::{
    certificate::Certificate, contract::Keyline, delegation::Delegation, power::Power,
    revocation::Revocation,
};
use keyline_memory::MemoryKeyline;
use nonempty::nonempty;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{collections::BTreeSet, sync::Arc};
use testresult::TestResult;

type Ref = [u8; 32];
type Store = MemoryKeyhiveStore<Ref>;
type Hive = Keyhive<
    Sendable,
    MemorySigner,
    Ref,
    Vec<u8>,
    Arc<Mutex<MemoryCiphertextStore<Ref, Vec<u8>>>>,
    Persisting,
    rand::rngs::OsRng,
    MemoryKeyline<ContentHeads<Ref>>,
    Store,
>;

/// What an application that persists incrementally does with what a keyhive
/// reports to its listener: keep it in the store.
#[derive(Clone)]
struct Persisting(Store);

impl PrekeyListener<Sendable> for Persisting {
    fn on_prekeys_expanded<'a>(
        &'a self,
        new_prekey: &'a Arc<Signed<AddKeyOp>>,
        local_secret: Option<&'a LocalPrekeySecret>,
    ) -> <Sendable as FutureForm>::Future<'a, ()> {
        let op = KeyOp::Add(new_prekey.as_ref().clone().verify().expect("verifies"));
        Sendable::from_future(async move { keep_prekey(&self.0, op, local_secret).await })
    }

    fn on_prekey_rotated<'a>(
        &'a self,
        rotate_key: &'a Arc<Signed<RotateKeyOp>>,
        local_secret: Option<&'a LocalPrekeySecret>,
    ) -> <Sendable as FutureForm>::Future<'a, ()> {
        let op = KeyOp::Rotate(rotate_key.as_ref().clone().verify().expect("verifies"));
        Sendable::from_future(async move { keep_prekey(&self.0, op, local_secret).await })
    }
}

async fn keep_prekey(store: &Store, op: KeyOp, secret: Option<&LocalPrekeySecret>) {
    let who = IndividualId::from(op.issuer());
    KeyhiveStore::<Sendable, Ref>::append_prekey_ops(store, who, &[Arc::new(op)])
        .await
        .unwrap();
    if let Some(secret) = secret {
        let pair = (secret.share_key(), secret.share_secret_key().clone());
        KeyhiveStore::<Sendable, Ref>::put_key_pairs(store, &[pair])
            .await
            .unwrap();
    }
}

impl CgkaListener<Sendable> for Persisting {
    fn on_cgka_op<'a>(
        &'a self,
        op: &'a Arc<Verified<CgkaOperation>>,
    ) -> <Sendable as FutureForm>::Future<'a, ()> {
        Sendable::from_future(async move {
            let doc = DocumentId::from(op.payload().doc_id);
            KeyhiveStore::<Sendable, Ref>::append_cgka_ops(&self.0, doc, std::slice::from_ref(op))
                .await
                .unwrap();
        })
    }
}

impl MembershipListener<Sendable, Ref> for Persisting {
    fn on_delegation<'a>(
        &'a self,
        _: &'a Arc<Verified<Delegation>>,
    ) -> <Sendable as FutureForm>::Future<'a, ()> {
        Sendable::ready(())
    }

    fn on_revocation<'a>(
        &'a self,
        _: &'a Arc<Verified<Revocation<ContentHeads<Ref>>>>,
    ) -> <Sendable as FutureForm>::Future<'a, ()> {
        Sendable::ready(())
    }
}

/// A replica, its signer (kept to reopen it) and the store its caller keeps.
struct Node {
    hive: Hive,
    signer: MemorySigner,
    store: Store,
}

impl Node {
    async fn new() -> Self {
        let signer = MemorySigner::generate(&mut rand::rngs::OsRng);
        let store = Store::default();
        let hive = Keyhive::generate(
            signer.clone(),
            Arc::new(Mutex::new(MemoryCiphertextStore::new())),
            Persisting(store.clone()),
            MemoryKeyline::new(),
            store.clone(),
            rand::rngs::OsRng,
        )
        .await
        .unwrap();
        // A generated identity has announced nothing.
        let identity = hive.identity().await;
        let pairs: Vec<_> = identity.key_pairs.into_iter().collect();
        KeyhiveStore::<Sendable, Ref>::put_key_pairs(&store, &pairs)
            .await
            .unwrap();
        KeyhiveStore::<Sendable, Ref>::append_prekey_ops(&store, hive.id(), &identity.prekey_ops)
            .await
            .unwrap();
        Node {
            hive,
            signer,
            store,
        }
    }

    /// This replica as it comes back after a restart, with everything its
    /// store holds loaded.
    async fn restarted(&self) -> TestResult<Hive> {
        let hive = self.reopened().await?;
        hive.hydrate_all().await?;
        Ok(hive)
    }

    /// This replica as it comes back after a restart, with nothing loaded: its
    /// store, and the certificates its Keyline store holds.
    async fn reopened(&self) -> TestResult<Hive> {
        let keyline = MemoryKeyline::new();
        let certs = Keyline::<Sendable>::certificates(self.hive.keyline())
            .await?
            .value
            .into_iter()
            .map(Certificate::verify)
            .collect::<Result<Vec<_>, _>>()?;
        Keyline::<Sendable>::insert(&keyline, certs).await?;
        Ok(Keyhive::open(
            self.signer.clone(),
            Arc::new(Mutex::new(MemoryCiphertextStore::new())),
            Persisting(self.store.clone()),
            keyline,
            self.store.clone(),
            rand::rngs::OsRng,
        )
        .await?)
    }

    /// Tell `self` what it needs to know of `peer`'s prekeys, keeping them.
    async fn learn_individual(&self, peer: &Node) {
        let state = peer.hive.active().individual().lock().await.clone();
        let ops: Vec<_> = state.prekey_ops().values().cloned().collect();
        // Registered first: an individual the store holds counts as known.
        assert!(self.hive.register_individual(state).await);
        KeyhiveStore::<Sendable, Ref>::append_prekey_ops(&self.store, peer.hive.id(), &ops)
            .await
            .unwrap();
    }

    /// Ingest what `from` sends this replica, keeping the operations first, as
    /// a caller that persists what it ingests does.
    async fn receive_from(&self, from: &Node) -> TestResult {
        let events: Vec<_> = from
            .hive
            .static_events_for_agent(self.hive.id())
            .await?
            .into_values()
            .collect();
        for event in &events {
            match event {
                StaticEvent::CgkaOperation(op) => {
                    let op = Arc::new(op.as_ref().clone().verify()?);
                    let doc = DocumentId::from(op.payload().doc_id);
                    KeyhiveStore::<Sendable, Ref>::append_cgka_ops(&self.store, doc, &[op]).await?;
                }
                StaticEvent::PrekeysExpanded(op) => {
                    let op = Arc::new(KeyOp::Add(op.clone().verify()?));
                    let who = IndividualId::from(op.issuer());
                    KeyhiveStore::<Sendable, Ref>::append_prekey_ops(&self.store, who, &[op])
                        .await?;
                }
                StaticEvent::PrekeyRotated(op) => {
                    let op = Arc::new(KeyOp::Rotate(op.clone().verify()?));
                    let who = IndividualId::from(op.issuer());
                    KeyhiveStore::<Sendable, Ref>::append_prekey_ops(&self.store, who, &[op])
                        .await?;
                }
                StaticEvent::Delegated(_) | StaticEvent::Revoked(_) => {}
            }
        }
        self.hive.ingest_unsorted_static_events(events).await;
        let waiting = self.hive.pending_events().await;
        KeyhiveStore::<Sendable, Ref>::put_pending_events(&self.store, &waiting).await?;
        Ok(())
    }
}

fn content_ref(content: &[u8]) -> Ref {
    blake3::hash(content).into()
}

/// Write `content` after `preds` the way a caller that persists first does: prepare,
/// keep everything the preparation carries, apply.
async fn write(
    hive: &Hive,
    store: &Store,
    doc: DocumentId,
    content: &[u8],
    preds: &[Ref],
) -> TestResult<EncryptedContent<Vec<u8>, Ref>> {
    let cr = content_ref(content);
    let prepared: PreparedContent<Ref> = hive
        .prepare_encrypt_content(doc, &cr, preds, content, &[])
        .await?;
    keep_preparation(store, &prepared).await;
    let (written, _) = hive.apply_prepared_encryption(prepared).await?;
    Ok(written.encrypted_content().clone())
}

async fn keep_preparation(store: &Store, prepared: &PreparedContent<Ref>) {
    let doc = prepared.doc();
    let preliminary = prepared.preliminary();
    KeyhiveStore::<Sendable, Ref>::append_cgka_ops(store, doc, &preliminary.cgka_ops)
        .await
        .unwrap();
    KeyhiveStore::<Sendable, Ref>::put_key_pairs(store, &preliminary.key_pairs)
        .await
        .unwrap();
    if let Some((op, pair)) = prepared.rotation() {
        KeyhiveStore::<Sendable, Ref>::append_cgka_ops(store, doc, &[Arc::new(op.clone())])
            .await
            .unwrap();
        KeyhiveStore::<Sendable, Ref>::put_key_pairs(store, &[pair])
            .await
            .unwrap();
    }
    KeyhiveStore::<Sendable, Ref>::cache_content_key(
        store,
        doc,
        &prepared.encrypted_content().content_ref,
        &prepared.application_secret_key(),
    )
    .await
    .unwrap();
}

/// Read `encrypted`, caching the key it opened under.
async fn read(
    hive: &Hive,
    store: &Store,
    doc: DocumentId,
    encrypted: &EncryptedContent<Vec<u8>, Ref>,
) -> TestResult<Vec<u8>> {
    let (envelope, key) = hive.try_decrypt_content_keyed(doc, encrypted).await?;
    KeyhiveStore::<Sendable, Ref>::cache_content_key(store, doc, &encrypted.content_ref, &key)
        .await?;
    Ok(envelope.plaintext)
}

async fn op_digests(hive: &Hive, doc: DocumentId) -> BTreeSet<[u8; 32]> {
    hive.cgka_ops_for_doc(&doc)
        .await
        .unwrap_or_default()
        .iter()
        .map(|op| op.digest().into())
        .collect()
}

/// Alice founds a document, makes Bob an editor, and they exchange writes.
struct Scenario {
    alice: Node,
    bob: Node,
    doc: DocumentId,
    first: EncryptedContent<Vec<u8>, Ref>,
    reply: EncryptedContent<Vec<u8>, Ref>,
}

async fn scenario() -> TestResult<Scenario> {
    let alice = Node::new().await;
    let bob = Node::new().await;
    alice.learn_individual(&bob).await;
    bob.learn_individual(&alice).await;

    let doc = alice
        .hive
        .generate_doc(vec![], nonempty![content_ref(b"genesis")])
        .await?;
    alice
        .hive
        .set_content_heads(doc, [content_ref(b"genesis")])
        .await?;
    KeyhiveStore::<Sendable, Ref>::put_content_heads(&alice.store, doc, &[content_ref(b"genesis")])
        .await?;
    alice
        .hive
        .add_member(bob.hive.id(), doc, Power::Edit)
        .await?;
    // Membership is Keyline's: Bob learns of it from Alice's certificates.
    bob.receive_from(&alice).await?;

    let first = write(&alice.hive, &alice.store, doc, b"first", &[]).await?;
    bob.receive_from(&alice).await?;
    assert_eq!(read(&bob.hive, &bob.store, doc, &first).await?, b"first");

    let reply = write(
        &bob.hive,
        &bob.store,
        doc,
        b"reply",
        &[content_ref(b"first")],
    )
    .await?;
    alice.receive_from(&bob).await?;
    assert_eq!(
        read(&alice.hive, &alice.store, doc, &reply).await?,
        b"reply"
    );
    Ok(Scenario {
        alice,
        bob,
        doc,
        first,
        reply,
    })
}

/// Everything a replica answers about `doc` that does not depend on how it
/// came to know it.
async fn answers(
    hive: &Hive,
    doc: DocumentId,
    first: &EncryptedContent<Vec<u8>, Ref>,
    reply: &EncryptedContent<Vec<u8>, Ref>,
) -> TestResult<(
    Option<BTreeSet<IndividualId>>,
    BTreeSet<[u8; 32]>,
    Vec<u8>,
    Vec<u8>,
    bool,
)> {
    Ok((
        hive.cgka_members_for(doc).await?,
        op_digests(hive, doc).await,
        hive.try_decrypt_content(doc, first).await?.plaintext,
        hive.try_decrypt_content(doc, reply).await?.plaintext,
        hive.has_document(doc).await,
    ))
}

/// A keyhive reopened from the store holds what one that never restarted does,
/// reads and writes the same content, and keeps working with its peer.
#[tokio::test]
async fn a_reopened_keyhive_answers_like_one_that_never_restarted() -> TestResult {
    let s = scenario().await?;
    let alice2 = s.alice.restarted().await?;
    let bob2 = s.bob.restarted().await?;

    for (live, reopened) in [(&s.alice.hive, &alice2), (&s.bob.hive, &bob2)] {
        assert_eq!(
            answers(live, s.doc, &s.first, &s.reply).await?,
            answers(reopened, s.doc, &s.first, &s.reply).await?
        );
    }

    // Bob's reopened keyhive writes after content it read before the restart:
    // its key was cached, and its leaf secret and CGKA operations were kept.
    let again = write(
        &bob2,
        &s.bob.store,
        s.doc,
        b"after restart",
        &[content_ref(b"first")],
    )
    .await?;
    s.alice.receive_from(&s.bob).await?;
    assert_eq!(
        s.alice
            .hive
            .try_decrypt_content(s.doc, &again)
            .await?
            .plaintext,
        b"after restart"
    );
    Ok(())
}

/// The sequence the replicas went through includes a removal and a rotation of
/// a prekey; both survive a restart.
#[tokio::test]
async fn removal_and_prekey_rotation_survive_a_restart() -> TestResult {
    let s = scenario().await?;
    let carol = Node::new().await;
    s.alice.learn_individual(&carol).await;
    carol.learn_individual(&s.alice).await;
    s.alice
        .hive
        .add_member(carol.hive.id(), s.doc, Power::Read)
        .await?;
    carol.receive_from(&s.alice).await?;
    let third = write(&s.alice.hive, &s.alice.store, s.doc, b"third", &[]).await?;
    carol.receive_from(&s.alice).await?;
    assert_eq!(
        read(&carol.hive, &carol.store, s.doc, &third).await?,
        b"third"
    );

    // Bob rotates a prekey, then Alice removes Carol and writes again.
    let prekey = s
        .bob
        .hive
        .active()
        .pick_prekey(s.doc)
        .await
        .expect("a prekey");
    s.bob.hive.rotate_prekey(prekey).await?;
    s.alice
        .hive
        .revoke_member(carol.hive.id(), true, s.doc)
        .await?;
    let fourth = write(&s.alice.hive, &s.alice.store, s.doc, b"fourth", &[]).await?;

    let alice2 = s.alice.restarted().await?;
    let carol2 = carol.restarted().await?;
    let bob2 = s.bob.restarted().await?;
    assert_eq!(
        s.alice.hive.cgka_members_for(s.doc).await?,
        alice2.cgka_members_for(s.doc).await?
    );
    assert!(!alice2
        .cgka_members_for(s.doc)
        .await?
        .expect("joined")
        .contains(&carol.hive.id()));
    assert_eq!(
        op_digests(&s.alice.hive, s.doc).await,
        op_digests(&alice2, s.doc).await
    );
    assert_eq!(
        s.bob
            .hive
            .identity()
            .await
            .key_pairs
            .keys()
            .collect::<BTreeSet<_>>(),
        bob2.identity()
            .await
            .key_pairs
            .keys()
            .collect::<BTreeSet<_>>()
    );
    // Carol still reads what she was given, and not what came after her removal.
    assert_eq!(
        carol2.try_decrypt_content(s.doc, &third).await?.plaintext,
        b"third"
    );
    s.bob.receive_from(&s.alice).await?;
    assert!(bob2.try_decrypt_content(s.doc, &fourth).await.is_err());
    assert_eq!(
        s.bob
            .hive
            .try_decrypt_content(s.doc, &fourth)
            .await?
            .plaintext,
        b"fourth"
    );
    Ok(())
}

/// Opening a keyhive reads no document. A document is read when the caller
/// hydrates it, and until then a method that returns a `Result` says it is not
/// loaded, and one that returns a `bool` answers from what is loaded.
#[tokio::test]
async fn opening_reads_no_document_until_it_is_hydrated() -> TestResult {
    let alice = Node::new().await;
    let mut docs = Vec::new();
    for n in 0..3u8 {
        let doc = alice.hive.generate_doc(vec![], nonempty![[n; 32]]).await?;
        write(&alice.hive, &alice.store, doc, &[n], &[]).await?;
        docs.push(doc);
    }
    assert_eq!(
        KeyhiveStore::<Sendable, Ref>::list_documents(&alice.store)
            .await?
            .len(),
        3
    );

    let reopened = alice.reopened().await?;
    assert!(
        alice.store.cgka_reads().is_empty(),
        "opening read a document"
    );
    assert!(!reopened.has_document(docs[1]).await);
    assert_eq!(
        reopened.set_content_heads(docs[1], [[9; 32]]).await,
        Err(NotFound::NotLoaded(docs[1]))
    );
    assert!(alice.store.cgka_reads().is_empty());

    reopened.hydrate(docs[1]).await?;
    assert_eq!(
        alice.store.cgka_reads(),
        vec![docs[1]],
        "only that document is read"
    );
    assert!(reopened.has_document(docs[1]).await);
    reopened.set_content_heads(docs[1], [[9; 32]]).await?;
    // Hydrating it again reads nothing, and the others are still not loaded.
    reopened.hydrate(docs[1]).await?;
    assert_eq!(alice.store.cgka_reads().len(), 1);
    assert!(!reopened.has_document(docs[0]).await);
    Ok(())
}

/// A key the store caches opens its content without loading the document, and
/// content it has no key for says the document is not loaded.
#[tokio::test]
async fn a_cached_key_opens_content_without_loading_the_document() -> TestResult {
    let s = scenario().await?;
    let unread = write(&s.alice.hive, &s.alice.store, s.doc, b"unread", &[]).await?;
    s.bob.receive_from(&s.alice).await?;

    let bob2 = s.bob.reopened().await?;
    let (envelope, _) = bob2.try_decrypt_content_keyed(s.doc, &s.first).await?;
    assert_eq!(envelope.plaintext, b"first");
    assert!(matches!(
        bob2.try_decrypt_content(s.doc, &unread).await,
        Err(DecryptError::NotFound(NotFound::NotLoaded(doc))) if doc == s.doc
    ));
    assert!(
        s.bob.store.cgka_reads().is_empty(),
        "a read loaded the document"
    );

    // Once loaded, the key comes from the CGKA group as before.
    bob2.hydrate(s.doc).await?;
    assert_eq!(
        bob2.try_decrypt_content(s.doc, &unread).await?.plaintext,
        b"unread"
    );
    Ok(())
}

/// A document evicted and hydrated again is the document that was never evicted.
#[tokio::test]
async fn an_evicted_document_hydrates_to_what_it_was() -> TestResult {
    let s = scenario().await?;
    let before = answers(&s.alice.hive, s.doc, &s.first, &s.reply).await?;

    s.alice.hive.evict(s.doc).await;
    assert!(!s.alice.hive.has_document(s.doc).await);
    assert_eq!(
        s.alice.hive.set_content_heads(s.doc, [[9; 32]]).await,
        Err(NotFound::NotLoaded(s.doc))
    );
    s.alice.hive.hydrate(s.doc).await?;
    assert_eq!(
        before,
        answers(&s.alice.hive, s.doc, &s.first, &s.reply).await?
    );
    Ok(())
}

/// A membership change on a document that is not loaded loads it and issues the
/// CGKA operations it implies at once.
#[tokio::test]
async fn adding_and_removing_a_member_on_an_unloaded_document_issues_the_operations() -> TestResult
{
    let s = scenario().await?;
    let carol = Node::new().await;
    s.alice.learn_individual(&carol).await;

    let alice2 = s.alice.reopened().await?;
    alice2.hydrate_individuals(&[carol.hive.id()]).await?;
    assert!(!alice2.has_document(s.doc).await);
    let added = alice2
        .add_member(carol.hive.id(), s.doc, Power::Read)
        .await?;
    assert!(
        added
            .cgka_ops
            .iter()
            .any(|op| matches!(op.payload().change, CgkaChange::Add { .. })),
        "no CGKA add was issued"
    );
    assert!(
        alice2.has_document(s.doc).await,
        "the affected document was not loaded"
    );

    let alice3 = s.alice.reopened().await?;
    assert!(!alice3.has_document(s.doc).await);
    let removed = alice3.revoke_member(s.bob.hive.id(), true, s.doc).await?;
    assert!(
        has_remove_citing_its_revocation(&removed),
        "no CGKA remove was issued"
    );
    Ok(())
}

/// A write whose leaf was added under a prekey that was rotated away rotates
/// first. That rotation, and the secret of its new key, are in what the
/// preparation returns, and stay there until a write applies.
#[tokio::test]
async fn preparing_returns_the_rotation_of_a_retired_prekey_until_a_write_applies() -> TestResult {
    let alice = Node::new().await;
    let bob = Node::new().await;
    alice.learn_individual(&bob).await;
    let doc = alice
        .hive
        .generate_doc(vec![], nonempty![content_ref(b"genesis")])
        .await?;
    alice
        .hive
        .add_member(bob.hive.id(), doc, Power::Edit)
        .await?;
    bob.receive_from(&alice).await?;
    let first = write(&alice.hive, &alice.store, doc, b"first", &[]).await?;
    bob.receive_from(&alice).await?;
    read(&bob.hive, &bob.store, doc, &first).await?;

    // Bob was added under one of his prekeys; retire it.
    let leaf = bob.hive.active().pick_prekey(doc).await.expect("a prekey");
    bob.hive.rotate_prekey(leaf).await?;

    let cr = content_ref(b"reply");
    let preds = [content_ref(b"first")];
    let prepared = bob
        .hive
        .prepare_encrypt_content(doc, &cr, &preds, b"reply", &[])
        .await?;
    assert_eq!(prepared.preliminary().cgka_ops.len(), 1);
    assert_eq!(prepared.preliminary().key_pairs.len(), 1);
    let (rotated_to, _) = prepared.preliminary().key_pairs[0].clone();
    drop(prepared);

    // The transaction rolled back: the next preparation carries it again.
    let prepared = bob
        .hive
        .prepare_encrypt_content(doc, &cr, &preds, b"reply", &[])
        .await?;
    assert_eq!(prepared.preliminary().cgka_ops.len(), 1);
    assert_eq!(prepared.preliminary().key_pairs[0].0, rotated_to);
    keep_preparation(&bob.store, &prepared).await;
    bob.hive.apply_prepared_encryption(prepared).await?;

    // Acknowledged by applying: not repeated.
    let next = bob
        .hive
        .prepare_encrypt_content(doc, &content_ref(b"more"), &[cr], b"more", &[])
        .await?;
    assert!(next.preliminary().is_empty());

    // What the caller kept is enough to reopen and write on.
    let bob2 = bob.restarted().await?;
    write(&bob2, &bob.store, doc, b"after restart", &[cr]).await?;
    Ok(())
}

/// Pending events are rows: kept, found again by digest after a restart.
#[tokio::test]
async fn waiting_events_are_kept_and_reloaded() -> TestResult {
    let alice = Node::new().await;
    let bob = Node::new().await;
    alice.learn_individual(&bob).await;
    let doc = alice
        .hive
        .generate_doc(vec![], nonempty![content_ref(b"genesis")])
        .await?;
    alice
        .hive
        .add_member(bob.hive.id(), doc, Power::Edit)
        .await?;
    // Bob receives Alice's CGKA operations without the certificates they cite,
    // so they wait.
    let events: Vec<_> = alice
        .hive
        .static_events_for_agent(bob.hive.id())
        .await?
        .into_values()
        .filter(|event| matches!(event, StaticEvent::CgkaOperation(_)))
        .collect();
    assert!(!events.is_empty());
    bob.hive.ingest_unsorted_static_events(events).await;
    let waiting = bob.hive.pending_events().await;
    assert!(!waiting.is_empty(), "precondition: events wait");
    KeyhiveStore::<Sendable, Ref>::put_pending_events(&bob.store, &waiting).await?;

    let bob2 = bob.restarted().await?;
    assert_eq!(
        bob.hive.pending_event_hashes().await,
        bob2.pending_event_hashes().await
    );
    Ok(())
}

/// The store lets a caller serve one peer without loading anything else:
/// operations by digest and the predecessor index.
#[tokio::test]
async fn operations_are_listed_by_document_and_loaded_by_digest() -> TestResult {
    let s = scenario().await?;
    let index = KeyhiveStore::<Sendable, Ref>::list_cgka_op_index(&s.alice.store, s.doc).await?;
    let all = KeyhiveStore::<Sendable, Ref>::load_cgka_ops(&s.alice.store, s.doc).await?;
    assert_eq!(index.len(), all.len());
    let digests: Vec<_> = index.iter().map(|row| row.digest).collect();
    let loaded = KeyhiveStore::<Sendable, Ref>::load_cgka_ops_by_digest(
        &s.alice.store,
        s.doc,
        &digests[..1],
    )
    .await?;
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].digest(), digests[0]);
    for row in &index {
        for predecessor in &row.predecessors {
            assert!(digests.contains(predecessor));
        }
    }
    let prekeys =
        KeyhiveStore::<Sendable, Ref>::list_prekey_op_digests(&s.alice.store, s.bob.hive.id())
            .await?;
    let ops = KeyhiveStore::<Sendable, Ref>::load_prekey_ops_by_digest(
        &s.alice.store,
        s.bob.hive.id(),
        &prekeys,
    )
    .await?;
    assert_eq!(ops.len(), prekeys.len());
    assert!(!ops.is_empty());
    Ok(())
}

/// An archive written to a store opens as the replica it describes.
#[tokio::test]
async fn an_archive_written_to_a_store_opens_as_the_same_replica() -> TestResult {
    let s = scenario().await?;
    let archive = s.bob.hive.into_archive().await?;
    let migrated = Store::default();
    archive.write_to_store::<Sendable, _>(&migrated).await?;

    let moved = Node {
        hive: s.bob.hive.clone(),
        signer: s.bob.signer.clone(),
        store: migrated,
    };
    let reopened = moved.restarted().await?;
    assert_eq!(
        answers(&s.bob.hive, s.doc, &s.first, &s.reply).await?,
        answers(&reopened, s.doc, &s.first, &s.reply).await?
    );
    Ok(())
}

/// Everything a replica says to peers and about its size, as digests, so that
/// replicas that know the same things compare equal however they came to know them.
async fn served(hive: &Hive, agents: &[Identifier]) -> TestResult<Served> {
    let all = hive.all_agent_events().await?;
    let mut per_agent = Vec::new();
    for agent in agents {
        per_agent.push((
            hive.static_events_for_agent(*agent)
                .await?
                .keys()
                .map(|digest| <[u8; 32]>::from(*digest))
                .collect(),
            hive.event_digests_for_agent(*agent)
                .await?
                .into_iter()
                .map(<[u8; 32]>::from)
                .collect(),
            all.digests_for(*agent)
                .into_iter()
                .map(<[u8; 32]>::from)
                .collect(),
        ));
    }
    Ok(Served {
        per_agent,
        all_events: all.events.keys().map(|d| <[u8; 32]>::from(*d)).collect(),
        total_ops: hive.total_ops().await?,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct Served {
    /// Per agent: the events it is sent, from `static_events_for_agent`,
    /// `event_digests_for_agent` and `all_agent_events`.
    per_agent: Vec<(BTreeSet<[u8; 32]>, BTreeSet<[u8; 32]>, BTreeSet<[u8; 32]>)>,
    all_events: BTreeSet<[u8; 32]>,
    total_ops: u64,
}

/// Every pair of replicas exchanges what it is sent.
async fn sync_all(nodes: &[Node]) -> TestResult {
    for from in nodes {
        for to in nodes {
            if from.hive.id() != to.hive.id() {
                to.receive_from(from).await?;
            }
        }
    }
    Ok(())
}

/// Replicas that found documents, add and remove members, write, and sync, as
/// `seed` decides.
async fn random_history(seed: u64) -> TestResult<Vec<Node>> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut nodes = Vec::new();
    for _ in 0..4 {
        nodes.push(Node::new().await);
    }
    for from in &nodes {
        for to in &nodes {
            if from.hive.id() != to.hive.id() {
                to.learn_individual(from).await;
            }
        }
    }
    for n in 0..rng.gen_range(1..=3u8) {
        let creator = rng.gen_range(0..nodes.len());
        let genesis = content_ref(&[seed as u8, n]);
        let doc = nodes[creator]
            .hive
            .generate_doc(vec![], nonempty![genesis])
            .await?;
        nodes[creator]
            .hive
            .set_content_heads(doc, [genesis])
            .await?;
        KeyhiveStore::<Sendable, Ref>::put_content_heads(&nodes[creator].store, doc, &[genesis])
            .await?;
        let mut editors = vec![creator];
        let mut readers = Vec::new();
        for other in (0..nodes.len()).filter(|other| *other != creator) {
            if !rng.gen_bool(0.7) {
                continue;
            }
            let power = if rng.gen_bool(0.5) {
                editors.push(other);
                Power::Edit
            } else {
                readers.push(other);
                Power::Read
            };
            nodes[creator]
                .hive
                .add_member(nodes[other].hive.id(), doc, power)
                .await?;
            nodes[other].receive_from(&nodes[creator]).await?;
        }
        for w in 0..rng.gen_range(1..=4u8) {
            let writer = &nodes[editors[rng.gen_range(0..editors.len())]];
            write(&writer.hive, &writer.store, doc, &[seed as u8, n, w], &[]).await?;
            sync_all(&nodes).await?;
        }
        if !readers.is_empty() && rng.gen_bool(0.5) {
            let removed = readers[rng.gen_range(0..readers.len())];
            nodes[creator]
                .hive
                .revoke_member(nodes[removed].hive.id(), true, doc)
                .await?;
            write(
                &nodes[creator].hive,
                &nodes[creator].store,
                doc,
                &[seed as u8, n, 9],
                &[],
            )
            .await?;
            sync_all(&nodes).await?;
        }
    }
    Ok(nodes)
}

/// A keyhive opened from its store serves peers and counts its operations as
/// one that loaded everything first does, and loads no document to do it.
#[tokio::test]
async fn serving_an_unloaded_keyhive_answers_like_a_loaded_one() -> TestResult {
    for seed in 0..6 {
        let nodes = random_history(seed).await?;
        let stranger = Node::new().await;
        let agents: Vec<Identifier> = nodes
            .iter()
            .chain([&stranger])
            .map(|node| node.hive.id().into())
            .collect();
        for node in &nodes {
            let lazy = node.reopened().await?;
            let from_lazy = served(&lazy, &agents).await?;
            // Serving reads rows without loading a document, which `cgka_ops_for_doc` would show.
            for doc in KeyhiveStore::<Sendable, Ref>::list_documents(&node.store).await? {
                assert!(
                    lazy.cgka_ops_for_doc(&doc).await.is_none() && !lazy.has_document(doc).await,
                    "seed {seed}: serving loaded a document"
                );
            }

            let eager = node.restarted().await?;
            assert_eq!(
                from_lazy,
                served(&eager, &agents).await?,
                "seed {seed}: unloaded and loaded keyhives differ"
            );
            assert_eq!(from_lazy.total_ops, eager.stats().await.total_ops());
            assert_eq!(
                from_lazy,
                served(&node.hive, &agents).await?,
                "seed {seed}: reopened and never restarted keyhives differ"
            );
        }
    }
    Ok(())
}

/// A count of operations does not move when a document is loaded, and grows
/// when an operation is added.
#[tokio::test]
async fn hydrating_a_document_does_not_change_the_count_of_operations() -> TestResult {
    let s = scenario().await?;
    let reopened = s.bob.reopened().await?;
    let before = reopened.total_ops().await?;
    assert!(before > 0);
    reopened.hydrate(s.doc).await?;
    assert_eq!(before, reopened.total_ops().await?);

    let carol = Node::new().await;
    s.alice.learn_individual(&carol).await;
    let before = s.alice.hive.total_ops().await?;
    s.alice
        .hive
        .add_member(carol.hive.id(), s.doc, Power::Read)
        .await?;
    assert!(s.alice.hive.total_ops().await? > before);
    Ok(())
}

/// A CGKA operation for a document that is not loaded waits, and the keyhive
/// names that document, so the caller loads it before ingesting again.
#[tokio::test]
async fn waiting_operations_name_their_documents() -> TestResult {
    let alice = Node::new().await;
    let bob = Node::new().await;
    alice.learn_individual(&bob).await;
    let doc = alice
        .hive
        .generate_doc(vec![], nonempty![content_ref(b"genesis")])
        .await?;
    alice
        .hive
        .add_member(bob.hive.id(), doc, Power::Edit)
        .await?;
    let events: Vec<_> = alice
        .hive
        .static_events_for_agent(bob.hive.id())
        .await?
        .into_values()
        .filter(|event| matches!(event, StaticEvent::CgkaOperation(_)))
        .collect();
    assert!(bob.hive.pending_documents().await.is_empty());
    bob.hive.ingest_unsorted_static_events(events).await;
    assert_eq!(bob.hive.pending_documents().await, BTreeSet::from([doc]));
    Ok(())
}

/// A write whose commit landed (its operation, its leaf secret and its content key are in the
/// store) but whose preparation was never applied here, because the commit was reported lost, can be
/// read once the document is read from the store again: the replayed graph holds the rotation, and
/// the secret of the leaf it rotated to comes from the store too, not only from what this
/// instance generated.
#[tokio::test]
async fn a_write_that_landed_and_was_never_applied_opens_once_the_document_is_read_again(
) -> TestResult {
    let alice = Node::new().await;
    let bob = Node::new().await;
    alice.learn_individual(&bob).await;
    let doc = alice
        .hive
        .generate_doc(vec![], nonempty![content_ref(b"genesis")])
        .await?;
    alice
        .hive
        .add_member(bob.hive.id(), doc, Power::Edit)
        .await?;

    let cr = content_ref(b"lost");
    let prepared = alice
        .hive
        .prepare_encrypt_content(doc, &cr, &[], b"lost", &[])
        .await?;
    assert!(prepared.rotation().is_some(), "the first write rotates");
    keep_preparation(&alice.store, &prepared).await;
    let encrypted = prepared.encrypted_content().clone();
    drop(prepared);

    // not applied: this instance holds neither the rotation nor its secret
    assert!(matches!(
        alice.hive.try_decrypt_content_keyed(doc, &encrypted).await,
        Err(DecryptError::KeyNotFound)
    ));

    alice.hive.evict(doc).await;
    alice.hive.hydrate(doc).await?;
    assert_eq!(
        read(&alice.hive, &alice.store, doc, &encrypted).await?,
        b"lost"
    );
    Ok(())
}

/// A membership change that ran between a write's commit and its apply makes the apply stale, and
/// the document is read again from the store: the write opens, though its rotation is concurrent
/// with the change.
#[tokio::test]
async fn a_write_opens_after_a_membership_change_ran_between_its_commit_and_its_apply() -> TestResult
{
    let alice = Node::new().await;
    let bob = Node::new().await;
    let carol = Node::new().await;
    alice.learn_individual(&bob).await;
    alice.learn_individual(&carol).await;
    let doc = alice
        .hive
        .generate_doc(vec![], nonempty![content_ref(b"genesis")])
        .await?;
    alice
        .hive
        .add_member(bob.hive.id(), doc, Power::Edit)
        .await?;

    let cr = content_ref(b"raced");
    let prepared = alice
        .hive
        .prepare_encrypt_content(doc, &cr, &[], b"raced", &[])
        .await?;
    keep_preparation(&alice.store, &prepared).await;
    let encrypted = prepared.encrypted_content().clone();

    // the change runs on memory that does not hold the rotation, and is kept
    alice
        .hive
        .add_member(carol.hive.id(), doc, Power::Read)
        .await?;
    for op in alice.hive.cgka_ops_for_doc(&doc).await.expect("held") {
        KeyhiveStore::<Sendable, Ref>::append_cgka_ops(&alice.store, doc, &[op]).await?;
    }
    assert!(
        alice
            .hive
            .apply_prepared_encryption(prepared)
            .await
            .is_err(),
        "the apply is stale"
    );

    alice.hive.evict(doc).await;
    alice.hive.hydrate(doc).await?;
    assert_eq!(
        read(&alice.hive, &alice.store, doc, &encrypted).await?,
        b"raced"
    );
    Ok(())
}

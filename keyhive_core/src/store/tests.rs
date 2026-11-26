//! A keyhive driven through a store and reopened from it answers like one that
//! never restarted, and opening it reads no document.

use super::{memory::MemoryKeyhiveStore, KeyhiveStore};
use crate::{
    content::heads::ContentHeads,
    event::static_event::StaticEvent,
    keyhive::{Keyhive, PreparedContent},
    listener::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener},
    principal::{
        active::LocalPrekeySecret,
        document::id::DocumentId,
        individual::{
            id::IndividualId,
            op::{add_key::AddKeyOp, rotate_key::RotateKeyOp, KeyOp},
        },
    },
};
use beekem::operation::CgkaOperation;
use future_form::{FutureForm, Sendable};
use futures::lock::Mutex;
use keyhive_content::{encrypted::EncryptedContent, store::memory::MemoryCiphertextStore};
use keyhive_crypto::{
    signer::memory::MemorySigner,
    verified::{Signed, Verified},
};
use keyline::{
    certificate::Certificate, contract::Keyline, delegation::Delegation, power::Power,
    revocation::Revocation,
};
use keyline_memory::MemoryKeyline;
use nonempty::nonempty;
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

    /// This replica as it comes back after a restart: its store, and the
    /// certificates its Keyline store holds.
    async fn restarted(&self) -> TestResult<Hive> {
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
        .prepare_encrypt_content(doc, &cr, preds, content)
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

/// Opening a keyhive reads no document: a document's CGKA operations are read
/// the first time it is used, and the others' never are.
#[tokio::test]
async fn opening_reads_no_document_until_it_is_used() -> TestResult {
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

    let reopened = alice.restarted().await?;
    assert!(
        alice.store.cgka_reads().is_empty(),
        "opening read a document"
    );
    let baseline = alice.store.cgka_reads().len();
    assert!(reopened.has_document(docs[1]).await);
    let reads = alice.store.cgka_reads();
    assert_eq!(
        &reads[baseline..],
        &[docs[1]],
        "only the used document is read"
    );
    // Used again, it is not read again.
    assert!(reopened.has_document(docs[1]).await);
    assert_eq!(alice.store.cgka_reads().len(), baseline + 1);
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
        .prepare_encrypt_content(doc, &cr, &preds, b"reply")
        .await?;
    assert_eq!(prepared.preliminary().cgka_ops.len(), 1);
    assert_eq!(prepared.preliminary().key_pairs.len(), 1);
    let (rotated_to, _) = prepared.preliminary().key_pairs[0].clone();
    drop(prepared);

    // The transaction rolled back: the next preparation carries it again.
    let prepared = bob
        .hive
        .prepare_encrypt_content(doc, &cr, &preds, b"reply")
        .await?;
    assert_eq!(prepared.preliminary().cgka_ops.len(), 1);
    assert_eq!(prepared.preliminary().key_pairs[0].0, rotated_to);
    keep_preparation(&bob.store, &prepared).await;
    bob.hive.apply_prepared_encryption(prepared).await?;

    // Acknowledged by applying: not repeated.
    let next = bob
        .hive
        .prepare_encrypt_content(doc, &content_ref(b"more"), &[cr], b"more")
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

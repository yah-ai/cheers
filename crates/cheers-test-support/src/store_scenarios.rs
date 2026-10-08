//! Shared store-contract scenarios. Each is an `async fn` that takes the
//! constructed store(s) and exercises the trait surface. The per-backend test
//! files wire concrete handles, then call these.
//!
//! The functions panic via `assert!` on failure — the contract is "if this
//! returns, the impl satisfies the spec for that scenario."
//!
//! # Why these live here rather than in one backend's `tests/`
//!
//! They started as `cheers-sqlx/tests/common/mod.rs`, serving that crate's
//! pg and sqlite backends. `cheers-turso` is a third implementation of the
//! same traits over a different engine, and the whole claim being made about
//! it — "the account database can move into a cell without a rewrite" — is
//! precisely that it satisfies this contract identically.
//!
//! Copying the suite into the new crate would have made that claim
//! unfalsifiable in the way that matters: the two copies would agree on the
//! day they were written and drift thereafter, and the drift would land in
//! whichever backend was being touched less. One suite, run by every backend,
//! makes "these behave the same" a mechanically checked property.
//!
//! `cheers-sqlx`'s `tests/common/mod.rs` is now a re-export of this module, so
//! its `sqlite.rs` / `pg.rs` call sites are unchanged.

use cheers_core::{
    Credential, DeviceBinding, DeviceId, Principal, PrincipalId, PrincipalStatus, Revoked, Scope,
    StoreError, Subject, UserId,
};
use cheers_server::audit::{AuditQuery, AuditRecord, AuditStore};
use cheers_core::yah_scopes;
use cheers_server::ownership::{NewOwnership, OwnershipStore};
use cheers_server::store::{
    NewUser, PasskeyCredentialStore, ProviderKey, RefreshStore, RefreshTokenRecord, UserStore,
};
use cheers_server::{ServicePrincipalStore, SigningKey, SigningKeyStatus};
use cheers_server::user_tokens::{UserTokenRecord, UserTokenStore};
use cheers_server::{BindingSequenceStore, RevocationWriter};
use cheers_verify::RevocationReader;

// ---------------------------------------------------------------------------
// UserStore
// ---------------------------------------------------------------------------

pub async fn user_store_lifecycle<U: UserStore + ?Sized>(users: &U) {
    // Empty lookup.
    let none = users
        .find_by_provider(&ProviderKey::OidcGoogle, "google-sub-1")
        .await
        .expect("find_by_provider should not error on missing");
    assert!(none.is_none());

    // Create + link.
    let u = users
        .create(NewUser::new().with_email("alice@example.com").with_name("Alice"))
        .await
        .expect("create user");
    assert_eq!(u.email.as_deref(), Some("alice@example.com"));
    assert_eq!(u.name.as_deref(), Some("Alice"));

    users
        .link_provider(&u.id, &ProviderKey::OidcGoogle, "google-sub-1")
        .await
        .expect("link google");

    // Idempotent re-link to the same user.
    users
        .link_provider(&u.id, &ProviderKey::OidcGoogle, "google-sub-1")
        .await
        .expect("idempotent re-link");

    // Different user trying the same (provider, subject) -> Conflict.
    let u2 = users.create(NewUser::new()).await.expect("create user 2");
    match users
        .link_provider(&u2.id, &ProviderKey::OidcGoogle, "google-sub-1")
        .await
    {
        Err(StoreError::Conflict) => {}
        other => panic!("expected Conflict, got {other:?}"),
    }

    // Lookup the linked user.
    let found = users
        .find_by_provider(&ProviderKey::OidcGoogle, "google-sub-1")
        .await
        .expect("find_by_provider")
        .expect("user should exist");
    assert_eq!(found.id, u.id);

    // OidcGeneric carries its issuer through the (provider, issuer, subject)
    // composite key — different issuers don't collide.
    let generic_a = ProviderKey::OidcGeneric {
        issuer: "https://idp-a".into(),
    };
    let generic_b = ProviderKey::OidcGeneric {
        issuer: "https://idp-b".into(),
    };
    users
        .link_provider(&u.id, &generic_a, "sub-x")
        .await
        .expect("link idp-a");
    users
        .link_provider(&u2.id, &generic_b, "sub-x")
        .await
        .expect("link idp-b — same subject, different issuer is fine");

    let found_a = users.find_by_provider(&generic_a, "sub-x").await.unwrap();
    let found_b = users.find_by_provider(&generic_b, "sub-x").await.unwrap();
    assert_eq!(found_a.map(|u| u.id), Some(u.id.clone()));
    assert_eq!(found_b.map(|u| u.id), Some(u2.id.clone()));
}

/// The by-id accessor — the path a service takes when it holds a verified
/// bearer and nothing else. `Claims::sub` is a `UserId`, so this is the only
/// way back to the record without re-deriving `(provider, subject)`.
///
/// Pins three things a backend can plausibly get wrong: an unknown id is
/// `Ok(None)` and not an error; a fetched user carries the same `email`/`name`
/// the create returned (not just a matching id); and the id is a discriminating
/// key, so a second user's row never comes back for the first user's id.
pub async fn user_store_get_by_id<U: UserStore + ?Sized>(users: &U) {
    // Unknown id is a miss, not a failure.
    let missing = users
        .get(&UserId::new("no-such-user"))
        .await
        .expect("get should not error on a missing id");
    assert!(missing.is_none(), "unknown id must be Ok(None)");

    let created = users
        .create(
            NewUser::new()
                .with_email("bob@example.com")
                .with_name("Bob"),
        )
        .await
        .expect("create user");

    // Round-trip: every field the create returned survives the fetch.
    let fetched = users
        .get(&created.id)
        .await
        .expect("get")
        .expect("just-created user must be findable by its own id");
    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.email.as_deref(), Some("bob@example.com"));
    assert_eq!(fetched.name.as_deref(), Some("Bob"));

    // A NULL email/name round-trips as None rather than an empty string.
    let sparse = users
        .create(NewUser::new())
        .await
        .expect("create sparse user");
    let fetched_sparse = users
        .get(&sparse.id)
        .await
        .expect("get sparse")
        .expect("sparse user must be findable");
    assert_eq!(fetched_sparse.id, sparse.id);
    assert!(
        fetched_sparse.email.is_none(),
        "absent email must stay None"
    );
    assert!(fetched_sparse.name.is_none(), "absent name must stay None");

    // The id discriminates — a WHERE clause that matched too loosely would
    // hand back the wrong row here.
    assert_ne!(created.id, sparse.id);
    assert_eq!(
        users.get(&created.id).await.expect("re-get").map(|u| u.id),
        Some(created.id.clone()),
    );

    // A provider link does not gate the by-id path: a user with no link is
    // still reachable by id (`find_by_provider` is the only linked-only view).
    users
        .link_provider(&created.id, &ProviderKey::Email, "bob@example.com")
        .await
        .expect("link email provider");
    let after_link = users
        .get(&sparse.id)
        .await
        .expect("get unlinked user")
        .expect("an unlinked user is still reachable by id");
    assert_eq!(after_link.id, sparse.id);
}

// ---------------------------------------------------------------------------
// RefreshStore
// ---------------------------------------------------------------------------

/// Build a refresh record. The fixture user must already exist in the users
/// table (the per-backend tests seed it before calling this).
pub fn fixture_refresh(
    token: &str,
    chain_id: &str,
    parent: Option<&str>,
    user: &UserId,
    device: &DeviceId,
    issued_at: i64,
    expires_at: i64,
) -> RefreshTokenRecord {
    RefreshTokenRecord::new(
        token.into(),
        chain_id.into(),
        parent.map(str::to_owned),
        user.clone(),
        device.clone(),
        issued_at,
        expires_at,
        false,
        false,
    )
}

pub async fn refresh_store_put_get_consume_revoke<R: RefreshStore + ?Sized>(
    refresh: &R,
    user: &UserId,
    device: &DeviceId,
) {
    let r1 = fixture_refresh("tok-1", "chain-A", None, user, device, 100, 1_000);
    refresh.put(&r1).await.expect("put root");

    let back = refresh.get("tok-1").await.expect("get").expect("present");
    assert_eq!(back, r1);
    assert!(refresh.get("missing").await.unwrap().is_none());

    // First consume transitions the row and reports true.
    assert!(
        refresh.mark_consumed("tok-1").await.expect("consume"),
        "first consume should transition the row"
    );
    let back = refresh.get("tok-1").await.unwrap().unwrap();
    assert!(back.consumed);
    assert!(!back.revoked);
    // A second consume of the same token finds nothing unconsumed and reports
    // false — the atomic double-spend guard the rotator reads as a replay.
    assert!(
        !refresh.mark_consumed("tok-1").await.expect("second consume"),
        "second consume must report no transition"
    );

    // Successor in same chain.
    let r2 = fixture_refresh(
        "tok-2",
        "chain-A",
        Some("tok-1"),
        user,
        device,
        110,
        1_010,
    );
    refresh.put(&r2).await.expect("put successor");

    // Revoke chain marks both records.
    refresh.revoke_chain("chain-A").await.expect("revoke");
    let t1 = refresh.get("tok-1").await.unwrap().unwrap();
    let t2 = refresh.get("tok-2").await.unwrap().unwrap();
    assert!(t1.revoked);
    assert!(t2.revoked);

    // Re-revoke is idempotent.
    refresh.revoke_chain("chain-A").await.expect("idempotent");

    // mark_consumed on a missing token reports no transition (Ok(false)), not
    // an error — the rotator only calls it for a token it just read.
    assert!(
        !refresh.mark_consumed("never-existed").await.expect("missing"),
        "consuming an absent token reports no transition"
    );
}

pub async fn refresh_store_other_chain_unaffected<R: RefreshStore + ?Sized>(
    refresh: &R,
    user: &UserId,
    device: &DeviceId,
) {
    refresh
        .put(&fixture_refresh(
            "ca-1", "chain-CA", None, user, device, 200, 1_200,
        ))
        .await
        .unwrap();
    refresh
        .put(&fixture_refresh(
            "cb-1", "chain-CB", None, user, device, 200, 1_200,
        ))
        .await
        .unwrap();
    refresh.revoke_chain("chain-CA").await.unwrap();
    assert!(refresh.get("ca-1").await.unwrap().unwrap().revoked);
    assert!(!refresh.get("cb-1").await.unwrap().unwrap().revoked);
}

// ---------------------------------------------------------------------------
// PasskeyCredentialStore
// ---------------------------------------------------------------------------

pub fn fixture_passkey_cred(user: &UserId, device: &str, material_obj: &str) -> Credential {
    // material_obj is a JSON literal (e.g. r#"{"v":1}"#) — the store wants
    // valid JSON bytes since the trait sits on cheers-core's Credential
    // which carries Vec<u8>, but pg's JSONB rejects non-JSON.
    Credential::new(
        user.clone(),
        DeviceId::new(device),
        DeviceBinding::Passkey,
        material_obj.as_bytes().to_vec(),
    )
}

pub async fn passkey_store_round_trip<P: PasskeyCredentialStore + ?Sized>(
    passkeys: &P,
    user: &UserId,
) {
    assert!(passkeys.list_for_user(user).await.unwrap().is_empty());

    let phone = fixture_passkey_cred(user, "phone", r#"{"v":1,"id":"phone"}"#);
    let laptop = fixture_passkey_cred(user, "laptop", r#"{"v":1,"id":"laptop"}"#);
    passkeys.put(&phone).await.expect("put phone");
    passkeys.put(&laptop).await.expect("put laptop");

    // Duplicate (user, device) -> Conflict.
    match passkeys.put(&phone).await {
        Err(StoreError::Conflict) => {}
        other => panic!("expected Conflict, got {other:?}"),
    }

    let mut list = passkeys.list_for_user(user).await.unwrap();
    list.sort_by(|a, b| a.device_id.as_str().cmp(b.device_id.as_str()));
    assert_eq!(list.len(), 2);
    // material round-trips as valid JSON (the serde re-encode normalizes
    // whitespace but the value shape is preserved).
    let parse = |c: &Credential| {
        let v: serde_json::Value = serde_json::from_slice(&c.material).unwrap();
        v["id"].as_str().unwrap().to_owned()
    };
    assert_eq!(parse(&list[0]), "laptop");
    assert_eq!(parse(&list[1]), "phone");

    // Update rewrites the material (counter advance simulated by bumping v).
    let phone_v2 = fixture_passkey_cred(user, "phone", r#"{"v":2,"id":"phone"}"#);
    passkeys.update(&phone_v2).await.expect("update phone");
    let list = passkeys.list_for_user(user).await.unwrap();
    let phone_row = list.iter().find(|c| c.device_id.as_str() == "phone").unwrap();
    let v: serde_json::Value = serde_json::from_slice(&phone_row.material).unwrap();
    assert_eq!(v["v"].as_i64(), Some(2));

    // Update on missing -> NotFound.
    let ghost = fixture_passkey_cred(user, "ghost", r#"{"v":1}"#);
    match passkeys.update(&ghost).await {
        Err(StoreError::NotFound) => {}
        other => panic!("expected NotFound, got {other:?}"),
    }

    // Delete returns NotFound the second time.
    passkeys
        .delete(user, &DeviceId::new("phone"))
        .await
        .expect("delete phone");
    match passkeys.delete(user, &DeviceId::new("phone")).await {
        Err(StoreError::NotFound) => {}
        other => panic!("expected NotFound, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

/// One row per identity, one bound (R732-T7): a re-revoke keeps the larger
/// bound and advances the epoch only when the bound rose; a device masks
/// bindings below its `at_seq`, a membership snapshots below its `at_epoch`.
pub async fn revocation_writer_and_reader<W>(revoke: &W)
where
    W: RevocationWriter + RevocationReader + ?Sized,
{
    let alice = UserId::new("alice");
    let empty = revoke.snapshot().await.unwrap();
    assert!(empty.revoked.is_empty());
    let epoch = || async { revoke.snapshot().await.unwrap().epoch };

    // jti: exp far in the future so no store reads it as lapsed.
    let far = 4_000_000_000_i64;
    assert!(!revoke.is_revoked("tok-x").await.unwrap());
    revoke.revoke(&Revoked::jti("tok-x", Some(far))).await.unwrap();
    assert!(revoke.is_revoked("tok-x").await.unwrap());
    let e1 = epoch().await;
    assert!(e1 > empty.epoch, "a revoke advances the epoch");
    // An equal or lower bound is a no-op that leaves the epoch alone.
    revoke.revoke(&Revoked::jti("tok-x", Some(far))).await.unwrap();
    revoke.revoke(&Revoked::jti("tok-x", Some(far - 1))).await.unwrap();
    assert_eq!(epoch().await, e1);
    // A raise advances it; None (never lapses) is the top bound.
    revoke.revoke(&Revoked::jti("tok-x", None)).await.unwrap();
    let e2 = epoch().await;
    assert!(e2 > e1);
    revoke.revoke(&Revoked::jti("tok-x", Some(far + 1))).await.unwrap();
    assert_eq!(epoch().await, e2);
    // Independence.
    assert!(!revoke.is_revoked("tok-y").await.unwrap());

    // Devices: mask seq < at_seq only, so a re-enrolled binding is admitted.
    let phone = DeviceId::new("phone");
    assert!(!revoke.is_device_revoked(&phone, 0).await.unwrap());
    revoke.revoke(&Revoked::device("phone", 100)).await.unwrap();
    assert!(revoke.is_device_revoked(&phone, 99).await.unwrap());
    assert!(!revoke.is_device_revoked(&phone, 100).await.unwrap());
    assert!(!revoke.is_device_revoked(&phone, 101).await.unwrap());
    assert!(!revoke.is_device_revoked(&DeviceId::new("laptop"), 0).await.unwrap());
    let e3 = epoch().await;
    assert!(e3 > e2);
    revoke.revoke(&Revoked::device("phone", 50)).await.unwrap();
    assert_eq!(epoch().await, e3, "a lower device bound is a no-op");
    revoke.revoke(&Revoked::device("phone", 200)).await.unwrap();
    let e4 = epoch().await;
    assert!(e4 > e3, "a raised device bound advances the epoch");
    assert!(revoke.is_device_revoked(&phone, 150).await.unwrap());

    // Memberships: mask snapshot_epoch < at_epoch only.
    let alice = PrincipalId::from(&alice);
    revoke
        .revoke(&Revoked::membership("namespace", "ns-1", alice.clone(), 7))
        .await
        .unwrap();
    // Origin stores hold plaintext rows; the resource key is not consulted.
    let k = cheers_verify::test_revocation_key("namespace", "ns-1");
    assert!(revoke.is_membership_revoked(&k, "namespace", "ns-1", &alice, 6).await.unwrap());
    assert!(!revoke.is_membership_revoked(&k, "namespace", "ns-1", &alice, 7).await.unwrap());
    assert!(!revoke.is_membership_revoked(&k, "namespace", "ns-2", &alice, 0).await.unwrap());
    assert!(!revoke.is_membership_revoked(&k, "room", "ns-1", &alice, 0).await.unwrap());
    assert!(!revoke
        .is_membership_revoked(&k, "namespace", "ns-1", &PrincipalId::user("bob"), 0)
        .await
        .unwrap());
    // A Key principal (knock.md) is a membership subject like any user, and
    // a user spelled with the key's id string is a different subject.
    let key = PrincipalId::from_public_key(&[0x4b; 32]);
    let e_key = epoch().await;
    revoke.revoke(&Revoked::membership("namespace", "ns-1", key.clone(), 9)).await.unwrap();
    assert!(epoch().await > e_key);
    assert!(revoke.is_membership_revoked(&k, "namespace", "ns-1", &key, 8).await.unwrap());
    assert!(!revoke.is_membership_revoked(&k, "namespace", "ns-1", &key, 9).await.unwrap());
    assert!(!revoke
        .is_membership_revoked(&k, "namespace", "ns-1", &PrincipalId::user(key.id.clone()), 0)
        .await
        .unwrap());
    // Kinds don't bleed: a jti spelled like a device is not that device.
    assert!(!revoke.is_device_revoked(&DeviceId::new("tok-x"), 0).await.unwrap());

    let snap = revoke.snapshot().await.unwrap();
    assert!(snap.epoch > e4);
    let mut got = snap.revoked;
    got.sort_by(|a, b| a.identity().cmp(&b.identity()));
    assert_eq!(
        got,
        vec![
            Revoked::jti("tok-x", None),
            Revoked::device("phone", 200),
            // Identity order: `key:..` sorts before `user:alice`.
            Revoked::membership("namespace", "ns-1", key, 9),
            Revoked::membership("namespace", "ns-1", alice, 7),
        ]
    );
}

// ---------------------------------------------------------------------------
// BindingSequenceStore (R732-F5)
// ---------------------------------------------------------------------------

/// Every backend advances a device's sequence by
/// [`next_binding_seq`](cheers_server::next_binding_seq): clock-floored on
/// first use, `+1` when the clock has not moved past it, never backwards, and
/// independently per device.
pub async fn binding_sequence_store<S: BindingSequenceStore + ?Sized>(store: &S) {
    let (a, b) = (DeviceId::new("node:a"), DeviceId::new("node:b"));
    assert_eq!(store.next_binding_seq(&a, 1_000).await.unwrap(), 1_000);
    assert_eq!(store.next_binding_seq(&a, 1_000).await.unwrap(), 1_001);
    // The issuer clock went backwards: still above what was issued.
    assert_eq!(store.next_binding_seq(&a, 10).await.unwrap(), 1_002);
    // The clock moved well past it: the floor wins.
    assert_eq!(store.next_binding_seq(&a, 5_000).await.unwrap(), 5_000);
    // Another device starts from its own floor.
    assert_eq!(store.next_binding_seq(&b, 10).await.unwrap(), 10);
    // A pre-epoch clock still yields a positive first sequence.
    assert_eq!(store.next_binding_seq(&DeviceId::new("node:c"), -5).await.unwrap(), 1);
    assert_eq!(store.next_binding_seq(&a, 0).await.unwrap(), 5_001);
}

// ---------------------------------------------------------------------------
// OwnershipStore (R020-F4)
// ---------------------------------------------------------------------------

pub async fn ownership_store_lifecycle<O: OwnershipStore + ?Sized>(store: &O) {
    let yubaba = PrincipalId::service("yubaba");
    let alice = PrincipalId::user("alice");
    let bob = PrincipalId::user("bob");
    let camp_a = PrincipalId::camp("camp-a");
    let camp_b = PrincipalId::camp("camp-b");

    // Insert one row on alice's behalf for camp-a.
    let new1 = NewOwnership::new(
        camp_a.clone(),
        "service",
        "svc-1",
        "owns",
        yubaba.clone(),
        Some(alice.clone()),
    )
    .expect("validate new1");
    let row1 = store.insert(&new1, 100).await.expect("insert 1").row;
    assert_eq!(row1.subject, Subject::Principal(camp_a.clone()));
    assert_eq!(row1.granted_by, yubaba);
    assert_eq!(row1.on_behalf_of, Some(alice.clone()));
    assert_eq!(row1.granted_at, 100);
    assert!(row1.revoked_at.is_none());
    assert!(!row1.id.is_empty());

    // Insert two more — one for camp-a on alice's behalf, one for camp-b on bob's.
    let row2 = store
        .insert(
            &NewOwnership::new(
                camp_a.clone(),
                "arch_doc",
                "doc-1",
                "owns",
                yubaba.clone(),
                Some(alice.clone()),
            )
            .unwrap(),
            101,
        )
        .await
        .unwrap()
        .row;
    let row3 = store
        .insert(
            &NewOwnership::new(
                camp_b.clone(),
                "service",
                "svc-2",
                "owns",
                yubaba.clone(),
                Some(bob.clone()),
            )
            .unwrap(),
            102,
        )
        .await
        .unwrap()
        .row;

    // get() roundtrip preserves every column.
    let back = store.get(&row1.id).await.unwrap().unwrap();
    assert_eq!(back, row1);
    assert!(store.get("ghost-id").await.unwrap().is_none());

    // list_for_principal returns live rows for the principal, drops others.
    let mut camp_a_rows = store.list_for_principal(&camp_a).await.unwrap();
    camp_a_rows.sort_by_key(|a| a.granted_at);
    assert_eq!(camp_a_rows.len(), 2);
    assert_eq!(camp_a_rows[0].id, row1.id);
    assert_eq!(camp_a_rows[1].id, row2.id);

    let camp_b_rows = store.list_for_principal(&camp_b).await.unwrap();
    assert_eq!(camp_b_rows.len(), 1);
    assert_eq!(camp_b_rows[0].id, row3.id);

    // revoke_by_id soft-deletes one row.
    store.revoke_by_id(&row2.id, 200).await.unwrap();
    let back = store.get(&row2.id).await.unwrap().unwrap();
    assert_eq!(back.revoked_at, Some(200));
    let live_for_camp_a = store.list_for_principal(&camp_a).await.unwrap();
    assert_eq!(live_for_camp_a.len(), 1, "revoked row must drop out of list");
    assert_eq!(live_for_camp_a[0].id, row1.id);

    // Re-revoke is idempotent — same revoked_at, no error.
    store.revoke_by_id(&row2.id, 999).await.unwrap();
    let back = store.get(&row2.id).await.unwrap().unwrap();
    assert_eq!(back.revoked_at, Some(200), "re-revoke must not overwrite revoked_at");

    // revoke_by_id on an unknown id => NotFound.
    match store.revoke_by_id("ghost-id", 200).await {
        Err(StoreError::NotFound) => {}
        other => panic!("expected NotFound, got {other:?}"),
    }

    // Holder cascade for camp-a sweeps row1 (its last live row); camp-b's row3
    // untouched.
    let before = store.current_version().await.unwrap();
    let swept = store.revoke_by_principal(&camp_a, 300).await.unwrap();
    assert!(swept > before, "the sweep advances the ownership version");
    assert!(store.list_for_principal(&camp_a).await.unwrap().is_empty());
    assert_eq!(store.list_for_principal(&camp_b).await.unwrap().len(), 1);
    // The history still names every row camp-a held, each revoked when it was:
    // row1 by the sweep, row2 by the earlier revoke_by_id.
    let mut history = store.list_history_for_principal(&camp_a).await.unwrap();
    history.sort_by_key(|r| r.granted_at);
    let revoked: Vec<_> = history.iter().map(|r| (r.id.clone(), r.revoked_at)).collect();
    assert_eq!(revoked, vec![(row1.id.clone(), Some(300)), (row2.id.clone(), Some(200))]);

    // Cascading revoke is idempotent — the second call sweeps nothing and
    // reports the version unchanged.
    let swept_again = store.revoke_by_principal(&camp_a, 400).await.unwrap();
    assert_eq!(swept_again, swept);
    assert_eq!(store.list_history_for_principal(&camp_a).await.unwrap().len(), 2);
}

/// D4: `granted_by` may be any kind, and lifecycle follows the holder — the
/// row dies with its `principal_id`, never with its granter or its
/// `on_behalf_of` user.
pub async fn ownership_store_revoke_follows_holder<O: OwnershipStore + ?Sized>(store: &O) {
    let operator = PrincipalId::user("operator");
    let alice = PrincipalId::user("alice");
    let bob = PrincipalId::user("bob");

    // A user-granted row inserts and lists.
    let granted = store
        .insert(
            &NewOwnership::new(
                alice.clone(),
                "project",
                "p-1",
                "admin",
                operator.clone(),
                Some(operator.clone()),
            )
            .unwrap(),
            100,
        )
        .await
        .expect("user-granted insert")
        .row;
    assert_eq!(granted.granted_by, operator);
    let alice_rows = store.list_for_principal(&alice).await.unwrap();
    assert_eq!(alice_rows.len(), 1);
    assert_eq!(alice_rows[0], granted);

    let bob_row = store
        .insert(
            &NewOwnership::new(
                bob.clone(),
                "project",
                "p-1",
                "reader",
                operator.clone(),
                Some(operator.clone()),
            )
            .unwrap(),
            101,
        )
        .await
        .unwrap()
        .row;
    // The operator also holds a row of their own.
    store
        .insert(
            &NewOwnership::new(
                operator.clone(),
                "project",
                "p-1",
                "owner",
                PrincipalId::service("cheers"),
                None,
            )
            .unwrap(),
            102,
        )
        .await
        .unwrap()
        .row;

    // Deleting the operator sweeps only the row they HOLD. Rows they granted,
    // and rows attributed to them via on_behalf_of, survive.
    store.revoke_by_principal(&operator, 200).await.unwrap();
    assert!(store.list_for_principal(&operator).await.unwrap().is_empty());
    assert_eq!(store.list_for_principal(&alice).await.unwrap().len(), 1);
    assert_eq!(store.list_for_principal(&bob).await.unwrap().len(), 1);

    // Deleting a holder cascades that holder's rows and nobody else's.
    store.revoke_by_principal(&alice, 300).await.unwrap();
    assert_eq!(
        store.get(&granted.id).await.unwrap().unwrap().revoked_at,
        Some(300)
    );
    assert!(store.get(&bob_row.id).await.unwrap().unwrap().revoked_at.is_none());
}

/// R732-F1: a tuple's subject may be a set (`namespace/n1#member`). Set rows
/// round-trip, list by the set's resource, show up per resource, and never
/// leak into a principal's own rows or its holder cascade.
pub async fn ownership_store_subject_sets<O: OwnershipStore + ?Sized>(store: &O) {
    let operator = PrincipalId::user("operator");
    let alice = PrincipalId::user("alice");
    let members = Subject::set("namespace", "n1", "member");
    let admins = Subject::set("namespace", "n1", "admin");

    let set_row = store
        .insert(
            &NewOwnership::new(members.clone(), "room", "r1", "owner", operator.clone(), None)
                .unwrap(),
            100,
        )
        .await
        .expect("set-subject insert")
        .row;
    assert_eq!(set_row.subject, members);
    assert_eq!(store.get(&set_row.id).await.unwrap().unwrap(), set_row);

    let admin_row = store
        .insert(
            &NewOwnership::new(admins.clone(), "room", "r2", "owner", operator.clone(), None)
                .unwrap(),
            101,
        )
        .await
        .unwrap()
        .row;
    // Other resources' sets and principal rows on the same resource stay out.
    store
        .insert(
            &NewOwnership::new(
                Subject::set("namespace", "n2", "member"),
                "room",
                "r1",
                "reader",
                operator.clone(),
                None,
            )
            .unwrap(),
            102,
        )
        .await
        .unwrap()
        .row;
    let alice_row = store
        .insert(
            &NewOwnership::new(alice.clone(), "room", "r1", "reader", operator.clone(), None)
                .unwrap(),
            103,
        )
        .await
        .unwrap()
        .row;

    // Every relation's set on (namespace, n1), and nothing else.
    let mut on_n1 = store.list_for_subject_set("namespace", "n1").await.unwrap();
    on_n1.sort_by_key(|r| r.granted_at);
    assert_eq!(on_n1, vec![set_row.clone(), admin_row.clone()]);
    assert!(store.list_for_subject_set("namespace", "ghost").await.unwrap().is_empty());
    assert!(
        store.list_for_subject_set("user", "alice").await.unwrap().is_empty(),
        "a principal subject is never a set"
    );

    // Per resource, both subject forms are listed.
    let mut on_r1 = store.list_for_resource("room", "r1").await.unwrap();
    on_r1.sort_by_key(|r| r.granted_at);
    assert_eq!(on_r1.len(), 3);
    assert_eq!(on_r1[0], set_row);
    assert_eq!(on_r1[2], alice_row);

    // A principal's own rows never include a set row.
    assert_eq!(store.list_for_principal(&alice).await.unwrap(), vec![alice_row]);
    assert!(store.list_for_principal(&operator).await.unwrap().is_empty());

    // The holder cascade sweeps principal rows only; set rows survive it.
    store.revoke_by_principal(&alice, 200).await.unwrap();
    assert!(store.list_for_principal(&alice).await.unwrap().is_empty());
    assert_eq!(store.list_for_subject_set("namespace", "n1").await.unwrap().len(), 2);

    // A revoked set row drops out of the set listing.
    store.revoke_by_id(&set_row.id, 300).await.unwrap();
    assert_eq!(store.list_for_subject_set("namespace", "n1").await.unwrap(), vec![admin_row]);
}

/// R732-T9: `list_for_kind` returns every live row of one `resource_kind`
/// across resources and subject forms, nothing of any other kind, nothing
/// revoked, and nothing for a kind with no rows.
pub async fn ownership_store_list_for_kind<O: OwnershipStore + ?Sized>(store: &O) {
    let operator = PrincipalId::user("operator");
    let alice = PrincipalId::user("alice");
    let mut ins = Vec::new();
    for (i, (subject, kind, id)) in [
        (Subject::from(alice.clone()), "publish-scope", "s1"),
        (Subject::set("namespace", "n1", "member"), "publish-scope", "s2"),
        (Subject::from(alice.clone()), "namespace", "n1"),
        (Subject::from(alice.clone()), "publish-scope", "s3"),
    ]
    .into_iter()
    .enumerate()
    {
        let row = store
            .insert(
                &NewOwnership::new(subject, kind, id, "owns", operator.clone(), None).unwrap(),
                100 + i as i64,
            )
            .await
            .unwrap()
            .row;
        ins.push(row);
    }
    store.revoke_by_id(&ins[3].id, 200).await.unwrap();

    let mut scopes = store.list_for_kind("publish-scope").await.unwrap();
    scopes.sort_by_key(|r| r.granted_at);
    assert_eq!(scopes, vec![ins[0].clone(), ins[1].clone()], "live rows of the kind only");
    assert_eq!(store.list_for_kind("namespace").await.unwrap(), vec![ins[2].clone()]);
    assert!(store.list_for_kind("ghost").await.unwrap().is_empty());
}

/// R732-F4: the store-wide ownership version. Every write that changes a row
/// advances it to `max(v + 1, now)` and reports the version it produced; a
/// no-op write and every read advance nothing. Run against a fresh store.
/// R732-T10: a resource's membership-revocation key is created on first use
/// and never changes afterwards; distinct resources get distinct keys.
pub async fn ownership_store_revocation_key<O: OwnershipStore + ?Sized>(store: &O) {
    let a = store.revocation_key("namespace", "rk-1").await.unwrap();
    assert_eq!(store.revocation_key("namespace", "rk-1").await.unwrap(), a, "a key is immutable once created");
    assert_ne!(store.revocation_key("namespace", "rk-2").await.unwrap(), a);
    // Kind and id are both part of the resource.
    assert_ne!(store.revocation_key("room", "rk-1").await.unwrap(), a);
    // Keys do not move the ownership version: they are not tuples.
    let v = store.current_version().await.unwrap();
    store.revocation_key("namespace", "rk-3").await.unwrap();
    assert_eq!(store.current_version().await.unwrap(), v);
}

/// R734-F3: an admission policy row round-trips per resource, its write and
/// its delete each advance the ownership version, and a resource with no row
/// reads `None` (closed).
pub async fn ownership_store_admission_policy<O: OwnershipStore + ?Sized>(store: &O) {
    use cheers_core::{AdmissionMode, AdmissionPolicy, Confirmation};
    assert_eq!(store.admission_policy("namespace", "ap-1").await.unwrap(), None);
    let v0 = store.current_version().await.unwrap();
    let knock = AdmissionPolicy::new(AdmissionMode::Knock, "guest").with_min_confirmation("member", Confirmation::Scan);
    let v1 = store.set_admission_policy("namespace", "ap-1", Some(&knock), 10).await.unwrap();
    assert!(v1 > v0);
    assert_eq!(store.current_version().await.unwrap(), v1);
    assert_eq!(store.admission_policy("namespace", "ap-1").await.unwrap(), Some(knock.clone()));
    // Kind and id are both part of the resource.
    assert_eq!(store.admission_policy("room", "ap-1").await.unwrap(), None);
    assert_eq!(store.admission_policy("namespace", "ap-2").await.unwrap(), None);
    // Tightening overwrites in place and advances again.
    let closed = AdmissionPolicy { mode: AdmissionMode::Closed, ..knock };
    let v2 = store.set_admission_policy("namespace", "ap-1", Some(&closed), 10).await.unwrap();
    assert!(v2 > v1);
    assert_eq!(store.admission_policy("namespace", "ap-1").await.unwrap(), Some(closed));
    let v3 = store.set_admission_policy("namespace", "ap-1", None, 10).await.unwrap();
    assert!(v3 > v2);
    assert_eq!(store.admission_policy("namespace", "ap-1").await.unwrap(), None);
}

/// R734-F4: a tuple's lease round-trips through insert, get and the list
/// reads; a standing tuple reads `None`; `is_live_at` turns false at exp.
pub async fn ownership_store_lease<O: OwnershipStore + ?Sized>(store: &O) {
    use cheers_server::ownership::TupleLease;
    let seed = PrincipalId::service("seed");
    let key = PrincipalId::from_public_key(&[7; 32]);
    let lease = TupleLease { iat: 100, lease: cheers_core::Lease::new(100, 200, Some(1_000)).unwrap() };
    let leased = NewOwnership::new(key.clone(), "namespace", "ls-1", "guest", seed.clone(), None).unwrap().with_lease(Some(lease));
    let row = store.insert(&leased, 150).await.unwrap().row;
    assert_eq!(row.lease, Some(lease));
    assert_eq!(store.get(&row.id).await.unwrap().unwrap().lease, Some(lease));
    let listed = store.list_for_resource("namespace", "ls-1").await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].lease, Some(lease));
    assert!(listed[0].is_live_at(999));
    assert!(!listed[0].is_live_at(1_000));
    let standing = NewOwnership::new(PrincipalId::user("ls-u"), "namespace", "ls-1", "member", seed, None).unwrap();
    let row = store.insert(&standing, 150).await.unwrap().row;
    assert_eq!(store.get(&row.id).await.unwrap().unwrap().lease, None);
}

/// R734-F4: pending knocks (replace per requester, the cap, lapse), offers
/// (distinct-key max_uses, idempotent redeem, expiry) and admissions (first
/// outcome stands).
pub async fn knock_store_lifecycle<K: cheers_server::KnockStore + ?Sized>(store: &K) {
    use cheers_server::{Admission, PendingKnock, Queued, Redeemed, StoredOffer};
    let k = |id: &str, who: u8, created_at: i64| PendingKnock {
        id: id.into(),
        resource_kind: "namespace".into(),
        resource_id: "kn-1".into(),
        requester: PrincipalId::from_public_key(&[who; 32]),
        relation: "guest".into(),
        label: format!("phone {who}"),
        requester_user: (who == 1).then(|| cheers_core::UserId::new("kn-user")),
        renews: (who == 2).then(|| "admit-0".to_owned()),
        token: format!("token-{id}"),
        created_at,
        expires_at: created_at + 100,
    };
    assert_eq!(store.queue_knock(&k("a", 1, 10), 2, 10).await.unwrap(), Queued::Queued);
    assert_eq!(store.queue_knock(&k("b", 2, 11), 2, 11).await.unwrap(), Queued::Queued);
    // The cap counts others: a third key is refused, the first key replaces itself.
    assert_eq!(store.queue_knock(&k("c", 3, 12), 2, 12).await.unwrap(), Queued::Full);
    assert_eq!(store.queue_knock(&k("a2", 1, 13), 2, 13).await.unwrap(), Queued::Replaced);
    let pending = store.pending_knocks("namespace", "kn-1", 13).await.unwrap();
    assert_eq!(pending.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(), ["b", "a2"]);
    assert_eq!(pending[1], k("a2", 1, 13));
    assert_eq!(pending[0].renews.as_deref(), Some("admit-0"));
    assert_eq!(store.pending_knock("a", 13).await.unwrap(), None);
    assert_eq!(store.pending_knock("b", 13).await.unwrap(), Some(k("b", 2, 11)));
    // Lapsed knocks neither list nor count against the cap.
    assert_eq!(store.pending_knock("b", 111).await.unwrap(), None);
    assert_eq!(store.queue_knock(&k("c", 3, 112), 2, 112).await.unwrap(), Queued::Queued);
    store.drop_knock("a2").await.unwrap();
    store.drop_knock("a2").await.unwrap();
    assert_eq!(store.pending_knocks("namespace", "kn-1", 112).await.unwrap().iter().map(|p| p.id.as_str()).collect::<Vec<_>>(), ["c"]);

    let offer = StoredOffer {
        jti: "of-1".into(),
        resource_kind: "namespace".into(),
        resource_id: "kn-1".into(),
        relation: "guest".into(),
        created_by: PrincipalId::user("kn-owner"),
        max_uses: 2,
        created_at: 10,
        exp: 100,
    };
    store.put_offer(&offer).await.unwrap();
    let key = |b: u8| PrincipalId::from_public_key(&[b; 32]);
    assert_eq!(store.redeem_offer("nope", &key(1), 20).await.unwrap(), Redeemed::Unknown);
    assert_eq!(store.redeem_offer("of-1", &key(1), 20).await.unwrap(), Redeemed::Fresh(offer.clone()));
    assert_eq!(store.redeem_offer("of-1", &key(1), 21).await.unwrap(), Redeemed::Again(offer.clone()));
    assert_eq!(store.redeem_offer("of-1", &key(2), 22).await.unwrap(), Redeemed::Fresh(offer.clone()));
    assert_eq!(store.redeem_offer("of-1", &key(3), 23).await.unwrap(), Redeemed::Exhausted);
    let late = StoredOffer { jti: "of-2".into(), ..offer.clone() };
    store.put_offer(&late).await.unwrap();
    assert_eq!(store.redeem_offer("of-2", &key(1), 100).await.unwrap(), Redeemed::Expired);

    assert_eq!(store.admission("j-1").await.unwrap(), None);
    let ok = Admission::Accepted { ownership_id: "own-1".into() };
    assert_eq!(store.record_admission("j-1", &ok, 5).await.unwrap(), ok);
    let no = Admission::Refused { refusal: "late".into() };
    assert_eq!(store.record_admission("j-1", &no, 6).await.unwrap(), ok, "the first outcome stands");
    assert_eq!(store.record_admission("j-2", &no, 6).await.unwrap(), no);
    assert_eq!(store.admission("j-2").await.unwrap(), Some(no));
}

pub async fn ownership_store_version<O: OwnershipStore + ?Sized>(store: &O) {
    let seed = PrincipalId::service("seed");
    let tuple = |who: Subject, rel: &str| NewOwnership::new(who, "namespace", "n1", rel, seed.clone(), None).unwrap();
    let alice = PrincipalId::user("alice");
    let carol = PrincipalId::user("carol");
    assert_eq!(store.current_version().await.unwrap(), 0, "a fresh store is at 0");

    // The clock floor: the first write lands on now; the same second is +1.
    let a = store.insert(&tuple(alice.clone().into(), "member"), 1_000).await.unwrap();
    assert_eq!(a.version, 1_000);
    let b = store.insert(&tuple(PrincipalId::user("bob").into(), "member"), 1_000).await.unwrap();
    assert_eq!(b.version, 1_001);
    assert_eq!(store.current_version().await.unwrap(), 1_001);

    // A clock behind the version still advances strictly.
    assert_eq!(store.revoke_by_id(&a.row.id, 900).await.unwrap(), 1_002);
    // Already revoked: a no-op that reports the current version, moves nothing,
    // and keeps the original revoked_at.
    assert_eq!(store.revoke_by_id(&a.row.id, 5_000).await.unwrap(), 1_002);
    assert_eq!(store.get(&a.row.id).await.unwrap().unwrap().revoked_at, Some(900));
    assert!(matches!(store.revoke_by_id("ghost-id", 5_000).await, Err(StoreError::NotFound)));
    assert_eq!(store.current_version().await.unwrap(), 1_002);

    // Reads advance nothing.
    store.list_for_resource("namespace", "n1").await.unwrap();
    store.list_for_principal(&alice).await.unwrap();
    store.list_for_subject_set("namespace", "parent").await.unwrap();
    store.list_for_kind("namespace").await.unwrap();
    assert_eq!(store.current_version().await.unwrap(), 1_002);

    // A subject-set tuple is a row like any other.
    let set = store.insert(&tuple(Subject::set("namespace", "parent", "member"), "guest"), 2_000).await.unwrap();
    assert_eq!(set.version, 2_000);

    // The holder cascade advances once when it sweeps, never when it sweeps nothing.
    store.insert(&tuple(carol.clone().into(), "admin"), 2_000).await.unwrap();
    store.insert(&tuple(carol.clone().into(), "member"), 2_000).await.unwrap();
    assert_eq!(store.current_version().await.unwrap(), 2_002);
    assert_eq!(store.revoke_by_principal(&carol, 2_000).await.unwrap(), 2_003);
    assert_eq!(store.current_version().await.unwrap(), 2_003);
    assert_eq!(store.list_history_for_principal(&carol).await.unwrap().len(), 2, "both, now revoked");
    assert!(store.list_for_principal(&carol).await.unwrap().is_empty());
    assert_eq!(store.revoke_by_principal(&carol, 9_000).await.unwrap(), 2_003, "nothing live: current version");
    assert_eq!(store.current_version().await.unwrap(), 2_003);

    // Equal versions read equal rows: the live rows now are exactly bob's
    // member tuple and the set tuple.
    let mut live: Vec<_> = store.list_for_resource("namespace", "n1").await.unwrap();
    live.sort_by(|x, y| x.relationship.cmp(&y.relationship));
    assert_eq!(live, vec![set.row, b.row]);
}

/// The schema's one-form subject CHECK, exercised under the trait with raw
/// SQL. `exec` runs one statement on the backend under test and maps any
/// failure to `StoreError::Backend`. Literal values only, so one statement
/// text serves every dialect.
pub async fn ownership_subject_check_rejects_bad_forms<F, Fut>(exec: F)
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<(), StoreError>>,
{
    let insert = |id: &str, cols: &str, vals: &str| {
        format!(
            "INSERT INTO ownership \
             (id, {cols}, resource_kind, resource_id, relationship, granted_by, granted_at) \
             VALUES ('{id}', {vals}, 'doc', 'd1', 'reader', 'svc:cheers', 1000)"
        )
    };
    exec(insert("ok-principal", "principal_id", "'user:alice'"))
        .await
        .expect("a principal subject is accepted");
    exec(insert(
        "ok-set",
        "subject_kind, subject_id, subject_relation",
        "'namespace', 'n1', 'member'",
    ))
    .await
    .expect("a complete set subject is accepted");

    for (id, cols, vals) in [
        (
            "both",
            "principal_id, subject_kind, subject_id, subject_relation",
            "'user:alice', 'namespace', 'n1', 'member'",
        ),
        ("neither", "principal_id", "NULL"),
        ("partial-set", "subject_kind, subject_id", "'namespace', 'n1'"),
        ("principal-plus-kind", "principal_id, subject_kind", "'user:alice', 'namespace'"),
    ] {
        match exec(insert(id, cols, vals)).await {
            Err(StoreError::Backend(_)) => {}
            other => panic!("subject form {id:?} must fail the CHECK, got {other:?}"),
        }
    }
}

pub async fn ownership_store_check_constraints_reject_bad_rows<O: OwnershipStore + ?Sized>(
    store: &O,
) {
    // The Rust-side NewOwnership::new validator already blocks this. To
    // exercise the SQL-level CHECK we'd need to bypass NewOwnership::new and
    // emit raw SQL — out of the trait's reach. Cover the Rust-side belt here
    // and trust the schema CHECK as the suspenders documented in the doc.

    use cheers_core::PrincipalKind;
    use cheers_server::ownership::OwnershipValidationError;

    let yubaba = PrincipalId::service("yubaba");
    let alice = PrincipalId::user("alice");

    let err = NewOwnership::new(
        PrincipalId::camp("c"),
        "service",
        "s",
        "owns",
        yubaba.clone(),
        Some(yubaba.clone()),
    )
    .unwrap_err();
    assert_eq!(
        err,
        OwnershipValidationError::OnBehalfOfNotUser(PrincipalKind::Service)
    );

    // And the well-formed shape goes through the store cleanly.
    let row = store
        .insert(
            &NewOwnership::new(
                PrincipalId::camp("c-1"),
                "service",
                "s-1",
                "owns",
                yubaba,
                Some(alice),
            )
            .unwrap(),
            500,
        )
        .await
        .expect("well-formed insert succeeds")
        .row;
    assert!(!row.id.is_empty());
}

// ---------------------------------------------------------------------------
// ServicePrincipalStore (R020-T18)
// ---------------------------------------------------------------------------

fn fixture_signing_key(
    kid: &str,
    principal: &PrincipalId,
    seed: u8,
    status: SigningKeyStatus,
    created_at: i64,
    retire_at: Option<i64>,
) -> SigningKey {
    SigningKey::new(kid, principal.clone(), [seed; 32], status, created_at, retire_at)
}

pub async fn service_principal_lifecycle<S: ServicePrincipalStore + ?Sized>(store: &S) {
    let yubaba = PrincipalId::service("yubaba-1");

    // Unknown principal lookup is None, not an error.
    assert!(store.get_principal(&yubaba).await.unwrap().is_none());

    // Insert a fresh principal — service kind, bound_to=None per Principal::try_new.
    let principal =
        Principal::try_new(yubaba.clone(), None, PrincipalStatus::Active, 1_000).unwrap();
    store.insert_principal(&principal).await.expect("insert");

    // Re-insert with the same id => Conflict.
    match store.insert_principal(&principal).await {
        Err(StoreError::Conflict) => {}
        other => panic!("expected Conflict, got {other:?}"),
    }

    // Round-trip through get.
    let back = store.get_principal(&yubaba).await.unwrap().unwrap();
    assert_eq!(back, principal);

    // Empty key set for a freshly-provisioned principal.
    assert!(store.list_signing_keys(&yubaba).await.unwrap().is_empty());

    // Insert the active key.
    let k1 = fixture_signing_key(
        "kid-1",
        &yubaba,
        1,
        SigningKeyStatus::Active,
        1_000,
        None,
    );
    store.insert_signing_key(&k1).await.expect("insert k1");

    // Duplicate kid => Conflict.
    match store.insert_signing_key(&k1).await {
        Err(StoreError::Conflict) => {}
        other => panic!("expected Conflict on duplicate kid, got {other:?}"),
    }

    // list_signing_keys returns the one key.
    let listed = store.list_signing_keys(&yubaba).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0], k1);

    // list_all_signing_keys returns it too.
    let all = store.list_all_signing_keys().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0], k1);

    // retire_signing_key on unknown kid => NotFound.
    match store.retire_signing_key("ghost-kid", 2_000).await {
        Err(StoreError::NotFound) => {}
        other => panic!("expected NotFound, got {other:?}"),
    }

    // Retire the active key.
    store
        .retire_signing_key(&k1.kid, 5_000)
        .await
        .expect("retire");
    let listed = store.list_signing_keys(&yubaba).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].status, SigningKeyStatus::Retiring);
    assert_eq!(listed[0].retire_at, Some(5_000));

    // Idempotent re-retire overwrites retire_at.
    store
        .retire_signing_key(&k1.kid, 6_000)
        .await
        .expect("re-retire");
    let listed = store.list_signing_keys(&yubaba).await.unwrap();
    assert_eq!(listed[0].retire_at, Some(6_000));

    // Add a fresh active key (rotation).
    let k2 = fixture_signing_key(
        "kid-2",
        &yubaba,
        2,
        SigningKeyStatus::Active,
        7_000,
        None,
    );
    store.insert_signing_key(&k2).await.expect("insert k2");

    // Both keys present.
    let mut listed = store.list_signing_keys(&yubaba).await.unwrap();
    listed.sort_by(|a, b| a.kid.cmp(&b.kid));
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].kid, "kid-1");
    assert_eq!(listed[1].kid, "kid-2");

    // Prune before retire_at — k1 stays.
    let dropped = store.prune_retired_keys(5_999).await.unwrap();
    assert_eq!(dropped, 0);
    assert_eq!(store.list_signing_keys(&yubaba).await.unwrap().len(), 2);

    // Prune at retire_at — k1 drops, k2 stays.
    let dropped = store.prune_retired_keys(6_000).await.unwrap();
    assert_eq!(dropped, 1);
    let listed = store.list_signing_keys(&yubaba).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].kid, "kid-2");

    // Idempotent — second prune drops nothing.
    let dropped = store.prune_retired_keys(10_000).await.unwrap();
    assert_eq!(dropped, 0);
}

pub async fn service_principal_rejects_non_service_kind<S: ServicePrincipalStore + ?Sized>(
    store: &S,
) {
    // The Rust-side belt: insert_principal refuses non-service kinds before
    // ever reaching the schema CHECK. (The CHECK is the suspenders — bypassing
    // the trait with raw SQL would still trip it.)
    let user = Principal::try_new(
        PrincipalId::user("alice"),
        None,
        PrincipalStatus::Active,
        100,
    )
    .unwrap();
    match store.insert_principal(&user).await {
        Err(StoreError::Backend(_)) => {}
        other => panic!("expected Backend rejection for user kind, got {other:?}"),
    }
}

pub async fn service_principal_check_constraint_rejects_bad_status_directly<F>(
    insert_raw_bad: F,
) where
    F: std::future::Future<Output = Result<(), StoreError>>,
{
    // Bypass the trait and INSERT a malformed row via raw SQL — the schema
    // CHECK must reject it. The per-backend test files provide the closure
    // (they hold the pool); this scenario just asserts the outcome.
    match insert_raw_bad.await {
        Err(StoreError::Backend(_)) => {}
        other => panic!("expected Backend (CHECK failure), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// AuditStore (R020-F13)
// ---------------------------------------------------------------------------

fn fixture_audit(at: i64, sub: PrincipalId, method: &str, request_id: &str) -> AuditRecord {
    AuditRecord::new(
        at,
        sub,
        None,
        Some("camp-a".into()),
        "https://kamaji.example",
        method,
        vec![yah_scopes::CLOUD_DEPLOY, yah_scopes::CLOUD_READ],
        "allow",
        request_id,
    )
    .expect("fixture record validates")
}

pub async fn audit_store_batch_insert_round_trip<A: AuditStore + ?Sized>(store: &A) {
    use cheers_core::{Actor, PrincipalId, Scope};

    let alice = PrincipalId::user("alice");
    let yubaba = PrincipalId::service("yubaba");

    // Empty batch is a no-op (matches the trait contract).
    let zero = store.insert_batch(&[], 9_000).await.unwrap();
    assert!(zero.is_empty());

    // 100-record batch — every record present, ids unique, ingested_at stamped.
    let batch: Vec<AuditRecord> = (0..100)
        .map(|i| fixture_audit(1_700_000_000 + i, alice.clone(), "POST /deploy", &format!("rid-{i}")))
        .collect();
    let rows = store.insert_batch(&batch, 1_800_000_000).await.unwrap();
    assert_eq!(rows.len(), 100);
    let ids: std::collections::HashSet<_> = rows.iter().map(|r| r.id.clone()).collect();
    assert_eq!(ids.len(), 100, "ids must be unique within a batch");
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(row.ingested_at, 1_800_000_000);
        assert_eq!(row.record.request_id, format!("rid-{i}"));
        assert_eq!(row.record.sub, alice);
        assert_eq!(row.record.scope, vec![yah_scopes::CLOUD_DEPLOY, yah_scopes::CLOUD_READ]);
        assert_eq!(row.record.camp_id.as_deref(), Some("camp-a"));
    }

    // act-bearing record (agent-on-behalf-of) round-trips with the act column.
    let agent = PrincipalId::service("agent-claude");
    let with_act = AuditRecord::new(
        1_700_001_000,
        alice.clone(),
        Some(Actor::new(agent.clone())),
        None,
        "https://sage.example",
        "POST /tasks/create",
        vec![],
        "deny",
        "rid-act",
    )
    .unwrap();
    // Also exercise a service-principal-sub row to confirm sub vocabulary.
    let svc_call = fixture_audit(1_700_002_000, yubaba.clone(), "POST /ownership", "rid-svc");
    let rows = store
        .insert_batch(&[with_act.clone(), svc_call.clone()], 1_800_000_500)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].record.act.as_ref().map(|a| &a.sub), Some(&agent));
    assert_eq!(rows[0].record.camp_id, None);
    assert_eq!(rows[0].record.scope, Vec::<Scope>::new());
    assert_eq!(rows[1].record.sub, yubaba);
    assert_eq!(rows[1].record.method, "POST /ownership");
}

/// R020-F14 — the read side, against a real backend. Covers the full decode
/// path (`sub` / `act_sub` / `scope` JSON round-trip out of SQL), the two
/// filters, the keyset cursor, and the `sub`-scoping that keeps one user's
/// audit out of another's page.
pub async fn audit_store_query_by_on_behalf_of<A: AuditStore + ?Sized>(store: &A) {
    use cheers_core::Actor;

    let alice = PrincipalId::user("alice");
    let bob = PrincipalId::user("bob");
    let agent = PrincipalId::service("agent-claude");

    let mut seed: Vec<AuditRecord> = Vec::new();
    for i in 0..7 {
        seed.push(fixture_audit(
            1_700_000_000 + i,
            alice.clone(),
            "cloud.deploy.start",
            &format!("alice-deploy-{i}"),
        ));
    }
    // Same user, a method outside the W127 prefix.
    seed.push(fixture_audit(
        1_700_000_100,
        alice.clone(),
        "board.write",
        "alice-board",
    ));
    // Another user's row, and a service-subject row — neither may leak in.
    seed.push(fixture_audit(1_700_000_200, bob.clone(), "cloud.deploy.start", "bob-deploy"));
    seed.push(fixture_audit(
        1_700_000_300,
        PrincipalId::service("yubaba"),
        "cloud.deploy.start",
        "svc-deploy",
    ));
    // An agent-mediated row: `sub` is still alice, so it IS hers.
    seed.push(
        AuditRecord::new(
            1_700_000_400,
            alice.clone(),
            Some(Actor::new(agent.clone())),
            Some("camp-a".into()),
            "https://kamaji.example",
            "cloud.deploy.finish",
            vec![yah_scopes::CLOUD_DEPLOY],
            "allow",
            "alice-agent-deploy",
        )
        .unwrap(),
    );
    store.insert_batch(&seed, 1_800_000_000).await.unwrap();

    // Whole-user page, newest first, nobody else's rows.
    let page = store
        .query_by_on_behalf_of(&AuditQuery::new(alice.clone()).unwrap())
        .await
        .unwrap();
    assert_eq!(page.rows.len(), 9, "7 deploys + 1 board + 1 agent-mediated");
    assert_eq!(page.next_cursor, None);
    assert!(
        page.rows.iter().all(|r| r.record.sub == alice),
        "another principal's row leaked into alice's page",
    );
    let ats: Vec<i64> = page.rows.iter().map(|r| r.record.at).collect();
    let mut sorted = ats.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(ats, sorted, "rows must come back newest-first");

    // The act column survives the SQL round-trip.
    let agent_row = page
        .rows
        .iter()
        .find(|r| r.record.request_id == "alice-agent-deploy")
        .expect("agent-mediated row present");
    assert_eq!(agent_row.record.act.as_ref().map(|a| &a.sub), Some(&agent));
    assert_eq!(agent_row.record.scope, vec![yah_scopes::CLOUD_DEPLOY]);
    assert_eq!(agent_row.record.camp_id.as_deref(), Some("camp-a"));

    // since= is an inclusive lower bound on record.at.
    let since = store
        .query_by_on_behalf_of(&AuditQuery::new(alice.clone()).unwrap().with_since(1_700_000_100))
        .await
        .unwrap();
    assert!(
        since.rows.iter().all(|r| r.record.at >= 1_700_000_100),
        "since= must exclude older rows",
    );
    assert_eq!(
        since.rows.len(),
        2,
        "board.write (at=..100) + the agent deploy (at=..400); every plain \
         deploy is at ..000–..006 and falls below the bound",
    );

    // method-prefix= is a literal prefix, not a glob.
    let deploys = store
        .query_by_on_behalf_of(
            &AuditQuery::new(alice.clone()).unwrap().with_method_prefix("cloud.deploy"),
        )
        .await
        .unwrap();
    assert_eq!(deploys.rows.len(), 8, "7 starts + 1 finish, no board.write");
    assert!(deploys.rows.iter().all(|r| r.record.method.starts_with("cloud.deploy")));

    // A prefix containing a LIKE metacharacter matches nothing rather than
    // acting as a wildcard.
    let wild = store
        .query_by_on_behalf_of(&AuditQuery::new(alice.clone()).unwrap().with_method_prefix("cloud_"))
        .await
        .unwrap();
    assert!(
        wild.rows.is_empty(),
        "`_` must be escaped, not treated as a single-char wildcard",
    );

    // Keyset paging walks every row exactly once.
    let mut seen: Vec<String> = Vec::new();
    let mut cursor = None;
    let mut pages = 0;
    loop {
        let mut q = AuditQuery::new(alice.clone()).unwrap().with_limit(4);
        if let Some(c) = cursor {
            q = q.with_cursor(c);
        }
        let p = store.query_by_on_behalf_of(&q).await.unwrap();
        pages += 1;
        assert!(pages <= 5, "paging failed to terminate");
        seen.extend(p.rows.iter().map(|r| r.record.request_id.clone()));
        match p.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(pages, 3, "9 rows at limit 4 → 4 + 4 + 1");
    assert_eq!(seen.len(), 9);
    let unique: std::collections::HashSet<_> = seen.iter().collect();
    assert_eq!(unique.len(), 9, "no row repeated across pages: {seen:?}");

    // A page for a user with no rows is empty and terminal.
    let empty = store
        .query_by_on_behalf_of(&AuditQuery::new(PrincipalId::user("nobody")).unwrap())
        .await
        .unwrap();
    assert!(empty.rows.is_empty());
    assert_eq!(empty.next_cursor, None);
}


// ---------------------------------------------------------------------------
// UserTokenStore (R728-F1)
// ---------------------------------------------------------------------------

/// Build a token row for `user`. `expires_at` is what decides liveness, so the
/// scenarios below vary it rather than fiddling with a clock.
pub fn fixture_user_token(
    jti: &str,
    user: &UserId,
    name: &str,
    scopes: Vec<Scope>,
    created_at: i64,
    expires_at: i64,
) -> UserTokenRecord {
    UserTokenRecord::new(
        jti,
        user.clone(),
        name,
        scopes,
        "https://kamaji.example",
        created_at,
        expires_at,
    )
}

/// Insert / read-back, plus the two properties the `/me/tokens` routes lean
/// on: the list is scoped to one user, and the scope vector survives the
/// column encoding intact.
///
/// `user` and `other` must both already exist — `user_tokens.user_id` carries
/// a FK to `users` with `ON DELETE CASCADE`.
pub async fn user_token_store_insert_and_scoped_list<T: UserTokenStore + ?Sized>(
    tokens: &T,
    user: &UserId,
    other: &UserId,
) {
    let scopes = vec![yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY, yah_scopes::BOARD_WRITE];
    tokens
        .insert(&fixture_user_token(
            "j-mine-1",
            user,
            "ci",
            scopes.clone(),
            1_000,
            9_000,
        ))
        .await
        .unwrap();
    tokens
        .insert(&fixture_user_token(
            "j-mine-2",
            user,
            "laptop",
            vec![yah_scopes::CLOUD_READ],
            1_100,
            9_000,
        ))
        .await
        .unwrap();
    tokens
        .insert(&fixture_user_token(
            "j-theirs",
            other,
            "not-yours",
            vec![yah_scopes::CAMP_ADMIN],
            1_050,
            9_000,
        ))
        .await
        .unwrap();

    let mine = tokens.list_live_for_user(user, 2_000).await.unwrap();
    assert_eq!(mine.len(), 2, "list must be scoped to one user: {mine:?}");
    assert!(mine.iter().all(|r| &r.user_id == user));
    assert!(mine.iter().all(|r| !r.revoked));

    // Newest first — the (user_id, created_at DESC) index exists for this.
    assert_eq!(mine[0].jti, "j-mine-2");
    assert_eq!(mine[1].jti, "j-mine-1");

    // Every field survives the round trip, scope vector included and in order.
    let full = mine.iter().find(|r| r.jti == "j-mine-1").unwrap();
    assert_eq!(full.name, "ci");
    assert_eq!(full.scopes, scopes);
    assert_eq!(full.aud, "https://kamaji.example");
    assert_eq!(full.created_at, 1_000);
    assert_eq!(full.expires_at, 9_000);
    assert_eq!(full.last_used_at, None, "cheers never writes last_used_at");

    // A token with no scopes at all is a legal (if useless) row, and must not
    // decode as a NULL or a one-element list containing "".
    tokens
        .insert(&fixture_user_token(
            "j-empty",
            user,
            "none",
            vec![],
            1_200,
            9_000,
        ))
        .await
        .unwrap();
    let empty = tokens.get("j-empty").await.unwrap().unwrap();
    assert!(empty.scopes.is_empty());
}

/// Revoked and expired rows leave the live list but remain `get`-able.
///
/// That asymmetry is load-bearing, not incidental: `DELETE /me/tokens/{id}`
/// distinguishes "not yours" (404) from "already dead" (204) by reading the
/// row, so a store that deleted on revoke would turn every second revoke into
/// a 404 about a token the caller does own.
pub async fn user_token_store_revoked_and_expired_leave_the_live_list<T>(tokens: &T, user: &UserId)
where
    T: UserTokenStore + ?Sized,
{
    tokens
        .insert(&fixture_user_token(
            "live",
            user,
            "live",
            vec![yah_scopes::CLOUD_READ],
            1_000,
            9_000,
        ))
        .await
        .unwrap();
    tokens
        .insert(&fixture_user_token(
            "expired",
            user,
            "expired",
            vec![yah_scopes::CLOUD_READ],
            1_000,
            1_500,
        ))
        .await
        .unwrap();
    tokens
        .insert(&fixture_user_token(
            "revoked",
            user,
            "revoked",
            vec![yah_scopes::CLOUD_READ],
            1_000,
            9_000,
        ))
        .await
        .unwrap();
    tokens.mark_revoked("revoked").await.unwrap();

    let live = tokens.list_live_for_user(user, 2_000).await.unwrap();
    assert_eq!(live.len(), 1, "expected only the live row: {live:?}");
    assert_eq!(live[0].jti, "live");

    // Revocation is not deletion.
    let dead = tokens.get("revoked").await.unwrap().expect("row survives");
    assert!(dead.revoked);
    assert!(tokens.get("expired").await.unwrap().is_some());

    // An expiry boundary is exclusive: `expires_at == now` is already dead.
    let at_boundary = tokens.list_live_for_user(user, 9_000).await.unwrap();
    assert!(
        at_boundary.is_empty(),
        "expires_at == now must not be live: {at_boundary:?}"
    );

    // Unknown jti is None, not an error.
    assert!(tokens.get("no-such-jti").await.unwrap().is_none());
}

/// `mark_revoked` is idempotent, and an unknown `jti` is
/// [`StoreError::NotFound`]. `touch_last_used` carries the same contract — it
/// is the one write cheers itself never makes, so the store is the only place
/// it can be pinned.
pub async fn user_token_store_revoke_is_idempotent_and_touch_stamps<T>(tokens: &T, user: &UserId)
where
    T: UserTokenStore + ?Sized,
{
    tokens
        .insert(&fixture_user_token(
            "j1",
            user,
            "ci",
            vec![yah_scopes::CLOUD_READ],
            1_000,
            9_000,
        ))
        .await
        .unwrap();

    tokens.mark_revoked("j1").await.unwrap();
    tokens
        .mark_revoked("j1")
        .await
        .expect("re-revoking an already-revoked row is a no-op, not an error");
    assert!(tokens.get("j1").await.unwrap().unwrap().revoked);

    match tokens.mark_revoked("nope").await {
        Err(StoreError::NotFound) => {}
        other => panic!("expected NotFound revoking an unknown jti, got {other:?}"),
    }

    assert_eq!(tokens.get("j1").await.unwrap().unwrap().last_used_at, None);
    tokens.touch_last_used("j1", 4_242).await.unwrap();
    assert_eq!(
        tokens.get("j1").await.unwrap().unwrap().last_used_at,
        Some(4_242)
    );
    // Latest wins — the column is "last used", not "first used".
    tokens.touch_last_used("j1", 5_000).await.unwrap();
    assert_eq!(
        tokens.get("j1").await.unwrap().unwrap().last_used_at,
        Some(5_000)
    );

    match tokens.touch_last_used("nope", 1).await {
        Err(StoreError::NotFound) => {}
        other => panic!("expected NotFound touching an unknown jti, got {other:?}"),
    }
}

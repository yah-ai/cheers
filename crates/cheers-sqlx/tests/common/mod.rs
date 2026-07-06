//! Shared store-contract scenarios. Each is an `async fn` that takes the
//! constructed store(s) and exercises the trait surface. The per-backend test
//! files (`sqlite.rs`, `pg.rs`) wire concrete pools then call these.
//!
//! The functions panic via `assert!` on failure — the contract is "if this
//! returns, the impl satisfies the spec for that scenario."

use cheers_core::{
    Credential, DeviceBinding, DeviceId, Principal, PrincipalId, PrincipalStatus, StoreError,
    UserId,
};
use cheers_server::audit::{AuditRecord, AuditStore};
use cheers_server::ownership::{NewOwnership, OwnershipStore};
use cheers_server::store::{
    NewUser, PasskeyCredentialStore, ProviderKey, RefreshStore, RefreshTokenRecord, UserStore,
};
use cheers_server::{ServicePrincipalStore, SigningKey, SigningKeyStatus};
use cheers_server::RevocationWriter;
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

pub async fn revocation_writer_and_reader<W>(revoke: &W)
where
    W: RevocationWriter + RevocationReader + ?Sized,
{
    assert!(!revoke.is_revoked("tok-x").await.unwrap());
    revoke.revoke("tok-x").await.unwrap();
    assert!(revoke.is_revoked("tok-x").await.unwrap());
    // Idempotent.
    revoke.revoke("tok-x").await.unwrap();
    assert!(revoke.is_revoked("tok-x").await.unwrap());
    // Independence.
    assert!(!revoke.is_revoked("tok-y").await.unwrap());
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
    let row1 = store.insert(&new1, 100).await.expect("insert 1");
    assert_eq!(row1.principal_id, camp_a);
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
        .unwrap();
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
        .unwrap();

    // get() roundtrip preserves every column.
    let back = store.get(&row1.id).await.unwrap().unwrap();
    assert_eq!(back, row1);
    assert!(store.get("ghost-id").await.unwrap().is_none());

    // list_for_principal returns live rows for the principal, drops others.
    let mut camp_a_rows = store.list_for_principal(&camp_a).await.unwrap();
    camp_a_rows.sort_by(|a, b| a.granted_at.cmp(&b.granted_at));
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

    // Cascading revoke for alice sweeps row1 (her last live row); bob's row3 untouched.
    let swept = store.revoke_by_on_behalf_of(&alice, 300).await.unwrap();
    assert_eq!(swept, 1, "exactly row1 should be swept");
    let live_for_alice = store.list_for_principal(&camp_a).await.unwrap();
    assert!(live_for_alice.is_empty());
    let live_for_bob = store.list_for_principal(&camp_b).await.unwrap();
    assert_eq!(live_for_bob.len(), 1);

    // Cascading revoke is idempotent — second call returns 0.
    let swept_again = store.revoke_by_on_behalf_of(&alice, 400).await.unwrap();
    assert_eq!(swept_again, 0);
}

pub async fn ownership_store_check_constraints_reject_bad_rows<O: OwnershipStore + ?Sized>(
    store: &O,
) {
    // The Rust-side NewOwnership::new validator already blocks these. To
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
        alice.clone(),
        Some(alice.clone()),
    )
    .unwrap_err();
    assert_eq!(
        err,
        OwnershipValidationError::GrantedByNotService(PrincipalKind::User)
    );

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
        .expect("well-formed insert succeeds");
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
    use cheers_core::Scope;
    AuditRecord::new(
        at,
        sub,
        None,
        Some("camp-a".into()),
        "https://kamaji.example",
        method,
        vec![Scope::CloudDeploy, Scope::CloudRead],
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
        assert_eq!(row.record.scope, vec![Scope::CloudDeploy, Scope::CloudRead]);
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


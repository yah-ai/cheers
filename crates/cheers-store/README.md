# cheers-store

Device-tier credential storage for [cheers](../../README.md): concrete
[`CredentialStore`](../cheers-core) implementations for native apps that hold a
user's credential locally between launches.

This crate depends on `cheers-core` with `default-features = false` — it carries
the identity types and the `CredentialStore` trait but **no token crypto**. A
device that only acquires and stores an opaque credential never compiles a
codec, refresh, or session machinery. (The server-side providers — OIDC, Apple
Sign In, passkey, email, password — live in the separate `cheers` crate.)

## Backends (feature-gated)

| Feature    | Type                 | Backing store                                            |
|------------|----------------------|----------------------------------------------------------|
| `keyring`  | `KeyringStore`       | OS secret store (Apple Keychain / Windows Credential Manager / Linux Secret Service) |
| `headless` | `EncryptedFileStore` | `age`-encrypted file (TPM key if present) — *pending, R015-T2* |
| —          | `MemoryStore`        | process-local map for tests — *pending, R015-T3*         |

```toml
[dependencies]
cheers-store = { version = "0.0.1", features = ["keyring"] }
```

See `.yah/docs/working/cheers.md` (design) and `cheers-plan.md` (build plan).

# cheers-core

[![crates.io](https://img.shields.io/crates/v/cheers-core.svg)](https://crates.io/crates/cheers-core)
[![docs.rs](https://docs.rs/cheers-core/badge.svg)](https://docs.rs/cheers-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

The keyless **contract surface** shared across the `cheers` auth stack: identity
types, the typed error hierarchy, the `CredentialStore` trait, and the
`TokenMinter` / `TokenVerifier` traits.

No crypto, no I/O, no async runtime dependency. This is the crate every other
tier depends on — the mint/verify machinery (and everything that pulls
`pasetors` / `hmac` / `getrandom`) lives in
[`cheers-verify`](https://crates.io/crates/cheers-verify) (verify-only) and
`cheers-server` (mint + stores), never here.

```toml
[dependencies]
cheers-core = "0.8"
```

## Why keyless

Splitting the contract from the crypto is what lets an untrusted edge take a
verify-only dependency without any minter in its graph. `cheers-core` holds the
shared vocabulary; `cheers-verify` implements the half that can only *check*;
`cheers-server` implements the half that can *mint*. The dependency direction —
server and verify both depend on core, and server depends on verify — is the
security boundary.

## Minimum supported Rust version

Rust 1.85.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual-licensed as above, without any additional terms or conditions.

# cheers-verify

[![crates.io](https://img.shields.io/crates/v/cheers-verify.svg)](https://crates.io/crates/cheers-verify)
[![docs.rs](https://docs.rs/cheers-verify/badge.svg)](https://docs.rs/cheers-verify)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

The **edge-safe, verify-only** half of [`cheers`](https://crates.io/crates/cheers-core)
auth. Everything in this crate can *check* a session; nothing in it can *create*
one.

That guarantee is structural, not a feature flag: `cheers-verify` depends on
[`cheers-core`](https://crates.io/crates/cheers-core) and `pasetors`, but on **no
minter type**. A consumer that depends only on `cheers-verify` has no code path
to mint — which is exactly what makes it safe to ship to an untrusted edge (a
reverse proxy, a CDN worker, an ingress node).

```toml
[dependencies]
cheers-verify = "0.8"
```

## What's in the box

- **`PasetoV4PublicVerifier`** — PASETO v4.public (Ed25519) verification from a
  public key alone. The only `cheers_core::TokenVerifier` that *cannot* also
  mint (the symmetric codecs in `cheers-server` implement both halves; this one
  holds no secret).
- **`RevocationReader`** — the read side of the revocation split: a point
  membership check against an eventually-consistent replica (KV / gossip).
- **`EdgeVerifier`** — the facade an edge process holds: verify a token, then
  check it hasn't been revoked. It takes a `TokenVerifier`, so there is no path
  to a minter in its type graph.

## Why the split

`cheers-server` depends on `cheers-verify`, never the reverse. That single
dependency direction is the whole design: "the edge cannot mint" is realized as
"the edge's crate has no minter in its dependency graph." You get token
verification and revocation checks at the perimeter without shipping a signing
key — or a crate that could hold one — anywhere near it.

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

# cheers

Identity providers (OIDC, Apple Sign In, passkey, email magic-link, password,
LAN-pair) and native credential stores. Built on
[`cheers-core`](../cheers-core/).

Each provider lives behind a feature flag (`email`, `password`, `google`,
`apple`, `passkey`, `keyring`, `headless`, `macos`, `ios`, `lan-pair`);
default features are empty.

See the design doc at `../../.yah/docs/working/cheers.md`.

//! Property tests for the codec contract (origin-side impls).
//!
//! Two laws, exercised against the three concrete codecs:
//!
//! 1. **Roundtrip** — `verify_at(mint(c), c.issued_at)` equals `c` for any
//!    non-expired `Claims`.
//! 2. **Tamper detection** — flipping a single bit anywhere in a freshly
//!    minted token causes `verify_at` to reject it (Malformed,
//!    SignatureMismatch, Expired, or Serde — never `Ok` with claims that
//!    differ from the original).
//!
//! These live in `tests/` (integration scope) so they exercise the crate's
//! public surface exactly as a downstream consumer would. The asymmetric
//! verifier comes from `cheers-verify` (re-exported through `cheers-server`),
//! which is the only place a token minted by the secret key can be checked.

use cheers_core::{
    Claims, CodecError, DeviceBinding, DeviceId, TokenMinter, TokenVerifier, UserId,
};
use cheers_server::{HmacBlobCodec, PasetoV4Codec, PasetoV4SecretMinter};
use proptest::prelude::*;

fn binding_strategy() -> impl Strategy<Value = DeviceBinding> {
    prop_oneof![
        Just(DeviceBinding::Passkey),
        Just(DeviceBinding::OidcGoogle),
        Just(DeviceBinding::OidcApple),
        "[A-Za-z0-9.:/_-]{1,64}".prop_map(|issuer| DeviceBinding::OidcGeneric { issuer }),
        Just(DeviceBinding::EmailPassword),
        Just(DeviceBinding::EmailMagicLink),
        Just(DeviceBinding::LanPair),
    ]
}

/// Claims with a "now" sentinel pinned to `issued_at`. `expires_at` is always
/// strictly after `issued_at`, so the token is fresh at the moment it's minted.
fn claims_strategy() -> impl Strategy<Value = Claims> {
    (
        "[a-z0-9_-]{1,32}",
        "[a-z0-9_-]{1,32}",
        binding_strategy(),
        // Constrain timestamps to a sane positive range so we never blow up
        // pasetors's internal time math.
        0i64..1_000_000_000,
        1i64..=86_400i64, // duration up to one day
    )
        .prop_map(|(sub, device, binding, issued_at, ttl)| {
            Claims::new(
                UserId::new(sub),
                DeviceId::new(device),
                binding,
                issued_at,
                issued_at + ttl,
            )
        })
}

fn flip_bit(token: &mut [u8], bit_index: usize) {
    let byte = bit_index / 8;
    let bit = bit_index % 8;
    token[byte] ^= 1 << bit;
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        .. ProptestConfig::default()
    })]

    #[test]
    fn hmac_roundtrip(claims in claims_strategy()) {
        let codec = HmacBlobCodec::new([0xA5; 32]);
        let token = codec.mint(&claims).unwrap();
        let back = codec.verify_at(&token, claims.issued_at).unwrap();
        prop_assert_eq!(back, claims);
    }

    #[test]
    fn paseto_roundtrip(claims in claims_strategy()) {
        let codec = PasetoV4Codec::new(&[0x5A; 32]).unwrap();
        let token = codec.mint(&claims).unwrap();
        let back = codec.verify_at(&token, claims.issued_at).unwrap();
        prop_assert_eq!(back, claims);
    }

    /// Tamper: flip one bit at `bit_index` (modulo the token length) in the
    /// minted token bytes. The verifier must reject — i.e. never return
    /// `Ok(c')` where `c' == original`.
    ///
    /// (Bit flips can land on padding or change the b64 alphabet without
    /// altering the decoded payload — that's why we assert "not the same
    /// claims" rather than "always error". A successful verify that returns
    /// equivalent claims still preserves the integrity property.)
    #[test]
    fn hmac_tamper_rejected(claims in claims_strategy(), bit_index in 0usize..10_000) {
        let codec = HmacBlobCodec::new([0xA5; 32]);
        let token = codec.mint(&claims).unwrap();
        let mut bytes = token.into_bytes();
        let bit = bit_index % (bytes.len() * 8);
        flip_bit(&mut bytes, bit);
        // Tampered bytes may no longer be valid UTF-8 — if they are, run
        // verify; if not, the token is necessarily rejected.
        if let Ok(s) = std::str::from_utf8(&bytes) {
            match codec.verify_at(s, claims.issued_at) {
                Ok(c) => prop_assert_eq!(c, claims),
                Err(_) => { /* rejection is the expected path */ }
            }
        }
    }

    #[test]
    fn paseto_tamper_rejected(claims in claims_strategy(), bit_index in 0usize..10_000) {
        let codec = PasetoV4Codec::new(&[0x5A; 32]).unwrap();
        let token = codec.mint(&claims).unwrap();
        let mut bytes = token.into_bytes();
        let bit = bit_index % (bytes.len() * 8);
        flip_bit(&mut bytes, bit);
        if let Ok(s) = std::str::from_utf8(&bytes) {
            match codec.verify_at(s, claims.issued_at) {
                Ok(c) => prop_assert_eq!(c, claims),
                Err(_) => { /* rejection is the expected path */ }
            }
        }
    }

    /// Verifying with a different key always fails (regardless of the
    /// `now` parameter).
    #[test]
    fn hmac_wrong_key_rejected(claims in claims_strategy(), other_key in any::<[u8; 32]>()) {
        prop_assume!(other_key != [0xA5; 32]);
        let signer = HmacBlobCodec::new([0xA5; 32]);
        let verifier = HmacBlobCodec::new(other_key);
        let token = signer.mint(&claims).unwrap();
        let err = verifier.verify_at(&token, claims.issued_at).unwrap_err();
        prop_assert!(matches!(err, CodecError::SignatureMismatch));
    }

    #[test]
    fn paseto_wrong_key_rejected(claims in claims_strategy(), other_key in any::<[u8; 32]>()) {
        prop_assume!(other_key != [0x5A; 32]);
        let signer = PasetoV4Codec::new(&[0x5A; 32]).unwrap();
        let verifier = PasetoV4Codec::new(&other_key).unwrap();
        let token = signer.mint(&claims).unwrap();
        let err = verifier.verify_at(&token, claims.issued_at).unwrap_err();
        prop_assert!(matches!(err, CodecError::SignatureMismatch));
    }

    // ---- PasetoV4Public (asymmetric: secret minter / public verifier) -------

    #[test]
    fn paseto_public_roundtrip(claims in claims_strategy()) {
        let (minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
        let token = minter.mint(&claims).unwrap();
        let back = verifier.verify_at(&token, claims.issued_at).unwrap();
        prop_assert_eq!(back, claims);
    }

    #[test]
    fn paseto_public_tamper_rejected(claims in claims_strategy(), bit_index in 0usize..10_000) {
        let (minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
        let token = minter.mint(&claims).unwrap();
        let mut bytes = token.into_bytes();
        let bit = bit_index % (bytes.len() * 8);
        flip_bit(&mut bytes, bit);
        if let Ok(s) = std::str::from_utf8(&bytes) {
            match verifier.verify_at(s, claims.issued_at) {
                Ok(c) => prop_assert_eq!(c, claims),
                Err(_) => { /* rejection is the expected path */ }
            }
        }
    }

    /// A token minted by one secret key never verifies under an unrelated
    /// public key — the property that lets the edge hold only a verify key.
    #[test]
    fn paseto_public_wrong_key_rejected(claims in claims_strategy()) {
        let (minter, _) = PasetoV4SecretMinter::generate().unwrap();
        let (_, other_verifier) = PasetoV4SecretMinter::generate().unwrap();
        let token = minter.mint(&claims).unwrap();
        let err = other_verifier.verify_at(&token, claims.issued_at).unwrap_err();
        prop_assert!(matches!(err, CodecError::SignatureMismatch));
    }
}

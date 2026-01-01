//! Passkey authentication ceremony — `start_authentication` → `finish_authentication`.
//!
//! See the [module docs](super) for the credential profile, the
//! server-side-state requirement, and the `UserId` ↔ `Uuid` handle contract.
//!
//! Authentication is the mirror of [registration](super::PasskeyRelyingParty::start_registration):
//! the relying party hands the authenticator a challenge plus the set of
//! credentials the user is allowed to answer with, the authenticator signs, and
//! the server verifies the signature against the stored public key.

use super::{
    AuthenticationResult, Passkey, PasskeyAuthentication, PasskeyError, PasskeyRelyingParty,
    PublicKeyCredential, RequestChallengeResponse,
};

impl PasskeyRelyingParty {
    /// Begin authenticating a user against their already-registered passkeys.
    ///
    /// `allow_credentials` is the candidate set — the user's stored
    /// [`Passkey`]s (recover them from a `CredentialStore` via
    /// [`passkey_from_credential`](super::passkey_from_credential)). Because
    /// cheers ships the **non-discoverable** profile (see the [module
    /// docs](super)), the relying party already knows who is authenticating and
    /// supplies their credentials here; an empty slice produces a challenge no
    /// authenticator can answer.
    ///
    /// Returns the [`RequestChallengeResponse`] to serialise to the client and
    /// the [`PasskeyAuthentication`] state that **must be stored server-side**
    /// (single-use, confidential) until [`finish_authentication`] is called —
    /// it carries the challenge this assertion is bound to.
    ///
    /// ```
    /// # use cheers::passkey::{PasskeyRelyingParty, Passkey, Url};
    /// # fn run(rp: &PasskeyRelyingParty, stored: &[Passkey]) {
    /// let (challenge, state) = rp.start_authentication(stored).unwrap();
    ///
    /// // `challenge` -> serialise to JSON, hand to the browser/authenticator.
    /// // `state`     -> stash server-side until the client responds.
    /// # let _ = (challenge, state);
    /// # }
    /// ```
    ///
    /// [`finish_authentication`]: PasskeyRelyingParty::finish_authentication
    pub fn start_authentication(
        &self,
        allow_credentials: &[Passkey],
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), PasskeyError> {
        self.webauthn
            .start_passkey_authentication(allow_credentials)
            .map_err(PasskeyError::Ceremony)
    }

    /// Complete an authentication begun by [`start_authentication`].
    ///
    /// `credential` is the client's [`PublicKeyCredential`] assertion and
    /// `state` the [`PasskeyAuthentication`] stashed by `start_authentication`.
    /// On success returns an [`AuthenticationResult`] whose
    /// [`cred_id`](AuthenticationResult::cred_id) identifies *which* of the
    /// candidate credentials answered.
    ///
    /// The verified assertion does **not** mutate the stored credential: per the
    /// WebAuthn spec the relying party must fold the result back into the
    /// answering passkey (bumping its signature counter / backup flags) and
    /// re-persist it, so a later clone replaying a stale counter is detectable.
    /// [`apply_authentication_result`] does this — pass it the same slice you
    /// handed to `start_authentication`.
    ///
    /// Returns [`PasskeyError::Ceremony`] if the challenge, origin, or signature
    /// fail to verify, or if the assertion answers a credential outside the
    /// candidate set.
    ///
    /// [`start_authentication`]: PasskeyRelyingParty::start_authentication
    pub fn finish_authentication(
        &self,
        credential: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> Result<AuthenticationResult, PasskeyError> {
        self.webauthn
            .finish_passkey_authentication(credential, state)
            .map_err(PasskeyError::Ceremony)
    }
}

/// What [`apply_authentication_result`] did with a finished
/// [`AuthenticationResult`].
///
/// The `&Passkey` carried by [`Updated`](Self::Updated) /
/// [`Unchanged`](Self::Unchanged) is the credential that answered the ceremony —
/// useful for "last used" tracking and re-persistence.
#[derive(Debug)]
#[non_exhaustive]
pub enum PasskeyUpdate<'a> {
    /// The answering passkey changed (its counter or backup flags advanced) and
    /// **must be re-persisted** — serialise it back with
    /// [`passkey_to_credential`](super::passkey_to_credential).
    Updated(&'a Passkey),

    /// The answering passkey was found but nothing changed, so no write is
    /// needed. This is the common case: synced passkeys (phone/cloud-backed)
    /// carry no monotonic signature counter, so a successful authentication
    /// leaves the stored credential byte-for-byte identical.
    Unchanged(&'a Passkey),

    /// No stored passkey matched [`AuthenticationResult::cred_id`] — the
    /// assertion was signed by a credential this user does not own. The login
    /// **must be rejected**; do not treat the user as authenticated.
    UnknownCredential,
}

/// Fold a finished [`AuthenticationResult`] back into the user's stored
/// passkeys, updating the one that answered.
///
/// [`finish_authentication`](PasskeyRelyingParty::finish_authentication)
/// verifies the assertion but leaves the stored credential untouched. The
/// WebAuthn spec requires the relying party to then update the answering
/// credential's signature counter / backup flags and re-persist it. Pass the
/// same passkeys you handed to
/// [`start_authentication`](PasskeyRelyingParty::start_authentication); this
/// finds the entry whose [`cred_id`](Passkey::cred_id) matches
/// [`result.cred_id()`](AuthenticationResult::cred_id), applies
/// [`Passkey::update_credential`], and reports the outcome via [`PasskeyUpdate`].
///
/// # Clone detection
///
/// `webauthn-rs` raises a credential's counter monotonically and never lowers
/// it, so a clone replaying a *stale* counter cannot roll the stored value
/// back — it simply yields [`PasskeyUpdate::Unchanged`]. True signature-counter
/// regression detection (flagging the clone rather than ignoring it) needs the
/// raw asserted-vs-stored counter comparison, which `webauthn-rs` encapsulates
/// inside [`Passkey`]; surfacing it would require its `danger-credential-internals`
/// feature. For the synced-passkey profile cheers ships this is largely moot —
/// most credentials never advance a counter at all (see [`PasskeyUpdate::Unchanged`]).
pub fn apply_authentication_result<'a>(
    passkeys: &'a mut [Passkey],
    result: &AuthenticationResult,
) -> PasskeyUpdate<'a> {
    let Some(passkey) = passkeys
        .iter_mut()
        .find(|p| p.cred_id() == result.cred_id())
    else {
        return PasskeyUpdate::UnknownCredential;
    };
    // `update_credential` returns Some(true) if it changed the credential,
    // Some(false) if the cred_id matched but nothing changed, None on cred_id
    // mismatch — which can't happen here, we just matched on cred_id.
    match passkey.update_credential(result) {
        Some(true) => PasskeyUpdate::Updated(passkey),
        _ => PasskeyUpdate::Unchanged(passkey),
    }
}

#[cfg(test)]
mod tests {
    use super::{apply_authentication_result, PasskeyUpdate};
    use crate::passkey::{Passkey, PasskeyError, PasskeyRelyingParty, Url, Uuid};
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_authenticator_rs::WebauthnAuthenticator;

    const RP_ID: &str = "example.com";
    const ORIGIN: &str = "https://example.com";

    fn rp() -> PasskeyRelyingParty {
        PasskeyRelyingParty::new(RP_ID, Url::parse(ORIGIN).unwrap())
            .expect("valid relying-party config")
    }

    /// Register one passkey *with a caller-supplied authenticator* so the same
    /// authenticator can later answer an authentication ceremony — SoftPasskey
    /// stores the private key keyed by rp_id + cred_id, so register and auth
    /// must run against the same instance.
    fn register_with(
        rp: &PasskeyRelyingParty,
        authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
    ) -> Passkey {
        let (ccr, state) = rp
            .start_registration(Uuid::new_v4(), "alice@example.com", "Alice", &[])
            .expect("start_registration");
        let credential = authenticator
            .do_registration(Url::parse(ORIGIN).unwrap(), ccr)
            .expect("software authenticator registration");
        rp.finish_registration(&credential, &state)
            .expect("finish_registration")
    }

    #[test]
    fn start_authentication_challenge_has_expected_shape() {
        let rp = rp();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let passkey = register_with(&rp, &mut authenticator);

        let (rcr, _state) = rp
            .start_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let json = serde_json::to_value(&rcr).unwrap();
        let pk = &json["publicKey"];

        assert_eq!(pk["rpId"], "example.com");
        assert!(!pk["challenge"].as_str().unwrap().is_empty());
        // Passkeys are self-contained MFA — user verification is required.
        assert_eq!(pk["userVerification"], "required");
        // The non-discoverable profile names the candidate credentials.
        let want_id = serde_json::to_value(passkey.cred_id()).unwrap();
        let allowed = pk["allowCredentials"]
            .as_array()
            .expect("allowCredentials present");
        assert!(
            allowed.iter().any(|c| c["id"] == want_id),
            "allowCredentials {allowed:?} should list the stored cred_id {want_id}"
        );
    }

    #[test]
    fn authenticate_round_trip_identifies_the_credential() {
        let rp = rp();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let passkey = register_with(&rp, &mut authenticator);

        let (rcr, state) = rp
            .start_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let assertion = authenticator
            .do_authentication(Url::parse(ORIGIN).unwrap(), rcr)
            .expect("software authenticator authentication");

        let result = rp.finish_authentication(&assertion, &state).unwrap();
        assert_eq!(
            result.cred_id().as_slice(),
            passkey.cred_id().as_slice(),
            "the result names the credential that answered"
        );
    }

    #[test]
    fn finish_rejects_an_assertion_bound_to_a_different_challenge() {
        let rp = rp();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let passkey = register_with(&rp, &mut authenticator);

        // Assertion answers challenge #1.
        let (rcr1, _state1) = rp
            .start_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let assertion = authenticator
            .do_authentication(Url::parse(ORIGIN).unwrap(), rcr1)
            .unwrap();

        // A second, independent authentication state with a fresh challenge.
        let (_rcr2, state2) = rp
            .start_authentication(std::slice::from_ref(&passkey))
            .unwrap();

        // The assertion answers challenge #1 but is verified against state #2.
        let err = rp.finish_authentication(&assertion, &state2).unwrap_err();
        assert!(matches!(err, PasskeyError::Ceremony(_)), "got {err:?}");
    }

    #[test]
    fn apply_result_updates_the_answering_passkey() {
        let rp = rp();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let passkey = register_with(&rp, &mut authenticator);

        let (rcr, state) = rp
            .start_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let assertion = authenticator
            .do_authentication(Url::parse(ORIGIN).unwrap(), rcr)
            .unwrap();
        let result = rp.finish_authentication(&assertion, &state).unwrap();

        let mut stored = vec![passkey.clone()];
        match apply_authentication_result(&mut stored, &result) {
            // Either outcome is valid: SoftPasskey may or may not advance the
            // counter. What matters is the answering credential was identified.
            PasskeyUpdate::Updated(p) | PasskeyUpdate::Unchanged(p) => {
                assert_eq!(p.cred_id().as_slice(), passkey.cred_id().as_slice());
            }
            PasskeyUpdate::UnknownCredential => {
                panic!("the answering passkey is in the stored set")
            }
        }
    }

    #[test]
    fn apply_result_flags_an_unknown_credential() {
        let rp = rp();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let passkey = register_with(&rp, &mut authenticator);

        let (rcr, state) = rp
            .start_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let assertion = authenticator
            .do_authentication(Url::parse(ORIGIN).unwrap(), rcr)
            .unwrap();
        let result = rp.finish_authentication(&assertion, &state).unwrap();

        // The user owns no passkey matching the assertion's cred_id.
        let mut none: Vec<Passkey> = Vec::new();
        assert!(matches!(
            apply_authentication_result(&mut none, &result),
            PasskeyUpdate::UnknownCredential
        ));
    }
}

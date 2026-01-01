//! Passkey registration ceremony — `start_registration` → `finish_registration`.
//!
//! See the [module docs](super) for the credential profile, the
//! server-side-state requirement, and the `UserId` ↔ `Uuid` handle contract.

use cheers_core::{Credential, DeviceBinding, DeviceId, UserId};

use super::{
    CreationChallengeResponse, Passkey, PasskeyError, PasskeyRegistration, PasskeyRelyingParty,
    RegisterPublicKeyCredential, Uuid,
};

impl PasskeyRelyingParty {
    /// Begin registering a new passkey for the user identified by `user_handle`.
    ///
    /// `user_handle` is the WebAuthn user handle (see the [module docs](super)
    /// on the `UserId` ↔ `Uuid` mapping). `user_name` is a friendly account
    /// label (e.g. an email) and `user_display_name` the person's chosen name;
    /// both *may* be surfaced by the authenticator's UI and **must not** be
    /// treated as keys — they can change at any time.
    ///
    /// `exclude` is the user's already-registered passkeys. Passing them stops
    /// an authenticator from enrolling a second credential for a user it has
    /// already registered (the multi-credential model still lets a *different*
    /// authenticator — phone, laptop, security key — register). Pass an empty
    /// slice for the first credential.
    ///
    /// Returns the [`CreationChallengeResponse`] to serialise to the client and
    /// the [`PasskeyRegistration`] state that **must be stored server-side**
    /// (single-use, confidential) until [`finish_registration`] is called.
    ///
    /// ```
    /// use cheers::passkey::{PasskeyRelyingParty, Url, Uuid};
    ///
    /// let rp = PasskeyRelyingParty::new(
    ///     "example.com",
    ///     Url::parse("https://example.com").unwrap(),
    /// )
    /// .unwrap();
    ///
    /// let (challenge, state) = rp
    ///     .start_registration(Uuid::new_v4(), "alice@example.com", "Alice", &[])
    ///     .unwrap();
    ///
    /// // `challenge` -> serialise to JSON, hand to the browser/authenticator.
    /// // `state`     -> stash server-side until the client responds.
    /// # let _ = (challenge, state);
    /// ```
    ///
    /// [`finish_registration`]: PasskeyRelyingParty::finish_registration
    pub fn start_registration(
        &self,
        user_handle: Uuid,
        user_name: &str,
        user_display_name: &str,
        exclude: &[Passkey],
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), PasskeyError> {
        let exclude_credentials = if exclude.is_empty() {
            None
        } else {
            Some(exclude.iter().map(|p| p.cred_id().clone()).collect())
        };
        self.webauthn
            .start_passkey_registration(
                user_handle,
                user_name,
                user_display_name,
                exclude_credentials,
            )
            .map_err(PasskeyError::Ceremony)
    }

    /// Complete a registration begun by [`start_registration`].
    ///
    /// `credential` is the client's `RegisterPublicKeyCredential` response and
    /// `state` the [`PasskeyRegistration`] stashed by `start_registration`.
    /// On success returns the [`Passkey`] to persist against the user's
    /// account (one user may hold many). The caller **must** reject the result
    /// if its [`cred_id`](Passkey::cred_id) is already registered to a
    /// *different* account.
    ///
    /// Returns [`PasskeyError::Ceremony`] if attestation, the challenge, the
    /// origin, or the signature fail to verify.
    ///
    /// [`start_registration`]: PasskeyRelyingParty::start_registration
    pub fn finish_registration(
        &self,
        credential: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<Passkey, PasskeyError> {
        self.webauthn
            .finish_passkey_registration(credential, state)
            .map_err(PasskeyError::Ceremony)
    }
}

/// Package a finished [`Passkey`] into a [`Credential`] for a `CredentialStore`
/// (P8) or a product's own table (P12).
///
/// The credential's [`binding`](Credential::binding) is
/// [`DeviceBinding::Passkey`] and its [`material`](Credential::material) is the
/// JSON-serialised passkey (credential ID + public key + counter).
/// [`passkey_from_credential`] is the inverse. A natural store key is the
/// passkey's [`cred_id`](Passkey::cred_id) bytes, which are unique per
/// credential.
pub fn passkey_to_credential(
    user_id: UserId,
    device_id: DeviceId,
    passkey: &Passkey,
) -> Result<Credential, PasskeyError> {
    let material = serde_json::to_vec(passkey).map_err(PasskeyError::Serialize)?;
    Ok(Credential::new(
        user_id,
        device_id,
        DeviceBinding::Passkey,
        material,
    ))
}

/// Recover a [`Passkey`] from a [`Credential`] previously produced by
/// [`passkey_to_credential`].
///
/// Returns [`PasskeyError::WrongBinding`] if the credential's binding is not
/// [`DeviceBinding::Passkey`], or [`PasskeyError::Deserialize`] if the stored
/// material is not a valid serialised passkey.
pub fn passkey_from_credential(cred: &Credential) -> Result<Passkey, PasskeyError> {
    if !matches!(cred.binding, DeviceBinding::Passkey) {
        return Err(PasskeyError::WrongBinding {
            found: cred.binding.clone(),
        });
    }
    serde_json::from_slice(&cred.material).map_err(PasskeyError::Deserialize)
}

#[cfg(test)]
mod tests {
    use super::{passkey_from_credential, passkey_to_credential};
    use crate::passkey::{Passkey, PasskeyError, PasskeyRelyingParty, Url, Uuid};
    use cheers_core::{Credential, DeviceBinding, DeviceId, UserId};
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_authenticator_rs::WebauthnAuthenticator;

    const RP_ID: &str = "example.com";
    const ORIGIN: &str = "https://example.com";

    fn rp() -> PasskeyRelyingParty {
        PasskeyRelyingParty::new(RP_ID, Url::parse(ORIGIN).unwrap())
            .expect("valid relying-party config")
    }

    /// Drive a full registration ceremony with a software authenticator and
    /// return the resulting credential. A real [`Passkey`] can only be obtained
    /// by completing a ceremony — its internals are crate-private to webauthn-rs
    /// — so this is the source for the persistence + bridge assertions.
    fn register_one(rp: &PasskeyRelyingParty) -> Passkey {
        let (ccr, state) = rp
            .start_registration(Uuid::new_v4(), "alice@example.com", "Alice", &[])
            .expect("start_registration");
        // `falsify_uv = true`: the passkey profile requires user verification,
        // which a headless soft authenticator can only assert by fiat.
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let credential = authenticator
            .do_registration(Url::parse(ORIGIN).unwrap(), ccr)
            .expect("software authenticator registration");
        rp.finish_registration(&credential, &state)
            .expect("finish_registration")
    }

    #[test]
    fn start_registration_challenge_has_expected_shape() {
        let rp = rp();
        let (ccr, _state) = rp
            .start_registration(Uuid::new_v4(), "alice@example.com", "Alice Example", &[])
            .unwrap();
        let json = serde_json::to_value(&ccr).unwrap();
        let pk = &json["publicKey"];

        assert_eq!(pk["rp"]["id"], "example.com");
        assert_eq!(pk["user"]["name"], "alice@example.com");
        assert_eq!(pk["user"]["displayName"], "Alice Example");
        assert!(!pk["user"]["id"].as_str().unwrap().is_empty());
        assert!(!pk["challenge"].as_str().unwrap().is_empty());
        assert!(!pk["pubKeyCredParams"].as_array().unwrap().is_empty());
        assert_eq!(pk["attestation"], "none");
        // Non-discoverable by design ("discoverable off"): no resident key.
        assert_eq!(pk["authenticatorSelection"]["requireResidentKey"], false);
        // Passkeys are self-contained MFA — user verification is required.
        assert_eq!(pk["authenticatorSelection"]["userVerification"], "required");
    }

    #[test]
    fn start_registration_excludes_supplied_credentials() {
        let rp = rp();
        let existing = register_one(&rp);

        let (ccr, _state) = rp
            .start_registration(
                Uuid::new_v4(),
                "alice@example.com",
                "Alice",
                std::slice::from_ref(&existing),
            )
            .unwrap();

        let json = serde_json::to_value(&ccr).unwrap();
        // The credential id is serialised as base64url in both places, so
        // round-tripping the cred_id through serde gives the value to match.
        let want_id = serde_json::to_value(existing.cred_id()).unwrap();
        let excluded = json["publicKey"]["excludeCredentials"]
            .as_array()
            .expect("excludeCredentials present when a passkey is excluded");
        assert!(
            excluded.iter().any(|c| c["id"] == want_id),
            "excludeCredentials {excluded:?} should list the existing cred_id {want_id}"
        );
    }

    #[test]
    fn register_round_trip_yields_a_passkey() {
        let rp = rp();
        let passkey = register_one(&rp);
        assert!(!passkey.cred_id().is_empty());
    }

    #[test]
    fn finish_rejects_a_credential_bound_to_a_different_challenge() {
        let rp = rp();

        // Ceremony #1 produces a credential answering challenge #1.
        let (ccr1, _state1) = rp
            .start_registration(Uuid::new_v4(), "alice@example.com", "Alice", &[])
            .unwrap();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let credential = authenticator
            .do_registration(Url::parse(ORIGIN).unwrap(), ccr1)
            .unwrap();

        // A second, independent registration state with a fresh challenge.
        let (_ccr2, state2) = rp
            .start_registration(Uuid::new_v4(), "alice@example.com", "Alice", &[])
            .unwrap();

        // The credential answers challenge #1 but is verified against state #2.
        let err = rp.finish_registration(&credential, &state2).unwrap_err();
        assert!(matches!(err, PasskeyError::Ceremony(_)), "got {err:?}");
    }

    #[test]
    fn bridge_round_trips_a_passkey_through_a_credential() {
        let rp = rp();
        let passkey = register_one(&rp);

        let cred =
            passkey_to_credential(UserId::new("u-1"), DeviceId::new("d-1"), &passkey).unwrap();
        assert_eq!(cred.binding, DeviceBinding::Passkey);
        assert_eq!(cred.user_id, UserId::new("u-1"));
        assert_eq!(cred.device_id, DeviceId::new("d-1"));

        let recovered = passkey_from_credential(&cred).unwrap();
        assert_eq!(recovered.cred_id().as_slice(), passkey.cred_id().as_slice());
    }

    #[test]
    fn bridge_rejects_a_non_passkey_binding() {
        let cred = Credential::new(
            UserId::new("u-1"),
            DeviceId::new("d-1"),
            DeviceBinding::EmailPassword,
            b"irrelevant".to_vec(),
        );
        let err = passkey_from_credential(&cred).unwrap_err();
        assert!(
            matches!(
                err,
                PasskeyError::WrongBinding {
                    found: DeviceBinding::EmailPassword
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn bridge_rejects_garbage_material() {
        let cred = Credential::new(
            UserId::new("u-1"),
            DeviceId::new("d-1"),
            DeviceBinding::Passkey,
            b"not a serialised passkey".to_vec(),
        );
        let err = passkey_from_credential(&cred).unwrap_err();
        assert!(matches!(err, PasskeyError::Deserialize(_)), "got {err:?}");
    }

    #[test]
    fn builder_configures_name_and_extra_origin() {
        let extra = Url::parse("https://auth.example.com").unwrap();
        let rp = PasskeyRelyingParty::builder(RP_ID, Url::parse(ORIGIN).unwrap())
            .rp_name("Example")
            .allow_subdomains(true)
            .append_allowed_origin(extra.clone())
            .build()
            .unwrap();

        assert_eq!(rp.rp_id(), "example.com");
        assert_eq!(rp.rp_name(), Some("Example"));
        let origins = rp.allowed_origins();
        assert!(origins.iter().any(|o| o == &Url::parse(ORIGIN).unwrap()));
        assert!(origins.iter().any(|o| o == &extra));
    }

    #[test]
    fn new_rejects_origin_unrelated_to_rp_id() {
        let err = PasskeyRelyingParty::new("example.com", Url::parse("https://evil.test").unwrap())
            .unwrap_err();
        assert!(matches!(err, PasskeyError::Config(_)), "got {err:?}");
    }
}

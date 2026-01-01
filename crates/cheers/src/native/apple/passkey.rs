//! Native Apple passkey UI — `ASAuthorizationController` bridge (P9).
//!
//! Wraps [`ASAuthorizationController`] with
//! `ASAuthorizationPlatformPublicKeyCredentialProvider` to surface the
//! system-native Face ID / Touch ID / security-key prompt on macOS and iOS.
//! The native ceremony returns raw attestation or assertion bytes; those bytes
//! feed straight into [`crate::passkey::PasskeyRelyingParty`]'s server-side
//! `finish_registration` / `finish_authentication` calls.
//!
//! ## Bridge shape
//!
//! ```text
//! server: start_registration() -> CreationChallengeResponse
//!   → RegistrationRequest::from_challenge()
//!     → perform_registration(req, callback)     ← this module
//!       native system prompt fires; callback invoked with NativePasskeyRegistration
//!         → native_registration_to_credential()
//!           → PasskeyRelyingParty::finish_registration()   ← passkey module
//! ```
//!
//! ## Thread requirements
//!
//! `ASAuthorizationController` **must** be created and driven on the **main
//! thread**; both `perform_*` functions are `unsafe` and document this
//! requirement. The callback is also delivered on the main thread. Callers on
//! background threads (e.g. a Tauri command) should dispatch via
//! `AppHandle::run_on_main_thread` and bridge the result with a channel — see
//! `examples/native_passkey.rs`.
//!
//! ## Cleanup note
//!
//! `objc2-authentication-services` is fast-moving; re-audit the generated type
//! API on every version bump (method names can change between minor releases).

#![cfg(any(target_os = "macos", target_os = "ios"))]

use std::cell::RefCell;
use std::ffi::c_void;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use objc2::runtime::{AnyClass, AnyObject, Bool, NSObject, NSObjectProtocol};
use objc2::{declare_class, msg_send, msg_send_id, ClassType, DeclaredClass};
use objc2::mutability::InteriorMutable;
use objc2::rc::Retained;
use objc2_authentication_services::{
    ASAuthorization, ASAuthorizationController,
    ASAuthorizationControllerDelegate,
    ASAuthorizationPlatformPublicKeyCredentialDescriptor,
    ASAuthorizationPlatformPublicKeyCredentialProvider,
};
use objc2_foundation::{NSArray, NSData, NSError, NSString};

// When the server-side passkey feature is also active (e.g. macos + passkey),
// import the protocol types through crate::passkey which re-exports them from
// webauthn-rs. When only the ios feature is active (client only — no openssl),
// import directly from webauthn-rs-proto, which has no openssl dependency.
#[cfg(feature = "passkey")]
use crate::passkey::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};
#[cfg(not(feature = "passkey"))]
use webauthn_rs_proto::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

// ── Public request / response types ────────────────────────────────────────

/// Parameters for a native passkey **registration** ceremony.
///
/// Build from a [`CreationChallengeResponse`] via
/// [`RegistrationRequest::from_challenge`].
#[derive(Debug, Clone)]
pub struct RegistrationRequest {
    /// Raw challenge bytes extracted from the server's `CreationChallengeResponse`.
    pub challenge: Vec<u8>,
    /// Relying-party identifier (effective domain, e.g. `"example.com"`).
    pub rp_id: String,
    /// WebAuthn user handle — stable, opaque bytes (not PII). Typically a UUID.
    pub user_handle: Vec<u8>,
    /// Account identifier shown in the OS passkey sheet (e.g. an email address).
    pub user_name: String,
    /// Human-readable display name shown in the passkey sheet.
    pub user_display_name: String,
}

/// Parameters for a native passkey **authentication** ceremony.
///
/// Build from a [`RequestChallengeResponse`] via
/// [`AuthenticationRequest::from_challenge`].
#[derive(Debug, Clone)]
pub struct AuthenticationRequest {
    /// Raw challenge bytes extracted from the server's `RequestChallengeResponse`.
    pub challenge: Vec<u8>,
    /// Relying-party identifier.
    pub rp_id: String,
    /// Credential IDs the server allows (one per registered passkey for this user).
    /// Pass an empty vec to allow any credential (discoverable / resident-key mode).
    pub allowed_credentials: Vec<Vec<u8>>,
}

/// Raw bytes returned by a successful native **registration** ceremony.
///
/// Pass to [`native_registration_to_credential`] to produce the
/// [`RegisterPublicKeyCredential`] that
/// [`PasskeyRelyingParty::finish_registration`](crate::passkey::PasskeyRelyingParty::finish_registration)
/// expects.
#[derive(Debug, Clone)]
pub struct NativePasskeyRegistration {
    pub credential_id: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub client_data_json: Vec<u8>,
}

/// Raw bytes returned by a successful native **authentication** ceremony.
///
/// Pass to [`native_assertion_to_credential`] to produce the
/// [`PublicKeyCredential`] that
/// [`PasskeyRelyingParty::finish_authentication`](crate::passkey::PasskeyRelyingParty::finish_authentication)
/// expects.
#[derive(Debug, Clone)]
pub struct NativePasskeyAssertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
    /// User handle echoed back from the authenticator.
    pub user_handle: Vec<u8>,
}

/// Errors produced by the native passkey bridge.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativePasskeyError {
    /// The OS `ASAuthorizationController` callback delivered an error.
    #[error("system passkey error: {0}")]
    SystemError(String),

    /// The registration ceremony succeeded but the attestation object was empty.
    #[error("attestation object missing from registration response")]
    MissingAttestation,

    /// The credential returned by the system was neither a registration nor an
    /// authentication result.
    #[error("unexpected credential type returned by ASAuthorizationController")]
    UnexpectedCeremonyKind,

    /// A ceremony is already in progress on this thread.
    #[error("a passkey ceremony is already in progress")]
    AlreadyInFlight,

    /// The ceremony was cancelled or the controller deallocated before firing.
    #[error("passkey ceremony cancelled")]
    Cancelled,

    /// Failed to build the `RegisterPublicKeyCredential` / `PublicKeyCredential`
    /// JSON shape from the raw ceremony bytes.
    #[error("building WebAuthn credential from native bytes: {0}")]
    Encode(#[from] serde_json::Error),
}

// ── From-challenge constructors ─────────────────────────────────────────────

impl RegistrationRequest {
    /// Extract the fields needed for `ASAuthorizationController` from the
    /// server-issued `CreationChallengeResponse`.
    pub fn from_challenge(
        ccr: &CreationChallengeResponse,
        user_handle: Vec<u8>,
        user_name: impl Into<String>,
        user_display_name: impl Into<String>,
    ) -> Result<Self, NativePasskeyError> {
        let json = serde_json::to_value(ccr)?;
        let pk = &json["publicKey"];
        let challenge = b64url_decode(pk["challenge"].as_str().unwrap_or(""))?;
        let rp_id = pk["rp"]["id"].as_str().unwrap_or_default().to_owned();
        Ok(Self {
            challenge,
            rp_id,
            user_handle,
            user_name: user_name.into(),
            user_display_name: user_display_name.into(),
        })
    }
}

impl AuthenticationRequest {
    /// Extract the fields needed for `ASAuthorizationController` from the
    /// server-issued `RequestChallengeResponse`.
    pub fn from_challenge(
        rcr: &RequestChallengeResponse,
        rp_id: impl Into<String>,
        allowed_credential_ids: Vec<Vec<u8>>,
    ) -> Result<Self, NativePasskeyError> {
        let json = serde_json::to_value(rcr)?;
        let challenge =
            b64url_decode(json["publicKey"]["challenge"].as_str().unwrap_or(""))?;
        Ok(Self {
            challenge,
            rp_id: rp_id.into(),
            allowed_credentials: allowed_credential_ids,
        })
    }
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, NativePasskeyError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| NativePasskeyError::SystemError(format!("base64url decode: {e}")))
}

// ── Thread-local callback state ─────────────────────────────────────────────

// Callbacks are always on the main thread (MainThreadOnly delegate), so a
// thread-local RefCell is safe and avoids any Mutex overhead.
thread_local! {
    static PENDING: RefCell<Option<Box<dyn FnOnce(Result<CeremonyOutcome, NativePasskeyError>)>>>
        = RefCell::new(None);
}

enum CeremonyOutcome {
    Registration(NativePasskeyRegistration),
    Authentication(NativePasskeyAssertion),
}

fn dispatch_outcome(outcome: Result<CeremonyOutcome, NativePasskeyError>) {
    PENDING.with(|cell| {
        if let Some(cb) = cell.borrow_mut().take() {
            cb(outcome);
        }
    });
}

// ── ObjC utilities ──────────────────────────────────────────────────────────

/// Read `NSData` bytes into a `Vec<u8>`.
unsafe fn ns_data_to_vec(data: *const NSData) -> Vec<u8> {
    if data.is_null() {
        return Vec::new();
    }
    let len: usize = msg_send![data, length];
    if len == 0 {
        return Vec::new();
    }
    let ptr: *const u8 = msg_send![data, bytes];
    std::slice::from_raw_parts(ptr, len).to_vec()
}

/// Wrap bytes in an autoreleased `NSData`.
unsafe fn bytes_to_ns_data(bytes: &[u8]) -> Retained<NSData> {
    msg_send_id![
        NSData::class(),
        dataWithBytes: bytes.as_ptr().cast::<c_void>()
        length: bytes.len()
    ]
}

/// Wrap a `&str` in an `NSString` (UTF-8).
unsafe fn str_to_ns_string(s: &str) -> Retained<NSString> {
    let bytes = s.as_bytes();
    msg_send_id![
        NSString::alloc(),
        initWithBytes: bytes.as_ptr().cast::<c_void>()
        length: bytes.len()
        encoding: 4u64   // NSUTF8StringEncoding
    ]
}

/// Extract the ceremony outcome from a completed `ASAuthorization`.
unsafe fn extract_outcome(
    authorization: &ASAuthorization,
) -> Result<CeremonyOutcome, NativePasskeyError> {
    let credential: *const AnyObject = msg_send![authorization, credential];

    if let Some(reg_class) =
        AnyClass::get("ASAuthorizationPlatformPublicKeyCredentialRegistration")
    {
        let is_reg: Bool = msg_send![credential, isKindOfClass: reg_class];
        if is_reg.as_bool() {
            let cred_id: *const NSData = msg_send![credential, credentialID];
            let attestation: *const NSData = msg_send![credential, rawAttestationObject];
            let client_data: *const NSData = msg_send![credential, rawClientDataJSON];

            if attestation.is_null() {
                return Err(NativePasskeyError::MissingAttestation);
            }

            return Ok(CeremonyOutcome::Registration(NativePasskeyRegistration {
                credential_id: ns_data_to_vec(cred_id),
                attestation_object: ns_data_to_vec(attestation),
                client_data_json: ns_data_to_vec(client_data),
            }));
        }
    }

    if let Some(assert_class) =
        AnyClass::get("ASAuthorizationPlatformPublicKeyCredentialAssertion")
    {
        let is_assert: Bool = msg_send![credential, isKindOfClass: assert_class];
        if is_assert.as_bool() {
            let cred_id: *const NSData = msg_send![credential, credentialID];
            let auth_data: *const NSData = msg_send![credential, rawAuthenticatorData];
            let client_data: *const NSData = msg_send![credential, rawClientDataJSON];
            let signature: *const NSData = msg_send![credential, signature];
            let user_id: *const NSData = msg_send![credential, userID];

            return Ok(CeremonyOutcome::Authentication(NativePasskeyAssertion {
                credential_id: ns_data_to_vec(cred_id),
                authenticator_data: ns_data_to_vec(auth_data),
                client_data_json: ns_data_to_vec(client_data),
                signature: ns_data_to_vec(signature),
                user_handle: ns_data_to_vec(user_id),
            }));
        }
    }

    Err(NativePasskeyError::UnexpectedCeremonyKind)
}

// ── Delegate class ──────────────────────────────────────────────────────────

declare_class!(
    struct PasskeyDelegate;

    unsafe impl ClassType for PasskeyDelegate {
        type Super = NSObject;
        type Mutability = InteriorMutable;
        const NAME: &'static str = "CheersPasskeyDelegate_R016";
    }

    impl DeclaredClass for PasskeyDelegate {
        type Ivars = ();
    }

    unsafe impl NSObjectProtocol for PasskeyDelegate {}

    unsafe impl ASAuthorizationControllerDelegate for PasskeyDelegate {
        #[method(authorizationController:didCompleteWithAuthorization:)]
        unsafe fn did_complete_with_authorization(
            &self,
            _controller: &ASAuthorizationController,
            authorization: &ASAuthorization,
        ) {
            dispatch_outcome(extract_outcome(authorization));
        }

        #[method(authorizationController:didCompleteWithError:)]
        unsafe fn did_complete_with_error(
            &self,
            _controller: &ASAuthorizationController,
            error: &NSError,
        ) {
            let desc: *const NSString = msg_send![error, localizedDescription];
            let text = if desc.is_null() {
                "unknown error".to_owned()
            } else {
                // NSString -> &str via UTF8String
                let ptr: *const std::os::raw::c_char = msg_send![desc, UTF8String];
                if ptr.is_null() {
                    "unknown error".to_owned()
                } else {
                    std::ffi::CStr::from_ptr(ptr)
                        .to_string_lossy()
                        .into_owned()
                }
            };
            dispatch_outcome(Err(NativePasskeyError::SystemError(text)));
        }
    }
);

// ── Public ceremony entry points ────────────────────────────────────────────

/// Show the system passkey **registration** sheet and call `callback` on the
/// main thread when done.
///
/// Returns `Err(AlreadyInFlight)` if another ceremony is pending.
///
/// # Safety
///
/// Must be called from the **main thread**. `ASAuthorizationController`
/// requires it, and the callback is delivered there. On background threads,
/// dispatch via `AppHandle::run_on_main_thread` (see `examples/native_passkey.rs`).
pub unsafe fn perform_registration<F>(
    req: RegistrationRequest,
    callback: F,
) -> Result<(), NativePasskeyError>
where
    F: FnOnce(Result<NativePasskeyRegistration, NativePasskeyError>) + 'static,
{
    PENDING.with(|cell| -> Result<(), NativePasskeyError> {
        let mut guard = cell.borrow_mut();
        if guard.is_some() {
            return Err(NativePasskeyError::AlreadyInFlight);
        }
        *guard = Some(Box::new(move |outcome| match outcome {
            Ok(CeremonyOutcome::Registration(r)) => callback(Ok(r)),
            Ok(_) => callback(Err(NativePasskeyError::UnexpectedCeremonyKind)),
            Err(e) => callback(Err(e)),
        }));
        Ok(())
    })?;

    let rp_id = str_to_ns_string(&req.rp_id);
    let provider: Retained<ASAuthorizationPlatformPublicKeyCredentialProvider> =
        msg_send_id![
            ASAuthorizationPlatformPublicKeyCredentialProvider::alloc(),
            initWithRelyingPartyIdentifier: &*rp_id
        ];

    let user_handle_data = bytes_to_ns_data(&req.user_handle);
    let user_name_str = str_to_ns_string(&req.user_name);
    let reg_req: Retained<AnyObject> = msg_send_id![
        &*provider,
        requestToCreateCredentialWithUserHandle: &*user_handle_data
        name: &*user_name_str
    ];

    let challenge_data = bytes_to_ns_data(&req.challenge);
    let _: () = msg_send![&*reg_req, setChallenge: &*challenge_data];

    let display_name_str = str_to_ns_string(&req.user_display_name);
    let _: () = msg_send![&*reg_req, setUserDisplayName: &*display_name_str];

    // NSArray for initWithAuthorizationRequests: — pass as raw id* array.
    let requests: Retained<NSArray<NSObject>> = {
        let ptr = &*reg_req as *const AnyObject as *const NSObject;
        msg_send_id![
            NSArray::<NSObject>::class(),
            arrayWithObjects: &ptr as *const *const NSObject
            count: 1usize
        ]
    };

    let controller: Retained<ASAuthorizationController> = msg_send_id![
        ASAuthorizationController::alloc(),
        initWithAuthorizationRequests: &*requests
    ];

    let delegate: Retained<PasskeyDelegate> = {
        let partial = PasskeyDelegate::alloc().set_ivars(());
        msg_send_id![super(partial), init]
    };

    let _: () = msg_send![&*controller, setDelegate: &*delegate];
    let _: () = msg_send![&*controller, performRequests];

    // Extend the lifetimes so the OS can retain controller/delegate for the
    // ceremony duration. The ObjC retain count holds them alive after this.
    std::mem::forget(controller);
    std::mem::forget(delegate);

    Ok(())
}

/// Show the system passkey **authentication** sheet and call `callback` on the
/// main thread when done.
///
/// See [`perform_registration`] for the threading contract and safety
/// requirements.
pub unsafe fn perform_authentication<F>(
    req: AuthenticationRequest,
    callback: F,
) -> Result<(), NativePasskeyError>
where
    F: FnOnce(Result<NativePasskeyAssertion, NativePasskeyError>) + 'static,
{
    PENDING.with(|cell| -> Result<(), NativePasskeyError> {
        let mut guard = cell.borrow_mut();
        if guard.is_some() {
            return Err(NativePasskeyError::AlreadyInFlight);
        }
        *guard = Some(Box::new(move |outcome| match outcome {
            Ok(CeremonyOutcome::Authentication(a)) => callback(Ok(a)),
            Ok(_) => callback(Err(NativePasskeyError::UnexpectedCeremonyKind)),
            Err(e) => callback(Err(e)),
        }));
        Ok(())
    })?;

    let rp_id = str_to_ns_string(&req.rp_id);
    let provider: Retained<ASAuthorizationPlatformPublicKeyCredentialProvider> =
        msg_send_id![
            ASAuthorizationPlatformPublicKeyCredentialProvider::alloc(),
            initWithRelyingPartyIdentifier: &*rp_id
        ];

    let descriptors: Vec<Retained<ASAuthorizationPlatformPublicKeyCredentialDescriptor>> = req
        .allowed_credentials
        .iter()
        .map(|id| {
            let ns_id = bytes_to_ns_data(id);
            msg_send_id![
                ASAuthorizationPlatformPublicKeyCredentialDescriptor::alloc(),
                initWithCredentialID: &*ns_id
            ]
        })
        .collect();

    let descriptor_refs: Vec<*const ASAuthorizationPlatformPublicKeyCredentialDescriptor> =
        descriptors
            .iter()
            .map(|d| d.as_ref() as *const _)
            .collect();

    let allowed: Retained<NSArray<ASAuthorizationPlatformPublicKeyCredentialDescriptor>> =
        msg_send_id![
            NSArray::<ASAuthorizationPlatformPublicKeyCredentialDescriptor>::class(),
            arrayWithObjects: descriptor_refs.as_ptr()
            count: descriptor_refs.len()
        ];

    let assert_req: Retained<AnyObject> = msg_send_id![
        &*provider,
        requestToAssertCredentialWithAllowedCredentials: &*allowed
    ];

    let challenge_data = bytes_to_ns_data(&req.challenge);
    let _: () = msg_send![&*assert_req, setChallenge: &*challenge_data];

    let requests: Retained<NSArray<NSObject>> = {
        let ptr = &*assert_req as *const AnyObject as *const NSObject;
        msg_send_id![
            NSArray::<NSObject>::class(),
            arrayWithObjects: &ptr as *const *const NSObject
            count: 1usize
        ]
    };

    let controller: Retained<ASAuthorizationController> = msg_send_id![
        ASAuthorizationController::alloc(),
        initWithAuthorizationRequests: &*requests
    ];

    let delegate: Retained<PasskeyDelegate> = {
        let partial = PasskeyDelegate::alloc().set_ivars(());
        msg_send_id![super(partial), init]
    };

    let _: () = msg_send![&*controller, setDelegate: &*delegate];
    let _: () = msg_send![&*controller, performRequests];

    std::mem::forget(controller);
    std::mem::forget(delegate);

    Ok(())
}

// ── Bridge to webauthn-rs types ─────────────────────────────────────────────

/// Convert a native registration result to the [`RegisterPublicKeyCredential`]
/// JSON shape that
/// [`PasskeyRelyingParty::finish_registration`](crate::passkey::PasskeyRelyingParty::finish_registration)
/// expects.
///
/// Pure Rust — no ObjC involved; safe to call on any thread.
pub fn native_registration_to_credential(
    reg: &NativePasskeyRegistration,
) -> Result<RegisterPublicKeyCredential, NativePasskeyError> {
    let id = URL_SAFE_NO_PAD.encode(&reg.credential_id);
    let json = serde_json::json!({
        "id": id,
        "rawId": id,
        "response": {
            "attestationObject": URL_SAFE_NO_PAD.encode(&reg.attestation_object),
            "clientDataJSON": URL_SAFE_NO_PAD.encode(&reg.client_data_json),
        },
        "type": "public-key",
    });
    serde_json::from_value(json).map_err(NativePasskeyError::Encode)
}

/// Convert a native authentication assertion to the [`PublicKeyCredential`]
/// JSON shape that
/// [`PasskeyRelyingParty::finish_authentication`](crate::passkey::PasskeyRelyingParty::finish_authentication)
/// expects.
pub fn native_assertion_to_credential(
    assertion: &NativePasskeyAssertion,
) -> Result<PublicKeyCredential, NativePasskeyError> {
    let id = URL_SAFE_NO_PAD.encode(&assertion.credential_id);
    let json = serde_json::json!({
        "id": id,
        "rawId": id,
        "response": {
            "authenticatorData": URL_SAFE_NO_PAD.encode(&assertion.authenticator_data),
            "clientDataJSON": URL_SAFE_NO_PAD.encode(&assertion.client_data_json),
            "signature": URL_SAFE_NO_PAD.encode(&assertion.signature),
            "userHandle": URL_SAFE_NO_PAD.encode(&assertion.user_handle),
        },
        "type": "public-key",
    });
    serde_json::from_value(json).map_err(NativePasskeyError::Encode)
}

//! Native passkey registration + authentication — full round-trip example.
//!
//! Exercises the P9 bridge: server issues a challenge via `PasskeyRelyingParty`,
//! native `ASAuthorizationController` shows the system passkey sheet, server
//! verifies the result.
//!
//! ## Build
//!
//! ```bash
//! cargo build --example native_passkey --features macos,passkey
//! ```
//!
//! Running requires macOS 13+ and a properly entitle app bundle
//! (`com.apple.developer.webauthn.relying-party-ids`). A bare CLI will
//! receive an OS error because it lacks the entitlement.
//!
//! ## Tauri wiring pattern
//!
//! In a Tauri app the command handler runs on a background tokio thread.
//! Dispatch to the main thread via `AppHandle::run_on_main_thread`, then
//! bridge back with `tokio::sync::oneshot`:
//!
//! ```rust,ignore
//! #[tauri::command]
//! async fn register_passkey(
//!     app: tauri::AppHandle,
//!     challenge_json: String,
//!     user_handle: Vec<u8>,
//!     user_name: String,
//! ) -> Result<serde_json::Value, String> {
//!     use cheers::native::apple::passkey::{
//!         native_registration_to_credential, perform_registration, RegistrationRequest,
//!     };
//!     use cheers::passkey::CreationChallengeResponse;
//!
//!     let ccr: CreationChallengeResponse = serde_json::from_str(&challenge_json)
//!         .map_err(|e| e.to_string())?;
//!     let req = RegistrationRequest::from_challenge(&ccr, user_handle, &user_name, &user_name)
//!         .map_err(|e| e.to_string())?;
//!
//!     let (tx, rx) = tokio::sync::oneshot::channel();
//!     app.run_on_main_thread(move || {
//!         // SAFETY: dispatched to the main thread by run_on_main_thread.
//!         unsafe {
//!             perform_registration(req, move |r| { let _ = tx.send(r); }).ok();
//!         }
//!     }).map_err(|e| e.to_string())?;
//!
//!     let native_reg = rx.await
//!         .map_err(|_| "ceremony cancelled".to_owned())?
//!         .map_err(|e| e.to_string())?;
//!
//!     let cred = native_registration_to_credential(&native_reg)
//!         .map_err(|e| e.to_string())?;
//!     serde_json::to_value(&cred).map_err(|e| e.to_string())
//! }
//! ```

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn main() {
    eprintln!("native_passkey example requires macOS or iOS");
    std::process::exit(1);
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn main() {
    use cheers::native::apple::passkey::{
        native_registration_to_credential, perform_registration, RegistrationRequest,
    };
    use cheers::passkey::{PasskeyRelyingParty, Url, Uuid};

    const RP_ID: &str = "example.com";
    const ORIGIN: &str = "https://example.com";

    let rp = PasskeyRelyingParty::new(RP_ID, Url::parse(ORIGIN).unwrap())
        .expect("valid RP configuration");

    let user_uuid = Uuid::new_v4();
    let user_name = "alice@example.com";

    // Server: issue the registration challenge.
    let (ccr, reg_state) = rp
        .start_registration(user_uuid, user_name, "Alice Example", &[])
        .expect("start_registration");

    // Build the native request from the server challenge.
    let req = RegistrationRequest::from_challenge(
        &ccr,
        user_uuid.as_bytes().to_vec(),
        user_name,
        "Alice Example",
    )
    .expect("build RegistrationRequest");

    let (tx, rx) = std::sync::mpsc::sync_channel(1);

    // SAFETY: this main() runs on the main thread; no other thread has
    // called into the ObjC runtime yet.
    unsafe {
        perform_registration(req, move |result| {
            let _ = tx.send(result);
        })
        .expect("perform_registration launched");
    }

    // Pump the default run-loop mode so ASAuthorizationController can deliver
    // its delegate callback. In a real NSApp or Tauri app, the host already
    // drives the run loop; this loop is only needed in the bare CLI context.
    loop {
        match rx.try_recv() {
            Ok(result) => {
                let native_reg = result.expect("registration succeeded");

                let credential = native_registration_to_credential(&native_reg)
                    .expect("build RegisterPublicKeyCredential");

                let passkey = rp
                    .finish_registration(&credential, &reg_state)
                    .expect("finish_registration");

                println!("Registered passkey: {:?}", passkey.cred_id());
                return;
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                // Run the default run-loop mode for 100 ms to let the OS
                // deliver the ASAuthorizationController delegate callback.
                unsafe {
                    use objc2::runtime::AnyObject;
                    let rl: *const AnyObject =
                        objc2::msg_send![objc2::runtime::AnyClass::get("NSRunLoop").unwrap(), currentRunLoop];
                    let mode: *const AnyObject =
                        objc2::msg_send![objc2::runtime::AnyClass::get("NSString").unwrap(),
                            stringWithUTF8String: c"kCFRunLoopDefaultMode".as_ptr()];
                    let date: *const AnyObject =
                        objc2::msg_send![objc2::runtime::AnyClass::get("NSDate").unwrap(),
                            dateWithTimeIntervalSinceNow: 0.1f64];
                    let _: bool = objc2::msg_send![rl, runMode: mode beforeDate: date];
                }
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                eprintln!("ceremony cancelled");
                return;
            }
        }
    }
}

//! The sealed vault's on-disk framing: `[version][iv_len][iv][ciphertext]`.
//!
//! Split out of [`jni_keystore`](super::jni_keystore) deliberately. The rest of
//! that module cannot be compiled off Android, let alone run — but this part is
//! the **file format**, the thing a truncated write, a restored backup, or a
//! future app version will hand back, and "we never execute the parser for our
//! own on-disk format" is not an acceptable place to land. Here it compiles and
//! its tests run on every host.
//!
//! Self-describing on the IV length even though Android Keystore's GCM IV is
//! always 12 bytes, so a future keymaster that disagrees cannot silently
//! mis-split a blob. The version byte is *checked*, not assumed: an unrecognized
//! one is an error rather than a guess at the layout.

use cheers_core::StoreError;

/// Current frame version. Bump only alongside a reader that still accepts the
/// old one, or every paired device has to pair again.
pub(super) const FRAME_VERSION: u8 = 0x01;

/// Join an IV and a ciphertext into one blob for [`unframe`] to split.
pub(super) fn frame(iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + iv.len() + ciphertext.len());
    out.push(FRAME_VERSION);
    out.push(iv.len() as u8);
    out.extend_from_slice(iv);
    out.extend_from_slice(ciphertext);
    out
}

/// Split a framed blob back into `(iv, ciphertext)`, rejecting anything that
/// isn't one.
///
/// Returns [`StoreError::Backend`] rather than panicking on a short or
/// unrecognized blob: the input is a file on disk that a restore, a truncation,
/// or a different app version could have written.
pub(super) fn unframe(sealed: &[u8]) -> Result<(&[u8], &[u8]), StoreError> {
    let (&version, rest) = sealed
        .split_first()
        .ok_or_else(|| StoreError::Backend("sealed vault is empty".into()))?;
    if version != FRAME_VERSION {
        return Err(StoreError::Backend(format!(
            "sealed vault has unknown frame version {version:#04x}"
        )));
    }
    let (&iv_len, rest) = rest
        .split_first()
        .ok_or_else(|| StoreError::Backend("sealed vault is truncated before its IV".into()))?;
    let iv_len = usize::from(iv_len);
    if rest.len() < iv_len {
        return Err(StoreError::Backend(
            "sealed vault is truncated inside its IV".into(),
        ));
    }
    Ok(rest.split_at(iv_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 12-byte IV Android Keystore actually produces.
    const IV: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    #[test]
    fn round_trips() {
        let framed = frame(&IV, b"ciphertext");
        let (iv, ct) = unframe(&framed).unwrap();
        assert_eq!(iv, IV);
        assert_eq!(ct, b"ciphertext");
    }

    #[test]
    fn round_trips_an_empty_ciphertext() {
        let framed = frame(&IV, b"");
        let (iv, ct) = unframe(&framed).unwrap();
        assert_eq!(iv, IV);
        assert!(ct.is_empty());
    }

    #[test]
    fn an_iv_of_another_length_still_splits_correctly() {
        // The point of framing the length rather than hardcoding 12.
        let framed = frame(&[9; 16], b"ct");
        let (iv, ct) = unframe(&framed).unwrap();
        assert_eq!(iv, [9; 16]);
        assert_eq!(ct, b"ct");
    }

    #[test]
    fn an_empty_blob_is_rejected() {
        assert!(unframe(&[]).is_err());
    }

    #[test]
    fn an_unknown_version_is_rejected_rather_than_guessed() {
        assert!(unframe(&[0x02, 12, 0, 0]).is_err());
    }

    #[test]
    fn a_blob_truncated_before_its_iv_length_is_rejected() {
        assert!(unframe(&[FRAME_VERSION]).is_err());
    }

    #[test]
    fn a_blob_truncated_inside_its_iv_is_rejected() {
        assert!(unframe(&[FRAME_VERSION, 12, 1, 2, 3]).is_err());
    }
}

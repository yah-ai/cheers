-- R962: username-less (discoverable) passkey sign-in.
--
-- The authenticator picks the credential, so the relying party learns which
-- row answered only from the assertion's credential id. Index it. The value is
-- the WebAuthn credential id, base64url without padding — exactly the string
-- webauthn-rs serialises at $.cred.cred_id, which is what the backfill copies
-- and what PasskeyCredentialStore impls write on every put
-- (cheers_server::passkey_material_credential_id).
--
-- Nullable only so the ALTER can run against existing rows; the backfill
-- fills every row a passkey_to_credential write produced.

ALTER TABLE passkey_credentials ADD COLUMN credential_id TEXT;

UPDATE passkey_credentials
SET credential_id = json_extract(material, '$.cred.cred_id');

CREATE UNIQUE INDEX passkey_credentials_credential_id
    ON passkey_credentials (credential_id);

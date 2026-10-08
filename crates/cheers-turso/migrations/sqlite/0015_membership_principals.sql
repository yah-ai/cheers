-- R734-F1: membership revocations name a principal, not a user.
--
-- A `membership` row's `subject` was a bare user id (`alice`). It is now the
-- principal's kind-prefixed wire form (`user:alice`, `key:<base64url>`), so a
-- Key principal (knock.md) can lose a membership like a user, and a user and a
-- key whose ids are the same string are different rows. Every existing row
-- named a user, so it gains the `user:` prefix. Readers parse the prefixed
-- form only; nothing reads the bare one.

UPDATE revocations SET subject = 'user:' || subject WHERE kind = 'membership';

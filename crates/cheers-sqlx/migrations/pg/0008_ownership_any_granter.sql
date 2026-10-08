-- D4 (operator 2026-10-06): granted_by is the writer's verified sub, of any
-- kind. 0002 declared the CHECK unnamed, so Postgres named it
-- `ownership_granted_by_check` (<table>_<column>_check).
--
-- Revocation now follows the holder (principal_id), served by
-- ix_ownership_principal; the on_behalf_of index backed the retired
-- on_behalf_of cascade and goes too.

ALTER TABLE ownership DROP CONSTRAINT ownership_granted_by_check;

DROP INDEX ix_ownership_on_behalf_of;

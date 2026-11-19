-- Additive only. The CLI version each active machine last called with, for
-- the operator's fleet view (scripts/fleet-versions.ts; docs/OPERATIONS.md,
-- Releasing the CLI step 7). Devices live in their workspace's object, which
-- D1 cannot read, so each object writes a machine's row here when its
-- `mehen/<x.y.z>` User-Agent first names a version or names a new one, and
-- deletes it when the machine is revoked (src/vault/areas/devices.ts); both
-- are best effort and never fail the machine's call. seen_at is when this
-- version was first seen. No name and no secret: the script joins workspaces
-- and managed_workspaces for slugs.

CREATE TABLE device_cli_versions (
  tenant TEXT NOT NULL,
  device TEXT NOT NULL,
  version TEXT NOT NULL,
  seen_at INTEGER NOT NULL,
  PRIMARY KEY (tenant, device)
);

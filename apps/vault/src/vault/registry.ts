// Every area of the TenantVault, in migration order. Adding an area is one
// line here; everything else about it lives in its own module.

import type { Area } from "./core.ts"
import { accessArea } from "./areas/access.ts"
import { adoptionsArea } from "./areas/adoptions.ts"
import { approvalsArea } from "./areas/approvals.ts"
import { devicesArea } from "./areas/devices.ts"
import { intakeArea } from "./areas/intake.ts"
import { itemsArea } from "./areas/items.ts"
import { oauthArea } from "./areas/oauth.ts"
import { policyArea } from "./areas/policy.ts"
import { pendingArea } from "./areas/pending.ts"
import { projectsArea } from "./areas/projects.ts"
import { relayArea } from "./areas/relay.ts"
import { runsArea } from "./areas/runs.ts"
import { tenantArea } from "./areas/tenant.ts"
import { managedArea } from "./areas/managed.ts"
import { vaultBackupArea } from "./areas/vault-backup.ts"
import { backupsArea } from "./areas/backups.ts"
import { browserArea } from "./areas/browser-workspace.ts"
import { pushesArea } from "./areas/pushes.ts"
import { mandatesArea } from "./areas/mandates-workspace.ts"

import { overridesArea, resolveOverride } from "./areas/overrides-workspace.ts"
import { settingsArea } from "./areas/settings-workspace.ts"
import { registerOverrideResolutionHook } from "./areas/runs-workspace.ts"

registerOverrideResolutionHook(resolveOverride)

export const AREAS: Area[] = [accessArea, tenantArea, devicesArea, itemsArea, intakeArea, adoptionsArea, oauthArea, relayArea, projectsArea, runsArea, approvalsArea, policyArea, pendingArea, overridesArea, settingsArea, managedArea]
// The operator's backup ops: system calls only and no tables, so their place
// in the order changes no migration.
AREAS.push(vaultBackupArea)
// Backup exports (layer 2): their own tables, appended after every area
// that shipped before them.
AREAS.push(backupsArea)
// Fill's rate limits and one-time codes, appended after backups.
AREAS.push(browserArea)
// Pushes into other services' secret stores: their own tables, after fill's.
AREAS.push(pushesArea)
// Mandates: what a machine may do without asking, signed in advance; their
// own tables, after pushes'.
AREAS.push(mandatesArea)

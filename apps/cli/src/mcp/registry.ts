import { vaultStatus } from "./vault-status.ts"
import { vaultDoctor } from "./vault-doctor.ts"
import { vaultTemplates } from "./vault-templates.ts"
import { vaultList } from "./vault-list.ts"
import { vaultShow } from "./vault-show.ts"
import { vaultCheck } from "./vault-check.ts"
import { vaultRequest } from "./vault-request.ts"
import { vaultConnect } from "./vault-connect.ts"
import { vaultFetch } from "./vault-fetch.ts"
import { vaultPlan } from "./vault-plan.ts"
import { vaultFill } from "./vault-fill.ts"
import { vaultPush } from "./vault-push.ts"
import { vaultEnv } from "./vault-env.ts"
import { vaultWait } from "./vault-wait.ts"
import { vaultPending } from "./vault-pending.ts"
import { vaultPolicy } from "./vault-policy.ts"
import { vaultMandate } from "./vault-mandate.ts"
import { vaultAdoptScan } from "./vault-adopt-scan.ts"
import { vaultAdoptStatus } from "./vault-adopt-status.ts"
import { vaultAskState } from "./vault-ask-state.ts"

export const TOOLS = [
  vaultStatus,
  vaultDoctor,
  vaultTemplates,
  vaultList,
  vaultShow,
  vaultCheck,
  vaultRequest,
  vaultConnect,
  vaultFetch,
  vaultPlan,
  vaultFill,
  vaultPush,
  vaultEnv,
  vaultWait,
  vaultPending,
  vaultPolicy,
  vaultMandate,
  vaultAdoptScan,
  vaultAdoptStatus,
]

// The tools only a card calls (MCP Apps visibility ["app"]): listed only to
// a host that negotiated MCP Apps, callable by any.
export const APP_TOOLS = [vaultAskState]

// Every route, by area. Order matters only where two patterns overlap,
// which they must not.

import type { Route } from "../router.ts"
import { adoptionsRoutes } from "./adoptions.ts"
import { backupRoutes } from "./backups.ts"
import { approvalsRoutes } from "./approvals.ts"
import { browserRoutes } from "./browser.ts"
import type { Handler } from "./context.ts"
import { itemsRoutes } from "./items.ts"
import { overridesDeviceRoutes } from "./overrides-workspace.ts"
import { oauthRoutes } from "./oauth.ts"
import { policyRoutes } from "./policy.ts"
import { mandateDeviceRoutes } from "./mandates.ts"
import { pendingRoutes } from "./pending.ts"
import { projectsRoutes } from "./projects.ts"
import { relayRoutes } from "./relay.ts"
import { pushRoutes } from "./push.ts"
import { systemRoutes } from "./system.ts"
import { uiRoutes } from "./ui.ts"
import { wellKnownRoutes } from "./well-known.ts"
import { workloadRoutes } from "./workloads.ts"

export const ROUTES: Route<Handler>[] = [
  ...systemRoutes,
  ...itemsRoutes,
  ...adoptionsRoutes,
  ...backupRoutes,
  ...relayRoutes,
  ...pushRoutes,
  ...browserRoutes,
  ...oauthRoutes,
  ...projectsRoutes,
  ...overridesDeviceRoutes,
  ...approvalsRoutes,
  ...pendingRoutes,
  ...workloadRoutes,
  ...policyRoutes,
  ...mandateDeviceRoutes,
  ...uiRoutes,
  ...wellKnownRoutes,
]

import type { PendingFixturePort } from "../pending-fixture-port.ts"
import { normaliseWorkspacePending, workspaceMachineNotices } from "../pending-workspace.ts"

export const pendingFixturePort = { normaliseWorkspacePending, workspaceMachineNotices } satisfies PendingFixturePort

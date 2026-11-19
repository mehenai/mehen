import type { Area } from "../core.ts"
import { workspacePendingOps } from "./pending-workspace.ts"

export const pendingArea: Area = { name: "pending",migrations: [],workspaceOps: workspacePendingOps }

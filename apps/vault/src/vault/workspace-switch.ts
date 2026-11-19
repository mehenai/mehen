// One reading of every per-workspace switch (POLICY_RULES, APPROVAL_BATCHES):
// "on" for every workspace, or a comma-separated list of workspace ids (tn_,
// never a slug, which a rename changes) for those alone, whitespace aside.
// "off", unset, or any other value, one bad entry included, is off for every
// workspace.
import { TENANT_ID } from "./client.ts"

export function workspaceSwitchOn(value: string | undefined, workspace: string): boolean {
  const trimmed = (value ?? "").trim()
  if (trimmed === "on") return true
  const listed = trimmed.split(",").map((id) => id.trim())
  return listed.every((id) => TENANT_ID.test(id)) && listed.includes(workspace)
}

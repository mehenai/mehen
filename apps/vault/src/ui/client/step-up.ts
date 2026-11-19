// The passkey step-up for workspace and account pages. A workspace action is
// signed through /api/w/<slug>/stepup/start, bound to that workspace; an
// account action (recovery codes, a passkey, a new workspace) through
// /api/account/stepup/start; a console change through its console's own.
// Never the legacy /api/stepup. The server
// rebuilds the action from its own state and refuses a proof for any other.

import type { StepUpProof } from "@mehen/protocol/api"
import type { WorkspaceStepUpAction } from "@mehen/protocol/workspace"
import { type PublicKeyCredentialRequestOptionsJSON, startAuthentication } from "@simplewebauthn/browser"
import { api, workspaceApi } from "./api.ts"
import type { ShellState } from "./shell-logic.ts"

// Inside the session's passkey grace window the vault answers `grace` and no
// options: the proof says so and no passkey is asked.
export type StepUpStarted = { nonce: string; options: PublicKeyCredentialRequestOptionsJSON } | { nonce: string; grace: { until: string } }

export const WORKSPACE_STEP_UP_PATH = "/stepup/start"
export const ACCOUNT_STEP_UP_PATH = "/api/account/stepup/start"

export async function stepUpProof(started: StepUpStarted, passkey: (options: PublicKeyCredentialRequestOptionsJSON) => Promise<unknown> = (options) => startAuthentication({ optionsJSON: options })): Promise<StepUpProof> {
  if ("grace" in started) return { nonce: started.nonce, grace: true }
  return { nonce: started.nonce, assertion: await passkey(started.options) }
}

export async function workspaceStepUp(shell: ShellState, action: WorkspaceStepUpAction): Promise<StepUpProof> {
  return stepUpProof(await workspaceApi<StepUpStarted>(shell, WORKSPACE_STEP_UP_PATH, { action }))
}

export async function accountStepUp(action: WorkspaceStepUpAction): Promise<StepUpProof> {
  return stepUpProof(await api<StepUpStarted>(ACCOUNT_STEP_UP_PATH, { action }))
}

// A console change (platform.operate or platform.administer), through the
// console's own step-up start: the operator's, or the admin's for one
// platform (CONSOLE_ROUTES in the protocol package).
export async function consoleStepUp(path: string, action: WorkspaceStepUpAction): Promise<StepUpProof> {
  return stepUpProof(await api<StepUpStarted>(path, { action }))
}

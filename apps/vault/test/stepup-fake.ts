export const FAKE_STEP_UP = { nonce: "test-nonce",assertion: "test-ok" } as const

// Workspace evidence names the verifying factor explicitly. This is invocation
// evidence for direct DO tests, not a second verifier or a passkey exemption.
export function workspaceStepUpEvidence(action: import("@mehen/protocol").WorkspaceStepUpAction, factor = "pk_fixture"): { action: import("@mehen/protocol").WorkspaceStepUpAction; factor: string } {
  return { action, factor }
}

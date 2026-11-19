// Every failure the CLI reports, from the vault or from this machine, as one
// shape: { error, message, next }, with the exit code from protocol's table.

import { type ApiError, type ApprovalStatus, type ErrorCode, EXIT, EXIT_FOR_ERROR, EXIT_FOR_LOCAL_ERROR, type ExitCode, type NextStep } from "@mehen/protocol/api"
import type { PolicyAreaRefusal, PolicyProposalStatus, PolicyRuleRefusal } from "@mehen/protocol/policy-mode"
import type { Ask } from "./ask.ts"
import { type CallContext, VaultApiError, VaultNetworkError } from "./vault-api.ts"

// Failures that start on this machine rather than in the vault.
export const LOCAL_EXIT = {
  usage: EXIT.usage,
  network: EXIT.transient,
  timeout: EXIT.human, // a human has not acted yet; wait again
  stale: EXIT.refused,
  superseded: EXIT.refused, // a newer ask from this machine to the same place replaced the approval
  denied: EXIT.refused, // an approval was denied
  rejected: EXIT.refused, // an enrolment was rejected
  mismatch: EXIT.human, // an OAuth connection signed in as the wrong account
  client_missing: EXIT.human, // mehen connect: no OAuth client exists yet; a human must add one
  expired: EXIT.error,
  cancelled: EXIT.error,
  failed: EXIT.error,
  upstream_status: EXIT.error, // mehen fetch --fail and a 4xx or 5xx upstream
  already_enrolled: EXIT.error,
  not_available: EXIT.error,
  helper_failed: EXIT.error,
  key_insecure: EXIT.identity,
  key_scope: EXIT.identity, // the key on disk was made for another vault
  command_failed: EXIT.error, // a mehen env call made through mehen mcp
  // mehen fill (browser/fill.ts): the browser, the page and the field.
  cdp_unreachable: EXIT.transient,
  page_changed: EXIT.transient,
  cdp_refused: EXIT.usage,
  target_ambiguous: EXIT.usage,
  field_ambiguous: EXIT.usage,
  field_not_found: EXIT.error,
  not_submitted: EXIT.error,
  field_kind_mismatch: EXIT.refused,
  field_hidden: EXIT.refused,
  frame_origin_mismatch: EXIT.refused,
  // Workspace selection on this machine (design 15.6): frozen in protocol's
  // LOCAL_ERROR_CODES, never sent by the vault, all exit 2.
  ...EXIT_FOR_LOCAL_ERROR,
} as const satisfies Record<string, ExitCode>

export type LocalErrorCode = keyof typeof LOCAL_EXIT
export type CliErrorCode = ErrorCode | LocalErrorCode

// `expiresAt` is read defensively: an older server does not send it.
// `ask` is attached by a command that already built one; otherwise the
// renderer synthesises it from the other fields (ask.ts, askForError).
// `context` is the failing call's own provenance (vault-api.ts CallContext),
// carried through the catch boundary so a synthesised ask is attributed to
// the call that actually failed. `group` is approval_required's
// review group as the vault sent it: it reaches output only on the ask,
// once askGroup has checked its link. `cleared` is mehen fill's: whether
// it emptied a field it had typed into before giving up.
export type ErrorExtras = Partial<ApprovalStatus | PolicyProposalStatus> & { kind?: "policy" | "approval"; id?: string } & Pick<ApiError, "approval" | "bindingCode" | "choices" | "retryAfter" | "providerStatus" | "mandate" | "mandateCover" | "mandateRefused"> & { expiresAt?: string; ask?: Ask; request?: MissingClientRequest; setup?: MissingClientSetup; context?: CallContext; ruleRefused?: PolicyRuleRefusal; areaRefused?: PolicyAreaRefusal; group?: unknown; bundle?: string; approvals?: { id: string; status: ApprovalStatus["status"] }[]; cleared?: boolean }

// Carried by client_missing: the exact `mehen request` / vault_request
// arguments for the client, and what the human needs at the provider.
export type MissingClientRequest = { kind: "oauth-client"; name: string; provider: string; reason: string }
export type MissingClientSetup = { redirectUri: string; docsUrl: string | null }

export class CliError extends Error {
  readonly code: CliErrorCode
  readonly next: NextStep | null
  readonly extras: ErrorExtras

  constructor(code: CliErrorCode, message: string, next?: NextStep | null, extras: ErrorExtras = {}) {
    super(message)
    this.code = code
    this.next = next ?? null
    this.extras = extras
  }
}

export function usageError(message: string, command = "mehen --help"): CliError {
  return new CliError("usage", message, { command, say: `Check the usage with \`${command}\`.` })
}

// mehen setup and mehen update act on the installed binary, which a run from
// source does not have.
export function installedBinaryRequired(command: "setup" | "update"): CliError {
  return new CliError("usage", `${command === "setup" ? "Setup" : "Update"} needs an installed standalone mehen binary. Install with https://mehen.dev/install first.`, {
    say: `Install mehen with \`curl -fsSL https://mehen.dev/install | sh\`, then run \`mehen ${command}\` with the installed binary.`,
  })
}

export function exitCodeFor(code: CliErrorCode): ExitCode {
  if (Object.hasOwn(LOCAL_EXIT, code)) return LOCAL_EXIT[code as LocalErrorCode]
  return EXIT_FOR_ERROR[code as ErrorCode] ?? EXIT.error
}

// The step for a vault refusal that came without one, so every error an
// agent sees names something to do. The vault's own `next` always wins:
// it knows the item, the link and the id; these only know the code.
export const DEFAULT_NEXT: Record<ErrorCode, NextStep> = {
  account_pending: { say: "Account security changes are pending. Ask the human to check their account security page." },
  owner_inactive: { say: "The machine owner is not active. Ask a workspace owner or admin to check their membership." },
  identity_required: { say: "The human must verify their Google identity in the workspace before continuing." },
  project_unshared: { say: "Ask the owner or a project manager to share the project with this machine's owner." },
  cli_outdated: { command: "mehen update", say: "This machine's mehen is older than the vault supports; update it, then run the command again." },
  workload_ended: { say: "This task's workload has ended. Stop; the program that started the task must create a new workload for it." },
  workload_required: { say: "This machine acts only through short-lived workloads. Make the request from a workload its harness created, not with the machine's own key." },
  platform_suspended: { say: "The platform this workspace belongs to is suspended. Stop and tell the human; only Mehen's operator can resume it." },
  quota_exceeded: { say: "This is past the platform's limit. Remove something you no longer need, or ask the platform to raise its limit." },
  origin_mismatch: { say: "This page is not one the credential may be typed into. Do not retry on another page; ask the human to add the page on the credential's page if it is right." },
  totp_unreadable: { say: "The one-time code secret cannot be read. Ask the human to enter it again as the base32 secret or the otpauth://totp link the site showed." },
  provider_refused: { say: "The provider refused the push and the message says why. Tell the human; pushing again changes nothing until the token's access, the destination or the name is fixed." },

  bad_request: { say: "Fix the request as the message says; `mehen <command> --help` shows the options." },
  ambiguous: { say: "Name one item by its slug; if you are not sure which account is meant, ask the human." },
  unauthenticated: { command: "mehen doctor", say: "The vault did not recognise this machine; `mehen doctor` says whether it is enrolled and what to do." },
  proof_invalid: { command: "mehen doctor", say: "The vault did not accept this machine's signature, often because the clock is more than 60 s off; `mehen doctor` checks the clock and the key." },
  device_revoked: { say: "This machine was revoked. Stop and tell the human; only they can let it enrol again." },
  device_pending: { command: "mehen pending", say: "This machine's enrolment has not been approved yet; relay its link to the owner (`mehen pending` shows it)." },
  intake_required: { command: "mehen request --help", say: "The credential does not exist yet; ask the human for it with `mehen request`." },
  needs_reauth: { say: "The credential no longer works; a human must reconnect or replace it in the vault. Tell them which one." },
  frozen: { say: "The vault is frozen. Stop and tell the human; they review the audit log and unfreeze it in the vault." },
  approval_required: { say: "This needs a human's approval in the vault; relay the link, wait for it, then repeat the same request." },
  forbidden: { command: "mehen status", say: "This machine is not allowed to do that. Tell the human; only they can widen its scope in the vault." },
  binding_refused: { say: "The vault will not send this credential there. Use a host and a plain URL from `mehen show <item>`; only a human can change where it may go." },
  surface_refused: { say: "Remove the placeholder from the body, query or header it is in; the vault injects the credential itself." },
  policy_denied: { say: "The item's policy refuses this. Do not work around it; tell the human what you tried, or use another route." },
  mode_refused: { say: "The vault will not use this credential that way. Use `mehen fetch` or `mehen run`, and keep a request that needs approval small and uncompressed." },
  environment_refused: { say: "That environment is protected or fenced. Use an unprotected one, or run with a literal --env <name> and expect an approval." },
  remote_mismatch: { say: "This checkout's origin remote is not the one bound to the project in mehen.toml. Check you are in the right clone." },
  refresh_retrying: { say: "The provider did not answer the vault's token refresh; retry shortly." },
  rate_limited: { say: "Too many requests; slow down and retry shortly." },
  upstream_failed: { say: "The vault could not get an answer from the upstream; retry later, and check whether the request took effect first." },
  not_found: { command: "mehen ls", say: "Check the name with `mehen ls`; ask for a missing credential with `mehen request`." },
  conflict: { command: "mehen pending", say: "This clashes with something that already exists or is already open; `mehen pending` lists this machine's open asks." },
  too_large: { say: "Send or ask for less: the vault caps requests and responses." },
  internal: { say: "Something broke inside the vault. Retry once; if it happens again, tell the human the time it happened." },
}

export function toCliError(error: unknown): CliError {
  if (error instanceof CliError) return error
  if (error instanceof VaultApiError) {
    const { approval, bindingCode, choices, retryAfter, providerStatus, group, mandateCover, mandateRefused } = error.body
    const { expiresAt } = error.body as { expiresAt?: unknown }
    const extras: ErrorExtras = {
      ...(approval ? { approval } : {}),
      ...(bindingCode ? { bindingCode } : {}),
      ...(choices ? { choices } : {}),
      ...(retryAfter !== undefined ? { retryAfter } : {}),
      ...(providerStatus !== undefined ? { providerStatus } : {}),
      ...(typeof expiresAt === "string" ? { expiresAt } : {}),
      ...(error.body.error === "approval_required" && group !== undefined ? { group } : {}),
      ...(error.body.error === "approval_required" && mandateCover !== undefined ? { mandateCover } : {}),
      ...(error.body.error === "forbidden" && mandateRefused !== undefined ? { mandateRefused } : {}),
      ...(error.context ? { context: error.context } : {}),
    }
    return new CliError(error.body.error, error.body.message, error.body.next ?? DEFAULT_NEXT[error.body.error] ?? null, extras)
  }
  if (error instanceof VaultNetworkError) {
    return new CliError("network", error.message, { say: "Check the network connection and the vault URL (MEHEN_VAULT_URL), then retry." })
  }
  const message = error instanceof Error ? error.message : String(error)
  return new CliError("internal", `Unexpected failure in mehen: ${message}`, { command: "mehen doctor", say: "Something broke inside mehen. `mehen doctor` checks this machine; if it passes, tell the human what you ran." })
}

export type ErrorBody = { error: CliErrorCode; message: string; next: NextStep | null } & ErrorExtras

// The --json and MCP body. An attached ask is included; a synthesised one is
// added by the caller (output.ts reportError, or the MCP server) when it has
// the environment to name who asked.
export function errorBody(error: CliError): ErrorBody {
  const { context: _call, group: _group, ...extras } = error.extras
  return { error: error.code, message: error.message, next: error.next, ...extras }
}

// An MCP tool call as text: `vault_wait { "id": "apr_1" }`, or the bare name.
export function toolCallText(tool: string, args?: Record<string, unknown>): string {
  if (args === undefined) return tool
  return `${tool} { ${Object.entries(args).map(([k, v]) => `${JSON.stringify(k)}: ${JSON.stringify(v)}`).join(", ")} }`
}

// The next step as readable lines, for stderr and MCP text content.
export function describeNext(next: NextStep | null): string[] {
  if (!next) return []
  const lines = [`next: ${next.say}`]
  if (next.url) lines.push(`  open: ${next.url}`)
  if (next.tool) lines.push(`  call: ${toolCallText(next.tool, next.arguments)}`)
  if (next.command) lines.push(`  run:  ${next.command}`)
  return lines
}

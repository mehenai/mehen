import type { PlatformVault } from "./platform/platform-vault.ts"
import type { WorkspaceVault } from "./vault/workspace-vault.ts"

export type Env = {
  TENANT_VAULT: DurableObjectNamespace<WorkspaceVault>
  // One object per platform, named by its plt_ id (platform/platform-vault.ts).
  PLATFORM_VAULT: DurableObjectNamespace<PlatformVault>
  DB: D1Database
  // ws/<tenant>/<yyyy-mm-dd>.bin, each workspace object's daily dump sealed
  // under its root-derived backup key (vault/areas/vault-backup.ts).
  VAULT_BACKUPS: R2Bucket
  ASSETS?: Fetcher
  RATE_LIMITER?: RateLimit
  AUTH_RATE_LIMITER?: RateLimit
  // Signed traffic is limited by the identity its proof claims, behind a
  // much higher limit per address (rate-limits.ts): many platforms' and
  // agents' calls can share one address.
  PLATFORM_IP_RATE_LIMITER?: RateLimit
  DEVICE_IP_RATE_LIMITER?: RateLimit
  DEVICE_RATE_LIMITER?: RateLimit
  // https://app.mehen.dev; every URL the vault prints starts with it.
  VAULT_ORIGIN: string
  RP_ID: string
  // Comma-separated Apple app ids (team id and bundle id) that may run
  // passkey ceremonies for RP_ID; unset serves no apple-app-site-association.
  APPLE_WEBCREDENTIAL_APPS?: string
  GOOGLE_SIGNIN_CLIENT_ID?: string
  GOOGLE_SIGNIN_CLIENT_SECRET?: string
  // Cloudflare Email Sending (a send_email binding): the six-digit codes
  // that prove an invited email (directory/email-proof.ts), sent from
  // EMAIL_FROM, "Name <address>" on a domain onboarded to Email Sending.
  // Unbound, the page offers only Google.
  EMAIL?: SendEmail
  EMAIL_FROM?: string
  // The /v1 version seam (cli-version.ts): an identified mehen below the
  // minimum is refused cli_outdated; both are advertised in Mehen-Cli.
  // CLI_RECOMMENDED_VERSION is a floor: the published release, when it
  // verifies and is higher, is advertised instead.
  CLI_MINIMUM_VERSION?: string
  CLI_RECOMMENDED_VERSION?: string
  // The mehen-web Worker, which serves https://mehen.dev/dl/latest.json:
  // read-only, for the published release (published-release.ts). Bound in
  // production only; unbound, the floor is advertised.
  RELEASES_WEB?: Fetcher
  // Whether an account the operator has not decided on may create
  // workspaces: "accounts" (yes) or "operator" (only after
  // allow-workspaces). Anything else, or unset, is "operator"
  // (directory/workspace-creation.ts).
  // The ceiling on the workspace_creation setting too
  // (directory/deployment-settings.ts).
  WORKSPACE_CREATION?: string
  // The widest sign-up mode the operators may set: "invite", "request" or
  // "open". Anything else, or unset, is "invite". Stored and shown only:
  // sign-up is by invitation whatever the setting says.
  SIGNUP_MODE_MAX?: string
  // Standing policy rules (areas/policy-rules-workspace.ts policyRulesOn):
  // "on" for every workspace, or a comma-separated list of workspace ids
  // (tn_) for those alone. "off", anything else, or unset, is off for every
  // workspace: no rule is offered, made or used.
  POLICY_RULES?: string
  // Batch approvals (areas/approvals-workspace.ts approvalBatchesOn), in
  // POLICY_RULES's form: asks record their review group, shape and floor,
  // and a machine may replace its own open ask. Off: none of it.
  APPROVAL_BATCHES?: string
  // Pushes into other services' secret stores (areas/push-allowance.ts
  // pushesOn), in POLICY_RULES's form. Off: no push is asked, sent or allowed.
  PUSH?: string
  // Fill (fill-unavailable.ts browserFillOn), in POLICY_RULES's form: an
  // item's fill ceiling and pages, fill in a machine's or workload's modes,
  // and POST /v1/fill. Off: every one is refused.
  BROWSER_FILL?: string
  // How careful a credential is (areas/postures-workspace.ts posturesOn), in
  // POLICY_RULES's form: a credential's posture may be set, the relay lets
  // what it covers through, and the home counts asks for its nudge. Off:
  // every credential asks as its policy says.
  POLICY_POSTURES?: string
  // Passkey grace (directory/workspace-stepup.ts stepUpGraceOn): "on" lets a
  // browser session confirm further actions for 15 minutes after a real
  // passkey confirmation without asking again. Per account, not per
  // workspace. Anything else, or unset, is off: no window is opened, offered
  // or accepted.
  STEPUP_GRACE?: string
  // Mandates (areas/mandates-workspace.ts mandatesOn), in POLICY_RULES's
  // form: a member may sign that one of their machines carries on without
  // asking, and the relay lets what it covers through. Off: no mandate covers
  // anything and the mandate routes answer as if they did not exist.
  MANDATES?: string
  // The approval dial (areas/approval-dial-workspace.ts approvalDialOn), in
  // POLICY_RULES's form: an owner or admin may choose how often Mehen asks,
  // and Let it work lets through what posture trust would. Off: the dial
  // cannot be changed and every workspace reads as Ask on writes.
  APPROVAL_DIAL?: string
  // Secrets.
  // JSON map of root key version to base64url of 32 random bytes. The
  // highest version encrypts; older ones only decrypt until rewrapped.
  ROOT_KEYS: string
  // ECDH P-256 private JWK that browsers and the CLI seal secrets to.
  SEAL_PRIVATE_JWK: string
  // One-time code that lets the first account sign up. Remove after use.
  BOOTSTRAP_CODE?: string
}

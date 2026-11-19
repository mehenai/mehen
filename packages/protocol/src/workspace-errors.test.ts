import { expect, test } from "bun:test"
import { ERROR_CODES, EXIT, EXIT_FOR_ERROR, HTTP_STATUS_FOR_ERROR, LOCAL_ERROR_CODES, EXIT_FOR_LOCAL_ERROR, apiErrorExtrasValid } from "./api.ts"
const legacy = {
  "bad_request": [
    400,
    "usage"
  ],
  "ambiguous": [
    409,
    "usage"
  ],
  "unauthenticated": [
    401,
    "identity"
  ],
  "proof_invalid": [
    401,
    "identity"
  ],
  "device_revoked": [
    403,
    "identity"
  ],
  "device_pending": [
    403,
    "human"
  ],
  "intake_required": [
    404,
    "human"
  ],
  "needs_reauth": [
    424,
    "human"
  ],
  "frozen": [
    423,
    "human"
  ],
  "approval_required": [
    409,
    "approval"
  ],
  "forbidden": [
    403,
    "refused"
  ],
  "binding_refused": [
    403,
    "refused"
  ],
  "surface_refused": [
    403,
    "refused"
  ],
  "policy_denied": [
    403,
    "refused"
  ],
  "mode_refused": [
    403,
    "refused"
  ],
  "environment_refused": [
    403,
    "refused"
  ],
  "remote_mismatch": [
    403,
    "refused"
  ],
  "refresh_retrying": [
    503,
    "transient"
  ],
  "rate_limited": [
    429,
    "transient"
  ],
  "upstream_failed": [
    502,
    "transient"
  ],
  "not_found": [
    404,
    "error"
  ],
  "conflict": [
    409,
    "error"
  ],
  "too_large": [
    413,
    "error"
  ],
  "internal": [
    500,
    "error"
  ]
} as const
test("all legacy HTTP and exit codes stay byte-for-byte stable", () => {
 for (const [code, [status, exit]] of Object.entries(legacy)) {
  expect(HTTP_STATUS_FOR_ERROR[code as keyof typeof legacy]).toBe(status)
  expect(EXIT_FOR_ERROR[code as keyof typeof legacy]).toBe(EXIT[exit])
 }
 expect(Object.keys(HTTP_STATUS_FOR_ERROR).sort()).toEqual([...ERROR_CODES].sort())
 expect(Object.keys(EXIT_FOR_ERROR).sort()).toEqual([...ERROR_CODES].sort())
 for (const local of LOCAL_ERROR_CODES) { expect((ERROR_CODES as readonly string[]).includes(local)).toBe(false); expect(EXIT_FOR_LOCAL_ERROR[local]).toBe(2) }
 for (const code of ["account_pending", "owner_inactive", "identity_required", "project_unshared"] as const) { expect(HTTP_STATUS_FOR_ERROR[code]).toBe(403); expect(EXIT_FOR_ERROR[code]).toBe(4) }
})
test("cli_outdated is a vault code: HTTP 426, exit 1", () => {
 expect(ERROR_CODES).toContain("cli_outdated")
 expect(HTTP_STATUS_FOR_ERROR.cli_outdated).toBe(426)
 expect(EXIT_FOR_ERROR.cli_outdated).toBe(EXIT.error)
})
test("the local selection codes, in order, all exit 2 and none is a vault code", () => {
 expect(LOCAL_ERROR_CODES).toEqual(["pin_outdated", "workspace_unbound", "workspace_mismatch", "workspace_unknown", "context_ambiguous", "workspace_not_allowed", "config_dir_retired"])
 expect(Object.keys(EXIT_FOR_LOCAL_ERROR).sort()).toEqual([...LOCAL_ERROR_CODES].sort())
 for (const local of LOCAL_ERROR_CODES) { expect((ERROR_CODES as readonly string[]).includes(local)).toBe(false); expect(EXIT_FOR_LOCAL_ERROR[local]).toBe(EXIT.usage) }
})
test("provider_refused is a vault code: HTTP 502, exit 5, and only it carries providerStatus", () => {
 expect(ERROR_CODES).toContain("provider_refused")
 expect(HTTP_STATUS_FOR_ERROR.provider_refused).toBe(502)
 expect(EXIT_FOR_ERROR.provider_refused).toBe(EXIT.refused)
 expect(apiErrorExtrasValid({ error: "provider_refused", message: "GitHub refused it.", providerStatus: 403 })).toBe(true)
 expect(apiErrorExtrasValid({ error: "upstream_failed", message: "GitHub did not answer.", providerStatus: 503 })).toBe(false)
})

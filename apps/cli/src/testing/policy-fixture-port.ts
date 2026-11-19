import type { PolicyFixturePort } from "../policy-fixture-port.ts"
import { proposePolicy, showPolicy, stopPolicy } from "../policy-operations.ts"
import { waitFor } from "../operations.ts"
import { waitOutput } from "../commands/intake.ts"
import { errorJson } from "../output.ts"
import { exitCodeFor, toCliError } from "../errors.ts"
import { VaultApiError } from "../vault-api.ts"

// This binding is typechecked by the CLI, not by the Workers compiler.
export const policyFixturePort = {
  proposePolicy,
  showPolicy,
  stopPolicy,
  async waitJson(api, id) { return waitOutput(id, await waitFor(api, id, { timeoutMs: 0, intervalMs: 0 })) },
  failureJson(error, vaultUrl) {
    const failure = toCliError(error)
    return { value: errorJson(failure, { env: { MEHEN_SESSION: "pol-test" }, vaultUrl }), exit: exitCodeFor(failure.code) }
  },
  apiError: VaultApiError,
} satisfies PolicyFixturePort

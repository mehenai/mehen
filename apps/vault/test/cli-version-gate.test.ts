// The /v1 version seam: an identified mehen below
// the minimum is refused 426 cli_outdated before any route runs, enrolment
// and renewal included; freeze and self-revoke pass at any version; an
// absent or non-mehen User-Agent passes by policy; every /v1 response, and
// only /v1, carries Mehen-Cli.

import { describe, expect, it } from "vitest"
import { clientLabel } from "../src/directory/session.ts"
import { cliVersionOf, connectCodesOffered } from "../src/cli-version.ts"
import { fetchWorkspaceWorker } from "./helpers.ts"
import { createWorkspaceFixture } from "./workspace-fixtures.ts"

const OLD = "mehen/0.2.0 (darwin-arm64; release)"
const CURRENT = "mehen/0.3.0 (linux-x64; release)"
const REFUSAL = { error: "cli_outdated", message: "This machine's mehen 0.2.0 is older than the vault supports (0.3.0).", next: { command: "mehen update --json", say: "Update mehen on this machine, then run the command again." } }

async function setup(vars: { CLI_MINIMUM_VERSION?: string; CLI_RECOMMENDED_VERSION?: string } = { CLI_MINIMUM_VERSION: "0.3.0", CLI_RECOMMENDED_VERSION: "0.3.1" }) {
  const f = await createWorkspaceFixture()
  const env = { ...f.env, ...vars }
  const send = (method: string, path: string, userAgent: string | null, body?: string) => fetchWorkspaceWorker(env, path, { method, headers: userAgent === null ? {} : { "user-agent": userAgent }, ...(body === undefined ? {} : { body }) })
  return { f, env, send }
}

describe("the /v1 version gate", () => {
  it("refuses an identified mehen below the minimum with 426 and the exact body, on device routes and every enrolment route, before anything runs", async () => {
    const { f, send } = await setup()
    const before = await f.env.DB.prepare("SELECT COUNT(*) AS n FROM enrolments").first<{ n: number }>()
    for (const [method, path, body] of [["GET", "/v1/me"], ["GET", "/v1/pending"], ["POST", "/v1/relay", "{}"], ["POST", "/v1/enrol", "{}"], ["GET", "/v1/enrol/enr_abcdefghijklmnop"], ["POST", "/v1/enrol/enr_abcdefghijklmnop/renew", ""]] as const) {
      const response = await send(method, path, OLD, body)
      expect(response.status, `${method} ${path}`).toBe(426)
      expect(response.headers.get("Mehen-Error")).toBe("1")
      expect(response.headers.get("Mehen-Cli")).toBe("minimum=0.3.0; recommended=0.3.1")
      expect(await response.json()).toEqual(REFUSAL)
    }
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM enrolments").first<{ n: number }>()).toEqual(before)
  })

  it("never blocks freeze or self-revoke, whatever the version", async () => {
    const { send } = await setup()
    for (const path of ["/v1/freeze", "/v1/devices/self/revoke"]) {
      const response = await send("POST", path, "mehen/0.0.1 (linux-x64; release)", "")
      expect(response.status).not.toBe(426)
      expect(((await response.json()) as { error?: string }).error).not.toBe("cli_outdated")
      expect(response.headers.get("Mehen-Cli")).toBe("minimum=0.3.0; recommended=0.3.1")
    }
    // Only the exact method and path are exempt.
    expect((await send("GET", "/v1/freeze", OLD)).status).toBe(426)
    expect((await send("POST", "/v1/freeze/", OLD, "")).status).toBe(426)
  })

  it("passes an absent User-Agent, Bun's (0.2.0 sends it), a browser's, and a mehen at or above the minimum", async () => {
    const { send } = await setup()
    for (const agent of [null, "Bun/1.4.2", "Mozilla/5.0 (Macintosh) Version/18.0 Safari/605.1", CURRENT, "mehen/0.3.0", "mehen/1.0.0 (darwin-arm64; dev)", "xmehen/0.0.1", "mehen/0.2"]) {
      const response = await send("GET", "/v1/me", agent)
      expect(response.status, String(agent)).toBe(401)
      expect(((await response.json()) as { error: string }).error).toBe("unauthenticated")
    }
  })

  it("carries Mehen-Cli on every /v1 response, success or error, and nowhere else", async () => {
    const { send } = await setup({ CLI_MINIMUM_VERSION: "0.2.0", CLI_RECOMMENDED_VERSION: undefined })
    const unknown = await send("GET", "/v1/no-such-route", CURRENT)
    expect(unknown.status).toBe(404)
    expect(unknown.headers.get("Mehen-Cli")).toBe("minimum=0.2.0")
    expect((await send("GET", "/v1/me", null)).headers.get("Mehen-Cli")).toBe("minimum=0.2.0")
    for (const path of ["/api/needs-you", "/app/v1/pending", "/signin", "/healthz"]) expect((await send("GET", path, CURRENT)).headers.has("Mehen-Cli"), path).toBe(false)
  })

  it("an unset or malformed minimum switches the gate and the advice off", async () => {
    for (const vars of [{ CLI_MINIMUM_VERSION: undefined }, { CLI_MINIMUM_VERSION: "latest" }, { CLI_MINIMUM_VERSION: "0.3" }]) {
      const { send } = await setup(vars)
      const response = await send("GET", "/v1/me", "mehen/0.0.1 (linux-x64; release)")
      expect(response.status).toBe(401)
      expect(response.headers.has("Mehen-Cli")).toBe(false)
    }
  })
})

describe("the mehen User-Agent", () => {
  it("is read as digits and dots only, and labelled mehen <version> on its platform", () => {
    expect(cliVersionOf(OLD)).toBe("0.2.0")
    expect(cliVersionOf("mehen/0.2.0.1")).toBeNull()
    expect(cliVersionOf("mehen/99999999.0.0")).toBeNull()
    expect(cliVersionOf("Bun/1.4.2")).toBeNull()
    expect(clientLabel(OLD)).toBe("mehen 0.2.0 on macOS")
    expect(clientLabel(CURRENT)).toBe("mehen 0.3.0 on Linux")
    expect(clientLabel("mehen/0.3.0")).toBe("mehen 0.3.0")
    expect(clientLabel("mehen/0.3.0 (<script>-x)")).toBe("mehen 0.3.0")
    expect(clientLabel("Mozilla/5.0 (Macintosh) Version/18.0 Safari/605.1")).toBe("Safari on Mac")
  })

  it("names the client library and its host's product token, never as a browser, and never gates it as the CLI", () => {
    expect(clientLabel("mehen-client/0.1.0")).toBe("mehen-client 0.1.0")
    expect(clientLabel("mehen-client/0.1.0 globex/2.4.1")).toBe("mehen-client 0.1.0 (globex/2.4.1)")
    expect(clientLabel("mehen-client/0.1.0 globex-broker/2026.10.29+abc")).toBe("mehen-client 0.1.0 (globex-broker/2026.10.29+abc)")
    expect(clientLabel(`mehen-client/0.1.0 globex/${"9".repeat(80)}`)).toBe(`mehen-client 0.1.0 (globex/${"9".repeat(33)})`)
    for (const hostile of ["mehen-client/0.1.0 <script>/1", "mehen-client/0.1.0 globex/2\u202E1", "mehen-client/0.1.0 globex", "mehen-client/0.1.0 /1.0", "mehen-client/0.1.0 globex/"]) expect(clientLabel(hostile), hostile).toBe("mehen-client 0.1.0")
    expect(clientLabel("mehen-client/0.1")).toBe("A browser")
    expect(clientLabel("mehen-client/0.1.0.9")).toBe("A browser")
    expect(cliVersionOf("mehen-client/0.1.0 globex/2.4.1")).toBeNull()
    expect(cliVersionOf("mehen-client/0.0.1")).toBeNull()
  })
})

// `mehen enrol --connect` is a 0.3.0 flag: the issuer answers only once the
// deployment recommends 0.3.0, so a 0.2.0 machine is never handed a command
// it cannot run.
describe("connect codes follow the recommended CLI", () => {
  it("are offered only when CLI_RECOMMENDED_VERSION is at least 0.3.0", () => {
    const env = (vars: Record<string, string | undefined>) => vars as unknown as Parameters<typeof connectCodesOffered>[0]
    expect(connectCodesOffered(env({}))).toBe(false)
    expect(connectCodesOffered(env({ CLI_RECOMMENDED_VERSION: "0.2.9" }))).toBe(false)
    expect(connectCodesOffered(env({ CLI_RECOMMENDED_VERSION: "not a version" }))).toBe(false)
    expect(connectCodesOffered(env({ CLI_RECOMMENDED_VERSION: "0.3.0" }))).toBe(true)
    expect(connectCodesOffered(env({ CLI_RECOMMENDED_VERSION: "1.0.0" }))).toBe(true)
  })
})

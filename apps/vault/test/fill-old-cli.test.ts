// Ruling F2 (src/vault/fill-old-cli.ts): a mehen below 0.3.17 fails to
// parse a mode list holding fill, and after following an enrolment it then
// revokes its own machine. A real workspace, so in a file of its own: the
// access fixtures register state providers that would replace its own.

import { describe, expect, it } from "vitest"
import { createProof, webCryptoSigner, type WorkloadView, type WorkspaceDeviceScope } from "@mehen/protocol"
import { cliReadsFill } from "../src/vault/fill-old-cli.ts"
import { newDeviceKey, publicJwk } from "./devices.ts"
import { ORIGIN } from "./helpers.ts"
import { acceptedScope, body, workJourney } from "./e2e/workspace-journey.ts"

describe("fill and a CLI below 0.3.17", () => {
  it("reads fill from 0.3.17 on, and never from an unknown or unreadable version", () => {
    for (const version of ["0.3.17", "0.3.19", "0.4.0", "1.0.0"]) expect({ version, reads: cliReadsFill(version) }).toEqual({ version, reads: true })
    for (const version of [null, undefined, "", "0.3.16", "0.3.17-rc.1", "0.2.9", "not-a-version"]) expect({ version, reads: cliReadsFill(version) }).toEqual({ version, reads: false })
  })

  it("leaves fill out of /v1/me, the enrolment status and every workload answer to a CLI below 0.3.17 or of unknown version", async () => {
    const f = await workJourney()
    const start = await f.startMachine(f.work)
    await body(await f.acceptMachine(f.alex, f.work, start))
    const enrolment = start.started.enrolment
    const active = await body<{ device: string }>(await f.deviceCall({ keys: start.keys, device: enrolment, workspace: f.work }, `/v1/enrol/${enrolment}`, undefined, "enrol"))
    const machine = { keys: start.keys, device: active.device, workspace: f.work }
    const workloadKeys = await newDeviceKey()
    const workload = await body<WorkloadView>(await f.deviceCall(machine, "/v1/workloads", { label: "browser-task", jwk: await publicJwk(workloadKeys), scope: { modes: ["relay"] } }), 201)
    // Fill as a rescope will give it once fill ships: the device, its
    // enrolment's copy and the workload all hold it, after the other modes.
    const usual = acceptedScope().modes
    const scope = (await f.sql<{ scope: string }>(f.work, "SELECT scope FROM devices WHERE id=?", machine.device))[0]!.scope
    await f.sql(f.work, "UPDATE devices SET scope=? WHERE id=?", JSON.stringify({ ...JSON.parse(scope), modes: [...usual, "fill"] }), machine.device)
    await f.sql(f.work, "UPDATE workloads SET scope=? WHERE id=?", JSON.stringify({ modes: ["relay", "fill"] }), workload.workload)
    const enrolled = await f.db.prepare("SELECT scope FROM enrolments WHERE id=?").bind(enrolment).first<{ scope: string }>()
    await f.db.prepare("UPDATE enrolments SET scope=? WHERE id=?").bind(JSON.stringify({ ...JSON.parse(enrolled!.scope), modes: [...usual, "fill"] }), enrolment).run()
    const call = async (path: string, userAgent: string | null, options: { method?: string; tenant?: string; id?: string; keys?: CryptoKeyPair; workload?: string } = {}) => {
      const method = options.method ?? "GET"
      const proof = await createProof(webCryptoSigner(options.id ?? machine.device, (options.keys ?? machine.keys).privateKey, options.workload), { method, url: `${ORIGIN}${path}`, body: method === "POST" ? "{}" : null }, { tenant: options.tenant ?? f.work.id })
      return f.request(path, undefined, method === "POST" ? {} : undefined, { "Mehen-Proof": proof, ...(userAgent === null ? {} : { "user-agent": userAgent }) }, method)
    }
    for (const [userAgent, reads] of [[null, false], ["Bun/1.2.0", false], ["mehen/0.3.16 (darwin arm64)", false], ["mehen/0.3.17 (darwin arm64)", true], ["mehen/0.4.0", true]] as const) {
      const modes = reads ? [...usual, "fill"] : usual
      const workloadModes = reads ? ["relay", "fill"] : ["relay"]
      const at = String(userAgent)
      expect({ at, modes: (await body<{ scope: WorkspaceDeviceScope }>(await call("/v1/me", userAgent))).scope.modes }).toEqual({ at, modes })
      const asWorkload = await body<{ scope: WorkspaceDeviceScope; workload: WorkloadView }>(await call("/v1/me", userAgent, { keys: workloadKeys, workload: workload.workload }))
      expect({ at, modes: asWorkload.scope.modes, workload: asWorkload.workload.scope.modes }).toEqual({ at, modes, workload: workloadModes })
      expect({ at, modes: (await body<{ scope: WorkspaceDeviceScope }>(await call(`/v1/enrol/${enrolment}`, userAgent, { tenant: "enrol", id: enrolment }))).scope.modes }).toEqual({ at, modes })
      expect({ at, modes: (await body<{ workloads: WorkloadView[] }>(await call("/v1/workloads", userAgent))).workloads.map((w) => w.scope.modes) }).toEqual({ at, modes: [workloadModes] })
      expect({ at, modes: (await body<WorkloadView>(await call(`/v1/workloads/${workload.workload}`, userAgent))).scope.modes }).toEqual({ at, modes: workloadModes })
      expect({ at, modes: (await body<WorkloadView>(await call(`/v1/workloads/${workload.workload}/renew`, userAgent, { method: "POST" }))).scope.modes }).toEqual({ at, modes: workloadModes })
    }
    // Revoking answers the same way, and the stored scopes keep fill.
    expect((await body<WorkloadView>(await call(`/v1/workloads/${workload.workload}`, "mehen/0.3.16", { method: "DELETE" }))).scope.modes).toEqual(["relay"])
    expect((await f.sql<{ scope: string }>(f.work, "SELECT scope FROM workloads WHERE id=?", workload.workload)).map((w) => JSON.parse(w.scope).modes)).toEqual([["relay", "fill"]])
    expect(JSON.parse((await f.sql<{ scope: string }>(f.work, "SELECT scope FROM devices WHERE id=?", machine.device))[0]!.scope).modes).toEqual([...usual, "fill"])
  })

  it("never answers a fill-only workload to a CLI below 0.3.17 or of unknown version, and makes none for it", async () => {
    const f = await workJourney()
    const start = await f.startMachine(f.work)
    await body(await f.acceptMachine(f.alex, f.work, start))
    const active = await body<{ device: string }>(await f.deviceCall({ keys: start.keys, device: start.started.enrolment, workspace: f.work }, `/v1/enrol/${start.started.enrolment}`, undefined, "enrol"))
    const machine = { keys: start.keys, device: active.device, workspace: f.work }
    const scope = (await f.sql<{ scope: string }>(f.work, "SELECT scope FROM devices WHERE id=?", machine.device))[0]!.scope
    await f.sql(f.work, "UPDATE devices SET scope=? WHERE id=?", JSON.stringify({ ...JSON.parse(scope), modes: [...acceptedScope().modes, "fill"] }), machine.device)
    const name = (await f.sql<{ name: string }>(f.work, "SELECT name FROM devices WHERE id=?", machine.device))[0]!.name
    const send = async (path: string, userAgent: string | null, options: { method?: string; input?: unknown; keys?: CryptoKeyPair; workload?: string } = {}) => {
      const method = options.method ?? (options.input === undefined ? "GET" : "POST"), encoded = options.input === undefined ? null : JSON.stringify(options.input)
      const proof = await createProof(webCryptoSigner(machine.device, (options.keys ?? machine.keys).privateKey, options.workload), { method, url: `${ORIGIN}${path}`, body: encoded }, { tenant: f.work.id })
      return f.request(path, undefined, options.input, { "Mehen-Proof": proof, ...(userAgent === null ? {} : { "user-agent": userAgent }) }, method)
    }
    const fillKeys = await newDeviceKey()
    const created = await body<WorkloadView>(await send("/v1/workloads", "mehen/0.3.17 (darwin arm64)", { input: { label: "sign-in", jwk: await publicJwk(fillKeys), scope: { modes: ["fill"] } } }), 201)
    expect(created.scope.modes).toEqual(["fill"])
    const stored = async () => f.sql<{ id: string; expires_at: number; revoked_at: number | null }>(f.work, "SELECT id,expires_at,revoked_at FROM workloads ORDER BY id")
    const kept = await stored()
    const unknownId = "wl_nosuchworkload"
    for (const [userAgent, runs] of [["mehen/0.3.16 (darwin arm64)", "runs mehen 0.3.16"], ["Bun/1.2.0", "runs an unknown version of mehen"], [null, "runs an unknown version of mehen"]] as const) {
      const at = String(userAgent)
      // The machine last proved 0.3.17, so only the caller's own mehen is judged.
      await f.sql(f.work, "UPDATE devices SET last_cli_version='0.3.17' WHERE id=?", machine.device)
      const refused = await send("/v1/workloads", userAgent, { input: { label: "sign-in", jwk: await publicJwk(await newDeviceKey()), scope: { modes: ["fill"] } } })
      expect({ at, status: refused.status, body: await refused.json() }).toEqual({ at, status: 403, body: { error: "mode_refused", message: `${name} ${runs}; typing into web pages needs 0.3.17 or later.`, next: { say: "Update mehen on that machine first, then allow it again." } } })
      expect({ at, listed: (await body<{ workloads: WorkloadView[] }>(await send("/v1/workloads", userAgent))).workloads }).toEqual({ at, listed: [] })
      for (const [suffix, method] of [["", "GET"], ["/renew", "POST"], ["", "DELETE"]] as const) {
        const options = method === "POST" ? { method, input: {} } : { method }
        const unknown = await send(`/v1/workloads/${unknownId}${suffix}`, userAgent, options)
        const hidden = await send(`/v1/workloads/${created.workload}${suffix}`, userAgent, options)
        expect({ at, method, status: hidden.status, body: await hidden.json() }).toEqual({ at, method, status: unknown.status, body: await unknown.json() })
        expect(hidden.status).toBe(404)
      }
      const me = await send("/v1/me", userAgent, { keys: fillKeys, workload: created.workload })
      expect({ at, status: me.status, body: await me.json() }).toEqual({ at, status: 403, body: { error: "mode_refused", message: "This workload only types into web pages, which needs mehen 0.3.17 or later.", next: { say: "Update mehen on this machine, then try again." } } })
      expect({ at, stored: await stored() }).toEqual({ at, stored: kept })
    }
    // From 0.3.17 it is there to see, renew and revoke.
    const current = "mehen/0.3.17 (darwin arm64)"
    expect((await body<{ workloads: WorkloadView[] }>(await send("/v1/workloads", current))).workloads.map((w) => [w.workload, w.scope.modes])).toEqual([[created.workload, ["fill"]]])
    expect((await body<WorkloadView>(await send(`/v1/workloads/${created.workload}`, current))).scope.modes).toEqual(["fill"])
    expect((await body<{ workload: WorkloadView }>(await send("/v1/me", current, { keys: fillKeys, workload: created.workload }))).workload.scope.modes).toEqual(["fill"])
    expect((await body<WorkloadView>(await send(`/v1/workloads/${created.workload}/renew`, current, { input: {} }))).scope.modes).toEqual(["fill"])
    expect((await body<WorkloadView>(await send(`/v1/workloads/${created.workload}`, current, { method: "DELETE" }))).state).toBe("revoked")
  })
})

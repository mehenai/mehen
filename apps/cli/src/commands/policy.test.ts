import { afterAll, afterEach, beforeAll, beforeEach, expect, test } from "bun:test"
import { join } from "node:path"
import type { PolicyChange } from "@mehen/protocol/policy-mode"
import { MockVault, item, vaultError } from "../testing/mock-vault.ts"
import { RULES_OFF, RULES_OFF_BODY, grantCreated, grantView, ruleCreated, rulePreview, ruleStatus, ruleView } from "../testing/policy-rules-fixtures.ts"
import { clockText } from "../ask.ts"
import { tempDir } from "../testing/run-mehen.ts"
import { readLedger } from "../ledger.ts"
import { readBounded } from "../policy-operations.ts"

let vault: MockVault
const scope = () => vault.ledgerScope()
let dir: Awaited<ReturnType<typeof tempDir>>
let env: Record<string, string>
let device: string
beforeAll(() => { vault = new MockVault() })
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  vault.lastDevice = null
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url, MEHEN_SESSION: "pol-test" }
  device = await vault.enrolSoftware(dir.path)
  vault.seen.length = 0
  vault.overrides.clear()
  vault.items.splice(2)
  vault.items.push(item("example-key", { binding: { hosts: ["api.example.com"] } }))
})
afterEach(async () => dir.remove())

function change() {
  return { kind: "mode", target: { kind: "item", item: "example-key" }, selector: { device, session: "pol-test" }, policyMode: "relaxed", scope: { host: "api.example.com", methods: ["POST"], path: "/projects/123/**", anchorPath: "/projects/123/issues", basis: "unreviewed" }, ttlSeconds: 3600, notAfter: null }
}
function context(c: PolicyChange) {
  return { item: "example-key", selector: c.selector, baseMode: "standard", effectiveMode: "standard", basePolicy: { default: "approve", rules: [] }, floor: [], snapshot: { itemId: "itm_test", device, configRev: 0, scopeRev: 0, protectionRev: 0, safetyDigest: "safety", frozen: false }, baseDigest: "a".repeat(43), slotRevision: 3, predecessor: null, state: { widening: [], observedAt: new Date().toISOString() } }
}

// The module is deliberately unregistered until CONTRACT-I. Exercise its real
// command entry and argument parser in a subprocess, without editing cli.ts.
async function run(args: string[], stdin?: string, extra: Record<string, string> = {}) {
  const source = `import {policyCommand as command} from ${JSON.stringify(join(import.meta.dir, "policy.ts"))}; import {parseArgs} from ${JSON.stringify(join(import.meta.dir, "../args.ts"))}; import {reportError} from ${JSON.stringify(join(import.meta.dir, "../output.ts"))}; import {toCliError,exitCodeFor} from ${JSON.stringify(join(import.meta.dir, "../errors.ts"))}; let json=true; try { const args=parseArgs(${JSON.stringify(args)}, command.spec); json=args.bool("json"); process.exitCode=await command.run({args,json,env:process.env}); } catch(e) {const error=toCliError(e); reportError(error,json,{env:process.env});process.exitCode=exitCodeFor(error.code);}`
  const proc = Bun.spawn([process.execPath, "-e", source], { env: { PATH: process.env.PATH, HOME: dir.path, ...env, ...extra }, stdin: stdin === undefined ? "ignore" : new TextEncoder().encode(stdin), stdout: "pipe", stderr: "pipe", timeout: 20000 })
  const [stdout, stderr, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited])
  return { code, stdout, stderr }
}
test("refusal/the window flags, --file and --new no longer exist: each gets one line naming what to use, and nothing reaches the vault", async () => {
  const before = vault.seen.length
  const rule = ["propose", "--item", "example-key", "--method", "POST", "--url", "https://api.example.com/tasks", "--reason", "Task"]
  const said: Record<string, string> = {
    "--policy-mode": "--policy-mode no longer exists; policy windows were replaced by standing rules: use mehen policy propose --from <apr_id>, or --item, --method and --url.",
    "--session": "--session no longer exists; a standing rule is for the key that asked: use mehen policy propose --from <apr_id>, or --item, --method and --url.",
    "--device": "--device no longer exists; a standing rule is for the key that asked: use mehen policy propose --from <apr_id>, or --item, --method and --url.",
    "--action": "--action no longer exists; policy windows were replaced by standing rules: use mehen policy propose --from <apr_id>, or --item, --method and --url.",
    "--anchor-path": "--anchor-path no longer exists; the vault takes the anchor from the request: use --url, and --path for one of its path choices.",
    "--host": "--host no longer exists; use --url with the full address.",
    "--until": "--until no longer exists; use --for 1d, 7d or 30d.",
    "--file": "--file no longer exists; use mehen policy propose --from <apr_id>, or --item, --method and --url.",
    "--new": "--new no longer exists; cancel the pending proposal with mehen policy cancel <pol_id>, then propose again.",
  }
  for (const [flag, message] of Object.entries(said)) {
    const value = ["--session", "--device", "--new"].includes(flag) ? [] : [flag === "--policy-mode" ? "relaxed" : "x"]
    for (const args of [[...rule, flag, ...value], ["preview", "--from", "apr_held1", flag, ...value], ["show", "example-key", flag, ...value]]) {
      const result = await run([...args, "--json"])
      expect(result.code).toBe(2)
      expect(JSON.parse(result.stdout)).toMatchObject({ error: "usage", message })
    }
  }
  for (const args of [["approve", "pol_test"], ["set", "example-key"], ["show", "example-key", "--item", "other-key"], ["cancel", "pol_test", "--reason", "x"], ["ls", "--url", "https://api.example.com/"]]) {
    const result = await run([...args, "--json"])
    expect(result.code).toBe(2)
    expect(JSON.parse(result.stdout).error).toBe("usage")
  }
  expect(vault.seen.length).toBe(before)
}, 30_000)

test("refusal/an oversized example body is refused after reading at most the limit", async () => {
  const before = vault.seen.length
  const path = join(dir.path, "huge.json")
  await Bun.write(path, " ".repeat(8 * 1024 * 1024))
  const result = await run(["preview", "--item", "example-key", "--method", "POST", "--url", "https://api.example.com/tasks", "-d", `@${path}`, "--json"])
  expect(result.code).toBe(2)
  expect(JSON.parse(result.stdout).message).toContain("32 KiB")
  const piped = await run(["preview", "--item", "example-key", "--method", "POST", "--url", "https://api.example.com/tasks", "-d", "-", "--json"], " ".repeat(40_000))
  expect(JSON.parse(piped.stdout).message).toContain("32 KiB")
  expect(vault.seen.length).toBe(before)
})

test("refusal/a FIFO given as the example body is refused at once, not waited on", async () => {
  const before = vault.seen.length
  const path = join(dir.path, "pipe.json")
  expect(Bun.spawnSync(["mkfifo", path]).exitCode).toBe(0)
  const started = Date.now()
  const result = await run(["preview", "--item", "example-key", "--method", "POST", "--url", "https://api.example.com/tasks", "-d", `@${path}`, "--json"])
  expect(result.code).toBe(2)
  expect(Date.now() - started).toBeLessThan(5000)
  expect(vault.seen.length).toBe(before)
})

test("readBounded stops pulling from a stream once it passes the limit", async () => {
  let pulled = 0
  const stream = new ReadableStream<Uint8Array>({ pull(controller) { pulled++; controller.enqueue(new Uint8Array(1024)) } })
  expect(await readBounded(stream, 4096)).toBeNull()
  expect(pulled).toBeLessThanOrEqual(6)
  const small = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(new TextEncoder().encode("{}")); controller.close() } })
  expect(new TextDecoder().decode((await readBounded(small, 4096))!)).toBe("{}")
})

// ---------------------------------------------------------------- standing rules

const example = () => ["propose", "--item", "example-key", "--method", "POST", "--url", "https://api.example.com/tasks", "-d", '{"title":"x"}', "--content-type", "application/json", "--reason", "Track tasks"]
const proposalsSent = () => vault.seen.filter((s) => s.path === "/v1/policy/proposals").map((s) => JSON.parse(s.body) as Record<string, unknown>)

test("propose from an example sends the request, no context outside a project, and hands over the ask", async () => {
  vault.overrides.set("POST /v1/policy/proposals", () => Response.json(ruleCreated(vault.url), { status: 201 }))
  const result = await run([...example(), "--json"])
  expect(result.code).toBe(0)
  expect(proposalsSent()).toEqual([{ from: { item: "example-key", method: "POST", url: "https://api.example.com/tasks", bodyBase64: Buffer.from('{"title":"x"}').toString("base64"), contentType: "application/json" }, reason: "Track tasks" }])
  expect(JSON.parse(result.stdout)).toMatchObject({ proposal: "pol_rule", status: "pending", stage: "approve", ask: { kind: "policy", id: "pol_rule", url: `${vault.url}/w/mock-space/p/pol_rule`, check: { label: "code", value: "CODE42" } }, next: { command: "mehen wait pol_rule" } })
  expect(result.stderr).toContain("No context was sent: the rule will cover only requests made outside any project. Give --project and --env to bind one.")
  expect(JSON.parse(result.stdout)).toMatchObject({ note: "No context was sent: the rule will cover only requests made outside any project. Give --project and --env to bind one.", warning: null })
  expect((await readLedger(vault.slotDir(dir.path), scope())).map((e) => e.ask.id)).toEqual(["pol_rule"])
})

test("propose sends --project/--env as the context, --path and --for, and prints the ask block", async () => {
  vault.overrides.set("POST /v1/policy/proposals", () => Response.json(ruleCreated(vault.url), { status: 201 }))
  const result = await run([...example(), "--project", "prj_3kQ9vXyZ7", "--env", "dev", "--path", "/tasks", "--for", "30d"])
  expect(result.code).toBe(0)
  expect(proposalsSent()[0]).toMatchObject({ from: { context: { project: "prj_3kQ9vXyZ7", environment: "dev" } }, path: "/tasks", ttlSeconds: 2_592_000 })
  expect(result.stderr).toContain("Context sent: project prj_3kQ9vXyZ7, environment dev.")
  expect(result.stdout).toContain(`open:    ${vault.url}/w/mock-space/p/pol_rule`)
  expect(result.stdout).toContain("the page shows code CODE42")
  expect(result.stdout).toContain("then:    mehen wait pol_rule")
})

test("propose --from names the held request and nothing else; --no-context sends none", async () => {
  vault.overrides.set("POST /v1/policy/proposals", () => Response.json(ruleCreated(vault.url), { status: 201 }))
  expect((await run(["propose", "--from", "apr_held1", "--reason", "Track tasks", "--json"])).code).toBe(0)
  expect(proposalsSent().at(-1)).toEqual({ from: { approval: "apr_held1" }, reason: "Track tasks" })
  expect(JSON.parse((await run(["propose", "--from", "apr_held1", "--reason", "Track tasks", "--json"])).stdout)).toMatchObject({ note: "Context: the one apr_held1 was asked in." })
  vault.overrides.set("POST /v1/policy/proposals", () => Response.json({ ...ruleCreated(vault.url), url: "https://evil.example/w/mock-space/p/pol_rule" }, { status: 201 }))
  const refusedLink = JSON.parse((await run(["propose", "--from", "apr_held1", "--reason", "Track tasks", "--json"])).stdout)
  expect(refusedLink).toMatchObject({ note: "Context: the one apr_held1 was asked in.", warning: expect.any(String), url: `${vault.url}/w/mock-space/p/pol_rule` })
  const none = await run([...example(), "--no-context", "--json"])
  expect(none.code).toBe(0)
  expect(proposalsSent().at(-1)?.from).not.toHaveProperty("context")
})

test("refusal/propose flags that do not fit together, durations and missing reasons never reach the vault", async () => {
  const before = vault.seen.length
  for (const args of [
    ["propose", "--from", "apr_held1", "--item", "example-key", "--reason", "x"],
    ["propose", "--from", "apr_held1", "--project", "prj_3kQ9vXyZ7", "--env", "dev", "--reason", "x"],
    ["propose", "--from", "apr_bad/next", "--reason", "x"],
    ["propose", "--item", "example-key", "--method", "POST", "--reason", "x"],
    [...example(), "--for", "2d"],
    [...example(), "--no-context", "--project", "prj_3kQ9vXyZ7", "--env", "dev"],
    [...example(), "--project", "prj_3kQ9vXyZ7"],
    ["propose", "--item", "example-key", "--method", "DELETE", "--url", "https://api.example.com/tasks/1", "--reason", "x"],
    ["propose", "--item", "example-key", "--method", "POST", "--url", "https://api.example.com/tasks"],
  ]) {
    const result = await run([...args, "--json"])
    expect(result.code).toBe(2)
    expect(JSON.parse(result.stdout).error).toBe("usage")
  }
  expect(vault.seen.length).toBe(before)
})

test("switch off: propose prints one line, keeps the vault's next and exits with the forbidden code", async () => {
  vault.overrides.set("POST /v1/policy/proposals", () => vaultError(RULES_OFF_BODY.error, RULES_OFF_BODY.message, { next: RULES_OFF_BODY.next! }))
  const human = await run(example())
  expect(human.code).toBe(5)
  expect(human.stderr.split("\n")[0]).toBe("mehen: Standing rules are not switched on for this workspace yet.")
  expect(human.stderr).toContain("mehen policy propose --help")
  const json = await run([...example(), "--json"])
  expect(json.code).toBe(5)
  expect(JSON.parse(json.stdout)).toMatchObject({ error: "forbidden", message: "Standing rules are not switched on for this workspace yet.", next: RULES_OFF.next })
})

test("a refused proposal prints the vault's words for its refusal code; a conflict prints the vault's message", async () => {
  const words = "This request sends a message, so it asks every time."
  vault.overrides.set("POST /v1/policy/proposals", () => vaultError("forbidden", words, { ruleRefused: "rule.send" }))
  const refused = await run([...example(), "--json"])
  expect(refused.code).toBe(5)
  expect(JSON.parse(refused.stdout)).toMatchObject({ error: "forbidden", message: words, ruleRefused: "rule.send" })
  expect(JSON.parse(refused.stdout).next).toEqual({ say: "This request cannot be allowed from now on; it asks for approval every time. Do not propose it again." })
  const human = await run(example())
  expect(human.stderr.split("\n")[0]).toBe(`mehen: ${words}`)
  vault.overrides.set("POST /v1/policy/proposals", () => vaultError("conflict", "This approval was denied, so it cannot become a rule."))
  const conflict = await run(["propose", "--from", "apr_held1", "--reason", "x", "--json"])
  expect(conflict.code).toBe(1)
  expect(JSON.parse(conflict.stdout)).toMatchObject({ error: "conflict", message: "This approval was denied, so it cannot become a rule." })
})

test("a refusal the agent can fix (path, binding, duration) says to pick from preview's choices and propose again", async () => {
  for (const [reason, words] of [["rule.path", "Pick one of the vault's path choices."], ["rule.binding", "That path is wider than this credential's binding allows."], ["rule.duration", "Pick 1, 7 or 30 days."]] as const) {
    vault.overrides.set("POST /v1/policy/proposals", () => vaultError("forbidden", words, { ruleRefused: reason }))
    const refused = await run([...example(), "--json"])
    expect(refused.code).toBe(5)
    expect(JSON.parse(refused.stdout)).toMatchObject({ error: "forbidden", message: words, ruleRefused: reason, next: { command: "mehen policy preview ...", say: "Pick one of preview's path choices (or 1d, 7d or 30d) and propose again." } })
  }
})

const exampleFlags = () => ["--item", "example-key", "--method", "POST", "--url", "https://api.example.com/tasks"]
const previewsSent = () => vault.seen.filter((s) => s.path === "/v1/policy/preview").map((s) => JSON.parse(s.body) as Record<string, unknown>)

test("preview needs no --reason, prints the summary and the path choices with the default marked; --json prints PolicyRulePreview", async () => {
  const preview = rulePreview({ pathChoices: ["/tasks", "/tasks/*"] })
  vault.overrides.set("POST /v1/policy/preview", () => Response.json(preview))
  const human = await run(["preview", ...exampleFlags(), "--path", "/tasks"])
  expect(human.code).toBe(0)
  expect(previewsSent().at(-1)).toMatchObject({ from: { item: "example-key", method: "POST" }, path: "/tasks" })
  expect(human.stdout).toBe(`${preview.summary}\npaths:\n  /tasks (default)\n  /tasks/*\n`)
  const json = await run(["preview", "--from", "apr_held1", "--json"])
  expect(json.code).toBe(0)
  expect(JSON.parse(json.stdout)).toEqual(preview)
})

test("preview prints the refusal reason in the vault's words with its code", async () => {
  const words = "This request sends a message, so it asks every time."
  vault.overrides.set("POST /v1/policy/preview", () => Response.json(rulePreview({ terms: null, pathChoices: [], summary: words, refused: "rule.send" })))
  const result = await run(["preview", ...exampleFlags()])
  expect(result.code).toBe(0)
  expect(result.stdout).toBe(`${words}\nThis request cannot become a rule (rule.send).\n`)
})

test("a preview refused for its path prints the path choices it asks the agent to pick from", async () => {
  const words = "Pick one of the vault's path choices."
  vault.overrides.set("POST /v1/policy/preview", () => Response.json(rulePreview({ terms: null, pathChoices: ["/tasks", "/tasks/*"], summary: words, refused: "rule.path" })))
  const result = await run(["preview", ...exampleFlags(), "--path", "/other"])
  expect(result.code).toBe(0)
  expect(result.stdout).toBe(`${words}\nThis request cannot become a rule (rule.path).\npaths:\n  /tasks (default)\n  /tasks/*\n`)
})

test("switch off: preview prints the one line and exits with the forbidden code", async () => {
  vault.overrides.set("POST /v1/policy/preview", () => vaultError(RULES_OFF_BODY.error, RULES_OFF_BODY.message, { next: RULES_OFF_BODY.next! }))
  const result = await run(["preview", ...exampleFlags()])
  expect(result.code).toBe(5)
  expect(result.stderr.split("\n")[0]).toBe("mehen: Standing rules are not switched on for this workspace yet.")
  vault.overrides.set("POST /v1/policy/preview", () => vaultError("bad_request", "Invalid request: from.url Invalid URL.", { next: RULES_OFF_BODY.next! }))
  const other = await run(["preview", ...exampleFlags()])
  expect(other.code).toBe(2)
  expect(other.stderr.split("\n")[0]).toBe("mehen: Invalid request: from.url Invalid URL.")
})

test("status reads a rule proposal once, without waiting, and says each stage in words", async () => {
  const endsAt = new Date(Date.now() + 7 * 86_400_000).toISOString()
  const answers: Record<string, unknown> = {
    approve: ruleStatus(),
    cosign: ruleStatus({ stage: "co-sign" }),
    approved: ruleStatus({ status: "approved", rule: { id: "rul_live", endsAt } }),
    denied: ruleStatus({ status: "denied" }),
  }
  let answer = "approve"
  vault.overrides.set("GET /v1/policy/proposals/pol_rule", () => Response.json(answers[answer]))
  const pending = await run(["status", "pol_rule"])
  expect(pending.code).toBe(0)
  expect(vault.seen.at(-1)?.path).toBe("/v1/policy/proposals/pol_rule")
  expect(pending.stdout).toContain("Waiting for the machine's owner to approve it on the vault page; the page shows code CODE42.")
  answer = "cosign"
  expect((await run(["status", "pol_rule"])).stdout).toContain("The machine's owner approved; a manager of the credential's home must co-sign it on the vault page; the page shows code CODE42.")
  answer = "approved"
  const approved = await run(["status", "pol_rule"], undefined, { TZ: "Etc/UTC" })
  expect(approved.stdout).toContain(`Approved: rule rul_live allows this from now on, until ${clockText(endsAt, { timeZone: "Etc/UTC" })}.`)
  expect(JSON.parse((await run(["status", "pol_rule", "--json"])).stdout)).toMatchObject({ proposal: "pol_rule", status: "approved", rule: { id: "rul_live", endsAt } })
  answer = "denied"
  expect((await run(["status", "pol_rule"])).stdout).toContain("The person denied it. Do not propose it again without asking them.")
})

test("status reads an older vault's answer without stage or rule, and the switched-off one line", async () => {
  const { stage: _stage, rule: _rule, ...old } = ruleStatus()
  vault.overrides.set("GET /v1/policy/proposals/pol_rule", () => Response.json(old))
  const result = await run(["status", "pol_rule", "--json"])
  expect(result.code).toBe(0)
  expect(JSON.parse(result.stdout)).toMatchObject({ proposal: "pol_rule", status: "pending" })
  vault.overrides.set("GET /v1/policy/proposals/pol_rule", () => vaultError(RULES_OFF.error, RULES_OFF.message, { next: RULES_OFF.next! }))
  const off = await run(["status", "pol_rule"])
  expect(off.code).toBe(5)
  expect(off.stderr.split("\n")[0]).toBe("mehen: Standing rules are not switched on for this workspace yet.")
  const before = vault.seen.length
  expect((await run(["status", "apr_held1", "--json"])).code).toBe(2)
  expect(vault.seen.length).toBe(before)
})

test("ls prints this key's rules as a table and --json prints the PolicyRuleList; --item filters at the vault", async () => {
  const endsAt = "2027-01-10T14:00:00.000Z"
  const rules = [
    ruleView({ id: "rul_live", endsAt, context: { project: "prj_3kQ9vXyZ7", environment: "dev" }, uses: 3, lastUsedAt: "2026-10-01T09:30:00.000Z" }),
    ruleView({ id: "rul_gql", method: "POST", host: "api.linear.app", path: "/graphql", anchorPath: "/graphql", graphql: { fields: ["commentCreate"], nestedFields: ["id"] }, asker: { device: "dev_test", workload: "wl_abcdefgh" }, endsAt, uses: 0, status: "ended", endedReason: "revoked" }),
  ]
  vault.overrides.set("GET /v1/policy/rules", () => Response.json(rules))
  const json = await run(["ls", "--item", "example-key", "--json"])
  expect(json.code).toBe(0)
  expect(vault.seen.at(-1)).toMatchObject({ path: "/v1/policy/rules", search: "?item=example-key" })
  expect(JSON.parse(json.stdout)).toEqual(rules)
  const human = await run(["ls"], undefined, { TZ: "Etc/UTC" })
  expect(human.code).toBe(0)
  expect(vault.seen.at(-1)).toMatchObject({ path: "/v1/policy/rules", search: "" })
  expect(human.stdout.split("\n").map((line) => line.split(/ {2,}/))).toEqual([
    ["ID", "ITEM", "REQUEST", "CONTEXT", "FROM", "ENDS", "USES", "LAST USED", "STATUS"],
    ["rul_live", "example-key", "POST api.example.com/tasks", "prj_3kQ9vXyZ7 / dev", "machine", "10 Jan 14:00", "3", "1 Oct 09:30", "active"],
    ["rul_gql", "example-key", "POST api.linear.app/graphql commentCreate", "outside any project", "workload wl_abcdefgh", "10 Jan 14:00", "0", "never", "ended (revoked)"],
    [""],
  ])
})

test("ls with no rules says so; an older vault and the switched-off answer read as the one line", async () => {
  vault.overrides.set("GET /v1/policy/rules", () => Response.json([]))
  expect((await run(["ls"])).stdout).toBe("No standing rules. mehen policy propose asks for one.\n")
  vault.overrides.set("GET /v1/policy/rules", () => vaultError(RULES_OFF.error, RULES_OFF.message, { next: RULES_OFF.next! }))
  const off = await run(["ls", "--json"])
  expect(off.code).toBe(5)
  expect(JSON.parse(off.stdout)).toMatchObject({ error: "forbidden", message: "Standing rules are not switched on for this workspace yet." })
  const before = vault.seen.length
  expect((await run(["ls", "rul_live", "--json"])).code).toBe(2)
  expect(vault.seen.length).toBe(before)
})

test("revoke ends a standing rule and says what it allowed; stop is a deprecated alias that takes rul_ ids only", async () => {
  const revoked = ruleView({ id: "rul_live", status: "ended", endedReason: "revoked" })
  vault.overrides.set("POST /v1/policy/rules/rul_live/revoke", () => Response.json(revoked))
  const human = await run(["revoke", "rul_live"])
  expect(human.code).toBe(0)
  expect(vault.seen.at(-1)).toMatchObject({ method: "POST", path: "/v1/policy/rules/rul_live/revoke", body: "{}" })
  expect(human.stdout).toBe("Revoked rule rul_live (POST api.example.com/tasks). Requests it allowed ask for approval again.\n")
  const json = await run(["revoke", "rul_live", "--json"])
  expect(JSON.parse(json.stdout)).toEqual(revoked)
  const alias = await run(["stop", "rul_live"])
  expect(alias.code).toBe(0)
  expect(alias.stderr).toBe("mehen policy stop is deprecated; use mehen policy revoke.\n")
  expect(alias.stdout).toBe(human.stdout)
})

test("refusal/revoke and stop take one rul_ id; a window or grant id gets one line and never reaches the vault", async () => {
  const before = vault.seen.length
  for (const args of [["revoke", "pov_test"], ["stop", "pov_test"], ["stop", "gnt_test"], ["revoke", "rul_x/next"], ["revoke"], ["revoke", "rul_live", "--item", "example-key"]]) {
    const result = await run([...args, "--json"])
    expect(result.code).toBe(2)
    expect(JSON.parse(result.stdout).error).toBe("usage")
  }
  expect(JSON.parse((await run(["stop", "pov_test", "--json"])).stdout).message).toBe("Policy windows and grants no longer exist; mehen policy revoke <rul_id> ends a standing rule.")
  expect(vault.seen.length).toBe(before)
  vault.overrides.set("POST /v1/policy/rules/rul_live/revoke", () => vaultError(RULES_OFF.error, RULES_OFF.message, { next: RULES_OFF.next! }))
  const off = await run(["revoke", "rul_live"])
  expect(off.code).toBe(5)
  expect(off.stderr.split("\n")[0]).toBe("mehen: Standing rules are not switched on for this workspace yet.")
})

test("show adds the item's live standing rules; with rules switched off or an older vault it shows the policy alone", async () => {
  vault.overrides.set("GET /v1/policy/context", () => Response.json(context(change() as PolicyChange)))
  const endsAt = "2027-01-10T14:00:00.000Z"
  const live = ruleView({ id: "rul_live", endsAt }), ended = ruleView({ id: "rul_old", endsAt, status: "ended", endedReason: "expired" })
  vault.overrides.set("GET /v1/policy/rules", () => Response.json([live, ended]))
  const json = await run(["show", "example-key", "--json"])
  expect(json.code).toBe(0)
  expect(vault.seen.at(-1)).toMatchObject({ path: "/v1/policy/rules", search: "?item=example-key" })
  expect(JSON.parse(json.stdout)).toMatchObject({ item: "example-key", rules: [live] })
  const human = await run(["show", "example-key"], undefined, { TZ: "Etc/UTC" })
  expect(human.stdout).toContain("Standing rules:\n  rul_live  POST api.example.com/tasks  outside any project  machine  ends 10 Jan 14:00  3 uses\n")
  expect(human.stdout).not.toContain("rul_old")
  vault.overrides.set("GET /v1/policy/rules", () => Response.json([]))
  expect((await run(["show", "example-key"])).stdout).toContain("Standing rules: none.\n")
  for (const answer of [() => vaultError(RULES_OFF.error, RULES_OFF.message, { next: RULES_OFF.next! }), () => vaultError("not_found", "No such route.")]) {
    vault.overrides.set("GET /v1/policy/rules", answer)
    const off = await run(["show", "example-key", "--json"])
    expect(off.code).toBe(0)
    expect(JSON.parse(off.stdout)).not.toHaveProperty("rules")
    expect((await run(["show", "example-key"])).stdout).not.toContain("Standing rules")
  }
})

test("cancel withdraws a rule proposal and reads its status, with or without the rule fields", async () => {
  vault.overrides.set("POST /v1/policy/proposals/pol_rule/cancel", () => Response.json(ruleStatus({ status: "cancelled" })))
  const result = await run(["cancel", "pol_rule", "--json"])
  expect(result.code).toBe(0)
  expect(vault.seen.at(-1)).toMatchObject({ method: "POST", path: "/v1/policy/proposals/pol_rule/cancel" })
  expect(JSON.parse(result.stdout)).toMatchObject({ proposal: "pol_rule", status: "cancelled", stage: "approve", rule: null })
  expect((await run(["cancel", "pol_rule"])).stdout).toBe("Cancelled policy proposal pol_rule.\n")
  vault.overrides.set("POST /v1/policy/proposals/pol_rule/cancel", () => vaultError(RULES_OFF.error, RULES_OFF.message, { next: RULES_OFF.next! }))
  expect((await run(["cancel", "pol_rule"])).stderr.split("\n")[0]).toBe("mehen: Standing rules are not switched on for this workspace yet.")
})

// ---------------------------------------------------------------- task grants

const area = (...extra: string[]) => ["propose", "--from", "apr_held1", "--item", "github-work", "--area", "issues", "--reason", "Triage the backlog", ...extra]

test("propose --area sends a task grant from the held request, with --for and --uses, and hands over the ask for a person", async () => {
  vault.overrides.set("POST /v1/policy/proposals", () => Response.json(grantCreated(vault.url), { status: 201 }))
  const json = await run(area("--json"))
  expect(json.code).toBe(0)
  expect(proposalsSent().at(-1)).toEqual({ from: { approval: "apr_held1" }, area: { item: "github-work", areas: ["issues"] }, reason: "Triage the backlog" })
  expect(JSON.parse(json.stdout)).toMatchObject({ proposal: "pol_grant", status: "pending", ask: { kind: "policy", id: "pol_grant", url: `${vault.url}/w/mock-space/p/pol_grant`, check: { label: "code", value: "CODE42" } }, next: { command: "mehen wait pol_grant" } })
  expect((await readLedger(vault.slotDir(dir.path), scope())).map((e) => e.ask.id)).toEqual(["pol_grant"])
  const human = await run(["propose", "--from", "apr_held1", "--item", "github-work", "--area", "issues,pulls", "--area", "actions", "--for", "4h", "--uses", "200", "--reason", "Triage the backlog"])
  expect(human.code).toBe(0)
  expect(proposalsSent().at(-1)).toEqual({ from: { approval: "apr_held1" }, area: { item: "github-work", areas: ["issues", "pulls", "actions"], ttlSeconds: 14_400, maxUses: 200 }, reason: "Triage the backlog" })
  expect(human.stdout).toContain(`open:    ${vault.url}/w/mock-space/p/pol_grant`)
  expect(human.stdout).toContain("then:    mehen wait pol_grant")
  for (const [flag, seconds] of [["15m", 900], ["1h", 3600]] as const) {
    expect((await run(area("--for", flag, "--uses", "1"))).code).toBe(0)
    expect(proposalsSent().at(-1)?.area).toEqual({ item: "github-work", areas: ["issues"], ttlSeconds: seconds, maxUses: 1 })
  }
})

test("refusal/propose --area flags that do not fit, rule durations, uses outside 1 to 200 and a missing reason never reach the vault", async () => {
  const before = vault.seen.length
  for (const args of [
    ["propose", "--item", "github-work", "--area", "issues", "--reason", "x"],
    ["propose", "--from", "apr_held1", "--area", "issues", "--reason", "x"],
    ["propose", "--from", "apr_held1", "--item", "github-work", "--area", "issues"],
    area("--for", "1d"), area("--for", "2h"), area("--uses", "0"), area("--uses", "201"), area("--uses", "5.5"), area("--uses", "many"),
    area("--path", "/repos/*"), area("--method", "POST"), area("--project", "prj_3kQ9vXyZ7", "--env", "dev"), area("--no-context"),
    ["propose", "--from", "apr_held1", "--item", "github-work", "--area", "issues,issues", "--reason", "x"],
    ["propose", "--from", "apr_held1", "--item", "github-work", "--area", "Issues!", "--reason", "x"],
    ["propose", "--from", "apr_held1", "--uses", "5", "--reason", "x"],
    [...example(), "--for", "1h"],
    ["preview", "--from", "apr_held1", "--item", "github-work", "--area", "issues"],
    ["propose", "--from", "apr_held1", "--reason", "x", "--grants"],
  ]) {
    const result = await run([...args, "--json"])
    expect(result.code, args.join(" ")).toBe(2)
    expect(JSON.parse(result.stdout).error).toBe("usage")
  }
  expect(vault.seen.length).toBe(before)
})

test("refusal/propose --area with a rule-only flag names --from, whose request's context the task grant takes", async () => {
  const words = "--area takes the context of the request --from names: give no --method, --url, -d, --content-type, --project, --env, --path or --no-context with it."
  for (const extra of [["--project", "prj_3kQ9vXyZ7"], ["--path", "/repos/*"], ["--no-context"]]) {
    const result = await run([...area(...extra), "--json"])
    expect(result.code, extra.join(" ")).toBe(2)
    expect(JSON.parse(result.stdout), extra.join(" ")).toMatchObject({ error: "usage", message: words })
  }
})

test("a task grant the vault refuses prints its words, its code and a next; one the agent can fix says what to pick", async () => {
  const words = "This request is not routine building, so it cannot start a task grant."
  vault.overrides.set("POST /v1/policy/proposals", () => vaultError("forbidden", words, { areaRefused: "area.not-routine" }))
  const refused = await run(area("--json"))
  expect(refused.code).toBe(5)
  expect(JSON.parse(refused.stdout)).toEqual({ error: "forbidden", message: words, areaRefused: "area.not-routine", next: { say: "This request cannot start a task grant; it asks for approval each time. Do not propose a task grant from it again." } })
  expect((await run(area())).stderr.split("\n")[0]).toBe(`mehen: ${words}`)
  vault.overrides.set("POST /v1/policy/proposals", () => vaultError("forbidden", "Pick areas from this service's reviewed list.", { areaRefused: "area.unknown" }))
  expect(JSON.parse((await run(area("--json"))).stdout)).toMatchObject({ areaRefused: "area.unknown", next: { command: "mehen policy propose --help", say: "Pick areas from the service's reviewed list, 15m, 1h or 4h, and 1 to 200 requests, and propose again." } })
  vault.overrides.set("POST /v1/policy/proposals", () => vaultError("conflict", "That request was denied or has expired; send the request again and propose from its new ask."))
  expect(JSON.parse((await run(area("--json"))).stdout)).toMatchObject({ error: "conflict", message: "That request was denied or has expired; send the request again and propose from its new ask." })
})

test("a vault that cannot read a task grant's proposal from this mehen, switched off or before task grants, reads as one line each", async () => {
  vault.overrides.set("POST /v1/policy/proposals", () => vaultError("bad_request", 'Invalid request: body Unrecognized key: "area".', { next: RULES_OFF.next! }))
  const old = await run(area("--json"))
  expect(old.code).toBe(5)
  expect(JSON.parse(old.stdout)).toEqual({ error: "forbidden", message: "This vault does not take task grant proposals from this mehen yet.", next: { say: "Approve each request on its own for now; do not propose a task grant again." } })
  vault.overrides.set("POST /v1/policy/proposals", () => vaultError(RULES_OFF.error, RULES_OFF.message, { next: RULES_OFF.next! }))
  expect(JSON.parse((await run(area("--json"))).stdout)).toMatchObject({ error: "forbidden", message: "Standing rules are not switched on for this workspace yet." })
})

test("ls --grants asks for task grants and shows their areas, uses of the most, end and what they were used for; --json keeps the vault's fields", async () => {
  const endsAt = "2027-01-10T16:40:00.000Z"
  const rows = [
    ruleView({ id: "rul_live", endsAt, uses: 3 }),
    grantView({ id: "rul_grant", endsAt, areas: ["issues", "pulls"], uses: 3, maxUses: 50, receipt: [{ entry: "github.issue-comment", words: "Comment on an issue", count: 2 }, { entry: "github.pull-create", words: "Open a pull request", count: 1 }] }),
    grantView({ id: "rul_spent", endsAt, uses: 5, maxUses: 5, status: "ended", endedReason: "uses-spent", receipt: [] }),
  ]
  vault.overrides.set("GET /v1/policy/rules", () => Response.json(rows))
  const json = await run(["ls", "--grants", "--item", "github-work", "--json"])
  expect(json.code).toBe(0)
  expect(vault.seen.at(-1)).toMatchObject({ path: "/v1/policy/rules", search: "?item=github-work&include=grants" })
  expect(JSON.parse(json.stdout)).toEqual(rows)
  const human = await run(["ls", "--grants"], undefined, { TZ: "Etc/UTC" })
  expect(vault.seen.at(-1)).toMatchObject({ path: "/v1/policy/rules", search: "?include=grants" })
  expect(human.stdout.split("\n").map((line) => line.split(/ {2,}/))).toEqual([
    ["ID", "ITEM", "REQUEST", "CONTEXT", "FROM", "ENDS", "USES", "LAST USED", "STATUS"],
    ["rul_live", "example-key", "POST api.example.com/tasks", "outside any project", "machine", "10 Jan 16:40", "3", "never", "active"],
    ["rul_grant", "github-work", "task grant: issues, pulls on api.github.com", "outside any project", "machine", "10 Jan 16:40", "3 of 50", "never", "active"],
    ["rul_spent", "github-work", "task grant: issues on api.github.com", "outside any project", "machine", "10 Jan 16:40", "5 of 5", "never", "ended (uses-spent)"],
    ["Used for:"],
    ["", "rul_grant: 2 × Comment on an issue, 1 × Open a pull request"],
    [""],
  ])
  vault.overrides.set("GET /v1/policy/rules", () => Response.json([]))
  expect((await run(["ls", "--grants"])).stdout).toBe("No standing rules or task grants. mehen policy propose asks for one.\n")
  // Without --grants nothing asks for them.
  await run(["ls"])
  expect(vault.seen.at(-1)).toMatchObject({ path: "/v1/policy/rules", search: "" })
})

// mehen env ls and check with personal overrides: the device metadata from
// GET /v1/projects/:id/overrides overlays the selected environment only,
// marks each override (additive `override: true` in --json), never prints a
// plain value, and refuses rather than falling back to the shared sources
// when the list cannot be read. A legacy project (no `access`) makes no
// extra request and prints exactly what it printed before.
import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { EXIT, type Project } from "@mehen/protocol/api"
import { VaultApiError } from "../vault-api.ts"
import { envCommand } from "./env.ts"
import { FakeVaultApi, fakeDeps, git, removeDir, tempDir, writeManifest } from "./fake-vault-api.ts"

let repo: string

beforeAll(() => {
  repo = tempDir("mehen-env-overrides-test-")
  git(repo, "init", "-q")
  writeManifest(repo, 'project = "prj_test"\ndefault_env = "dev"\n[vars]\nOPENAI_API_KEY = "vault"\nDATABASE_URL = "vault"\nFEATURE_FLAG = "vault"\nLOG_LEVEL = "info"\n')
})

afterAll(() => {
  if (repo !== undefined) removeDir(repo)
})

const legacy: Project = {
  id: "prj_test",
  slug: "demo",
  remotes: ["github.com/example/demo"],
  defaultEnv: "dev",
  environments: [
    { name: "dev", protected: false, fences: [] },
    { name: "prod", protected: true, fences: [] },
  ],
  vars: [
    { name: "OPENAI_API_KEY", env: "dev", source: "item", item: "openai-shared", field: null },
    { name: "DATABASE_URL", env: "dev", source: "unset", item: null, field: null },
    { name: "FEATURE_FLAG", env: "dev", source: "plain", item: null, field: null },
    { name: "OPENAI_API_KEY", env: "prod", source: "item", item: "openai-work", field: null },
    { name: "DATABASE_URL", env: "prod", source: "unset", item: null, field: null },
  ],
}

// A workspace projection carries `access`; that is what turns the overlay on.
const workspace = { ...legacy, access: { level: "use", runProtected: false, editProtected: false, sources: [] } }

const SENTINEL = "PLAIN-OVERRIDE-VALUE-NEVER-PRINTED"

const overrides = [
  { environment: "dev", variable: "OPENAI_API_KEY", source: { kind: "item", item: "openai-alex", field: "key" } },
  // Even a reply that wrongly carried a value never gets it printed.
  { environment: "dev", variable: "DATABASE_URL", source: { kind: "plain", value: SENTINEL } },
  // A manifest plain value keeps its precedence, whatever the vault says.
  { environment: "dev", variable: "LOG_LEVEL", source: { kind: "plain" } },
  // Another environment's marker never applies to dev.
  { environment: "staging", variable: "FEATURE_FLAG", source: { kind: "item", item: "flag-alex", field: "value" } },
]

function api(project: unknown, list: () => unknown = () => ({ overrides })): FakeVaultApi {
  return new FakeVaultApi().on("GET", "/v1/projects/prj_test", () => project).on("GET", "/v1/projects/prj_test/overrides", list)
}

describe("mehen env ls with personal overrides", () => {
  test("marks the selected environment's overrides, by name only, and never prints a value", async () => {
    const deps = fakeDeps(api(workspace), repo)
    expect(await envCommand(["ls"], deps)).toBe(EXIT.ok)
    expect(deps.out.text().trim().split("\n")).toEqual([
      "OPENAI_API_KEY  override (your openai-alex)",
      "DATABASE_URL    override (your plain value)",
      "FEATURE_FLAG    plain value in the vault",
      "LOG_LEVEL       plain value in mehen.toml",
    ])
    expect(deps.out.text() + deps.err.text()).not.toContain(SENTINEL)
    const json = fakeDeps(api(workspace), repo)
    expect(await envCommand(["ls", "--json"], json)).toBe(EXIT.ok)
    expect(json.out.text() + json.err.text()).not.toContain(SENTINEL)
    expect(deps.out.text()).not.toContain("flag-alex")
  })

  test("--json adds override: true to exactly the overridden rows and keeps every other field", async () => {
    const deps = fakeDeps(api(workspace), repo)
    expect(await envCommand(["ls", "--json"], deps)).toBe(EXIT.ok)
    expect(JSON.parse(deps.out.text())).toEqual({
      project: "prj_test",
      env: "dev",
      ok: true,
      variables: [
        { name: "OPENAI_API_KEY", resolved: true, source: "item", override: true, item: "openai-alex", field: "key", next: null },
        { name: "DATABASE_URL", resolved: true, source: "plain", override: true, item: null, field: null, next: null },
        { name: "FEATURE_FLAG", resolved: true, source: "plain", item: null, field: null, next: null },
        { name: "LOG_LEVEL", resolved: true, source: "manifest", item: null, field: null, next: null },
      ],
    })
  })

  test("check resolves an otherwise unset variable through its override; other environments are untouched", async () => {
    const dev = fakeDeps(api(workspace), repo)
    expect(await envCommand(["check"], dev)).toBe(EXIT.ok)
    expect(dev.out.text()).toBe("all 4 declared variables resolve for env=dev\n")
    const prod = fakeDeps(api(workspace), repo)
    expect(await envCommand(["check", "--env", "prod", "--json"], prod)).toBe(EXIT.human)
    const report = JSON.parse(prod.out.text()) as { variables: { name: string; override?: true; resolved: boolean }[] }
    expect(report.variables.filter((v) => v.override === true)).toEqual([])
    expect(report.variables.filter((v) => !v.resolved).map((v) => v.name)).toEqual(["DATABASE_URL", "FEATURE_FLAG"])
  })

  test("an empty list (a team machine, an unticked or protected source) leaves the shared sources", async () => {
    const deps = fakeDeps(api(workspace, () => ({ overrides: [] })), repo)
    expect(await envCommand(["ls"], deps)).toBe(EXIT.ok)
    expect(deps.out.text()).not.toContain("override")
    expect(deps.out.text()).toContain("OPENAI_API_KEY  vault item openai-shared")
  })

  test("a hostile slug from the override list is spelled out, never written raw", async () => {
    const hostile = [{ environment: "dev", variable: "OPENAI_API_KEY", source: { kind: "item", item: "openai\u001b[2K-alex\u202e", field: "key" } }]
    const deps = fakeDeps(api(workspace, () => ({ overrides: hostile })), repo)
    expect(await envCommand(["ls"], deps)).toBe(EXIT.ok)
    expect(deps.out.text()).not.toContain("\u001b")
    expect(deps.out.text()).not.toContain("\u202e")
    expect(deps.out.text()).toContain("override (your openai\\u001B[2K-alex[RLO U+202E])")
  })

  test("a refused override read refuses the command with the vault's exit code, never the shared view", async () => {
    const refusing = () => api(workspace, () => {
      throw new VaultApiError(404, { error: "not_found", message: "No such object." })
    })
    const human = fakeDeps(refusing(), repo)
    const code = await envCommand(["ls"], human)
    expect(code).not.toBe(EXIT.ok)
    expect(human.out.text()).toBe("")
    expect(human.err.text()).toContain("No such object.")
    const json = fakeDeps(refusing(), repo)
    expect(await envCommand(["ls", "--json"], json)).toBe(code)
    expect(JSON.parse(json.out.text())).toMatchObject({ error: "not_found", message: "No such object." })
  })

  test("a reply without the list refuses instead of pretending nothing is overridden", async () => {
    const deps = fakeDeps(api(workspace, () => ({})), repo)
    expect(await envCommand(["ls"], deps)).toBe(EXIT.error)
    expect(deps.out.text()).toBe("")
    expect(deps.err.text()).toContain("the vault's override list could not be read")
  })

  // Key order included: these are the bytes the CLI printed before overrides.
  test("a legacy project makes no override request and prints exactly the legacy rows and JSON", async () => {
    const legacyApi = api(legacy)
    const deps = fakeDeps(legacyApi, repo)
    expect(await envCommand(["ls"], deps)).toBe(EXIT.ok)
    expect(deps.out.text()).toBe("OPENAI_API_KEY  vault item openai-shared\nDATABASE_URL    unset in the vault\nFEATURE_FLAG    plain value in the vault\nLOG_LEVEL       plain value in mehen.toml\n")
    expect(legacyApi.calls.map((c) => `${c.method} ${c.path}`)).toEqual(["GET /v1/projects/prj_test"])
    const json = fakeDeps(api(legacy), repo)
    expect(await envCommand(["ls", "--json"], json)).toBe(EXIT.ok)
    expect(json.out.text()).toBe(`${JSON.stringify({ project: "prj_test", env: "dev", ok: false, variables: [
      { name: "OPENAI_API_KEY", item: "openai-shared", field: null, next: null, resolved: true, source: "item" },
      { name: "DATABASE_URL", item: null, field: null, next: { command: "mehen env set DATABASE_URL --env dev --item <slug>", say: 'DATABASE_URL is unset for env=dev: point it at a vault item; if the credential is not in the vault yet, ask a human for it with mehen request <kind> --name <slug> --reason "<why DATABASE_URL is needed>".' }, resolved: false, source: "unset" },
      { name: "FEATURE_FLAG", item: null, field: null, next: null, resolved: true, source: "plain" },
      { name: "LOG_LEVEL", item: null, field: null, next: null, resolved: true, source: "manifest" },
    ] })}\n`)
  })
})

// mehen run with personal overrides: the workspace run's `overrides` names
// become one stderr line each, by variable name and source name only. No
// value is printed, a repeated name prints once, hostile names stay inert,
// and a run without the field (legacy) prints exactly what it did before.
import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { type RunVar } from "@mehen/protocol/api"
import { FakeVaultApi, fakeDeps, git, removeDir, runCreated, tempDir, withTimeout, writeManifest } from "./fake-vault-api.ts"
import { runCommand } from "./run.ts"

let repo: string

beforeAll(() => {
  repo = tempDir("mehen-run-overrides-test-")
  git(repo, "init", "-q")
  writeManifest(repo, ['project = "prj_test"', 'default_env = "dev"', "", "[vars]", 'OPENAI_API_KEY = "vault"', 'DATABASE_URL = "vault"', 'LOG_LEVEL = "info"', ""].join("\n"))
})

afterAll(() => {
  if (repo !== undefined) removeDir(repo)
})

const LEASED = "sk-leased-override-never-printed"
const PLAIN = "postgres://override-plain-never-printed"

const runVars: RunVar[] = [
  { name: "OPENAI_API_KEY", delivery: "lease", value: LEASED, item: "openai-alex" },
  { name: "DATABASE_URL", delivery: "plain", value: PLAIN },
]

function api(extra: Record<string, unknown>): FakeVaultApi {
  return new FakeVaultApi().on("POST", "/v1/runs", () => ({ ...runCreated({ vars: runVars }), ...extra }))
}

function afterBanner(text: string): string[] {
  return text.split("\n").slice(1)
}

describe("mehen run with personal overrides", () => {
  test("names each override and its source once, never a value", async () => {
    const deps = fakeDeps(api({ overrides: ["OPENAI_API_KEY", "DATABASE_URL", "OPENAI_API_KEY"] }), repo)
    expect(await withTimeout(runCommand(["--", "true"], deps), 15_000, "mehen run")).toBe(0)
    expect(afterBanner(deps.err.text())).toEqual(["mehen: OPENAI_API_KEY: override (your openai-alex)", "mehen: DATABASE_URL: override (your plain value)", ""])
    expect(deps.err.text() + deps.out.text()).not.toContain(LEASED)
    expect(deps.err.text() + deps.out.text()).not.toContain(PLAIN)
  })

  test("a name the manifest did not ask for prints nothing", async () => {
    const deps = fakeDeps(api({ overrides: ["UNASKED_TOKEN"] }), repo)
    expect(await withTimeout(runCommand(["--", "true"], deps), 15_000, "mehen run")).toBe(0)
    expect(deps.err.text()).not.toContain("UNASKED_TOKEN")
    expect(deps.err.text()).not.toContain(": override (")
  })

  test("a hostile source name from the vault is spelled out", async () => {
    const hostile: RunVar[] = [{ name: "OPENAI_API_KEY", delivery: "lease", value: LEASED, item: "openai\u001b[2K\u202e" }, { name: "DATABASE_URL", delivery: "plain", value: PLAIN }]
    const deps = fakeDeps(new FakeVaultApi().on("POST", "/v1/runs", () => ({ ...runCreated({ vars: hostile }), overrides: ["OPENAI_API_KEY"] })), repo)
    expect(await withTimeout(runCommand(["--", "true"], deps), 15_000, "mehen run")).toBe(0)
    expect(deps.err.text()).not.toContain("\u001b")
    expect(deps.err.text()).not.toContain("\u202e")
    expect(deps.err.text()).toContain("override (your openai\\u001B[2K[RLO U+202E])")
  })

  test("without the field (a legacy run) or with an empty list, the output is the legacy output", async () => {
    const legacy = fakeDeps(api({}), repo)
    expect(await withTimeout(runCommand(["--", "true"], legacy), 15_000, "mehen run")).toBe(0)
    const empty = fakeDeps(api({ overrides: [] }), repo)
    expect(await withTimeout(runCommand(["--", "true"], empty), 15_000, "mehen run")).toBe(0)
    expect(afterBanner(legacy.err.text())).toEqual([""])
    expect(empty.err.text()).toBe(legacy.err.text())
    expect(empty.out.text()).toBe(legacy.out.text())
  })
})

import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { EXIT, type Project } from "@mehen/protocol/api"
import { requestedBy } from "../ask.ts"
import { VaultApiError, VaultNetworkError } from "../vault-api.ts"
import { envCommand } from "./env.ts"
import { FakeVaultApi, fakeDeps, git, removeDir, tempDir, writeManifest } from "./fake-vault-api.ts"

let repo: string

beforeAll(() => {
  repo = tempDir("mehen-env-test-")
  git(repo, "init", "-q")
  writeManifest(repo, 'project = "prj_test"\ndefault_env = "dev"\n[vars]\nOPENAI_API_KEY = "vault"\nDATABASE_URL = "vault"\nFEATURE_FLAG = "vault"\nLOG_LEVEL = "info"\n')
})

afterAll(() => {
  if (repo !== undefined) removeDir(repo)
})

const project: Project = {
  id: "prj_test",
  slug: "demo",
  remotes: ["github.com/example/demo"],
  defaultEnv: "dev",
  environments: [
    { name: "dev", protected: false, fences: [] },
    { name: "prod", protected: true, fences: [] },
  ],
  vars: [
    { name: "OPENAI_API_KEY", env: "dev", source: "item", item: "openai-personal", field: null },
    { name: "DATABASE_URL", env: "dev", source: "item", item: "dev-db", field: "url" },
    { name: "FEATURE_FLAG", env: "dev", source: "plain", item: null, field: null },
    { name: "OPENAI_API_KEY", env: "prod", source: "item", item: "openai-work", field: null },
    { name: "DATABASE_URL", env: "prod", source: "unset", item: null, field: null },
  ],
}

function api(): FakeVaultApi {
  return new FakeVaultApi().on("GET", "/v1/projects/prj_test", () => project).on("PUT", "/v1/projects/prj_test/vars/DATABASE_URL", () => project)
}

describe("mehen env ls", () => {
  test("shows how each declared variable resolves, never a value", async () => {
    const deps = fakeDeps(api(), repo)
    expect(await envCommand(["ls"], deps)).toBe(EXIT.ok)
    const lines = deps.out.text().trim().split("\n")
    expect(lines).toEqual([
      "OPENAI_API_KEY  vault item openai-personal",
      "DATABASE_URL    vault item dev-db#url",
      "FEATURE_FLAG    plain value in the vault",
      "LOG_LEVEL       plain value in mehen.toml",
    ])
    expect(deps.out.text()).not.toContain("info")
    expect(deps.err.text()).toContain("mehen: prj_test env=dev worktree=")
  })

  test("an item or field name from the vault with a hidden character or an escape is spelled out in the rows", async () => {
    const hostile: Project = {
      ...project,
      vars: [
        { name: "OPENAI_API_KEY", env: "dev", source: "item", item: "openai\u001b[2K\u001b[32m-personal", field: null },
        { name: "DATABASE_URL", env: "dev", source: "item", item: "dev-db", field: "url\u202e" },
      ],
    }
    const deps = fakeDeps(new FakeVaultApi().on("GET", "/v1/projects/prj_test", () => hostile), repo)
    expect(await envCommand(["ls"], deps)).toBe(EXIT.ok)
    const out = deps.out.text()
    expect(out).not.toContain("\u001b")
    expect(out).not.toContain("\u202e")
    expect(out).toContain("OPENAI_API_KEY  vault item openai\\u001B[2K\\u001B[32m-personal")
    expect(out).toContain("DATABASE_URL    vault item dev-db#url[RLO U+202E]")
  })

  test("an environment the project does not have is a usage error", async () => {
    const deps = fakeDeps(api(), repo)
    expect(await envCommand(["ls", "--env", "staging"], deps)).toBe(EXIT.usage)
    expect(deps.err.text()).toContain("Use one of: dev, prod.")
  })
})

describe("mehen env check", () => {
  test("passes when every variable resolves", async () => {
    const deps = fakeDeps(api(), repo)
    expect(await envCommand(["check"], deps)).toBe(EXIT.ok)
    expect(deps.out.text()).toContain("all 4 declared variables resolve for env=dev")
  })

  test("fails, by name and with the fix, when one does not: mehen:, then next:, then one run: per variable", async () => {
    const deps = fakeDeps(api(), repo)
    expect(await envCommand(["check", "--env=prod"], deps)).toBe(EXIT.human)
    expect(deps.err.text().split("\n").slice(1)).toEqual([
      "mehen: DATABASE_URL, FEATURE_FLAG do not resolve for env=prod",
      "  next: point each one at a vault item; if the credential is not in the vault yet, ask a human for it with mehen request.",
      "  run:  mehen env set DATABASE_URL --env prod --item <slug>",
      "  run:  mehen env set FEATURE_FLAG --env prod --item <slug>",
      "",
    ])
    // On a TTY the mehen: prefix and the labels are dim; the words are the same.
    const coloured = fakeDeps(api(), repo, { FORCE_COLOR: "1" })
    expect(await envCommand(["check", "--env=prod"], coloured)).toBe(EXIT.human)
    expect(coloured.err.text()).toContain("\u001b[2mmehen:\u001b[0m DATABASE_URL, FEATURE_FLAG do not resolve for env=prod\n  \u001b[2mnext:\u001b[0m point each one")
    expect(coloured.err.text()).toContain("\n  \u001b[2mrun:\u001b[0m  mehen env set DATABASE_URL --env prod --item <slug>\n")
  })

  test("an approval the vault asks for is the shared ask block, and with --json the contract's ask object", async () => {
    const refusing = () =>
      new FakeVaultApi().on("GET", "/v1/projects/prj_test", () => {
        throw new VaultApiError(409, {
          error: "approval_required",
          message: "env=prod needs an approval.",
          approval: "apr_9",
          bindingCode: "KQ7M",
          expiresAt: "2030-01-01T00:00:00.000Z",
          next: { say: "Ask Alex.", url: "https://vault.test/w/test-space/a/apr_9", command: "mehen wait apr_9" },
        })
      })
    const human = fakeDeps(refusing(), repo)
    expect(await envCommand(["check", "--env", "prod"], human)).toBe(EXIT.approval)
    expect(human.err.text()).toContain("mehen: env=prod needs an approval.\nnext: Ask Alex.\nHuman needed: approve a request\n  open:    https://vault.test/w/test-space/a/apr_9\n  what:    env=prod needs an approval\n  check:   the page shows code KQ7M\n")
    expect(human.err.text()).not.toContain("code:")
    const json = fakeDeps(refusing(), repo)
    expect(await envCommand(["check", "--env", "prod", "--json"], json)).toBe(EXIT.approval)
    expect(json.err.text().split("\n").slice(1)).toEqual([""])
    expect(JSON.parse(json.out.text())).toEqual({
      error: "approval_required",
      message: "env=prod needs an approval.",
      next: { say: "Ask Alex.", url: "https://vault.test/w/test-space/a/apr_9", command: "mehen wait apr_9" },
      approval: "apr_9",
      bindingCode: "KQ7M",
      expiresAt: "2030-01-01T00:00:00.000Z",
      ask: {
        kind: "approval",
        id: "apr_9",
        url: "https://vault.test/w/test-space/a/apr_9",
        title: "Approve a request",
        what: "env=prod needs an approval",
        check: { label: "code", value: "KQ7M" },
        expiresAt: "2030-01-01T00:00:00.000Z",
        account: null,
        requestedBy: requestedBy({}),
        wait: "mehen wait apr_9 --timeout 60 --json",
      },
    })
  })
})

describe("mehen env ls and check --json", () => {
  test("ls prints one stable object: project, env, ok and every variable with its source", async () => {
    const deps = fakeDeps(api(), repo)
    expect(await envCommand(["ls", "--json"], deps)).toBe(EXIT.ok)
    expect(JSON.parse(deps.out.text())).toEqual({
      project: "prj_test",
      env: "dev",
      ok: true,
      variables: [
        { name: "OPENAI_API_KEY", resolved: true, source: "item", item: "openai-personal", field: null, next: null },
        { name: "DATABASE_URL", resolved: true, source: "item", item: "dev-db", field: "url", next: null },
        { name: "FEATURE_FLAG", resolved: true, source: "plain", item: null, field: null, next: null },
        { name: "LOG_LEVEL", resolved: true, source: "manifest", item: null, field: null, next: null },
      ],
    })
  })

  test("check prints the same shape, exits 4 when something is unset, and each unset variable carries a valid next command", async () => {
    const deps = fakeDeps(api(), repo)
    expect(await envCommand(["check", "--env", "prod", "--json"], deps)).toBe(EXIT.human)
    const report = JSON.parse(deps.out.text()) as { ok: boolean; variables: { name: string; resolved: boolean; next: { command: string } | null }[] }
    expect(report.ok).toBe(false)
    const unset = report.variables.filter((v) => !v.resolved)
    expect(unset.map((v) => v.name)).toEqual(["DATABASE_URL", "FEATURE_FLAG"])
    expect(unset[0]?.next?.command).toBe("mehen env set DATABASE_URL --env prod --item <slug>")
  })

  test("a failure with --json is one JSON object on stdout", async () => {
    const deps = fakeDeps(api(), repo)
    expect(await envCommand(["ls", "--env", "staging", "--json"], deps)).toBe(EXIT.usage)
    expect(JSON.parse(deps.out.text())).toEqual({ error: "usage", message: "project demo has no environment staging", next: { say: "Use one of: dev, prod." } })
  })

  test("a checkout with no mehen.toml whose remote is a project names the project and sends the agent to mehen init; an unbound one is unchanged", async () => {
    const clone = tempDir("mehen-env-clone-")
    try {
      git(clone, "init", "-q")
      git(clone, "remote", "add", "origin", "git@github.com:example/demo.git")
      const lookup = `/v1/projects?remote=${encodeURIComponent("github.com/example/demo")}`
      const bound = new FakeVaultApi().on("GET", lookup, () => ({ id: "prj_test", slug: "demo", defaultEnv: "dev", environments: [{ name: "dev", protected: false, variables: ["OPENAI_API_KEY"] }] }))
      const json = fakeDeps(bound, clone)
      expect(await envCommand(["check", "--json"], json)).toBe(EXIT.error)
      expect(JSON.parse(json.out.text())).toEqual({
        error: "failed",
        message: "no mehen.toml in this checkout, but its remote github.com/example/demo is project demo (prj_test)",
        next: { say: "run mehen init to bind this checkout to project demo", command: "mehen init" },
      })
      const human = fakeDeps(bound, clone)
      expect(await envCommand(["check"], human)).toBe(EXIT.error)
      expect(human.err.text()).toBe("mehen: no mehen.toml in this checkout, but its remote github.com/example/demo is project demo (prj_test)\n  next: run mehen init to bind this checkout to project demo\n  run:  mehen init\n")
      expect(bound.calls.map((c) => c.path)).toEqual([lookup, lookup])

      const unbound = new FakeVaultApi().on("GET", lookup, () => {
        throw new VaultApiError(404, { error: "not_found", message: "No such object." })
      })
      const plain = fakeDeps(unbound, clone)
      expect(await envCommand(["check"], plain)).toBe(EXIT.error)
      expect(plain.err.text()).toContain("no mehen.toml in")
      expect(plain.err.text()).toContain("Run mehen init at the repo root to create the project and write mehen.toml.")
    } finally {
      removeDir(clone)
    }
  })

  test("a checkout with no mehen.toml whose remote lookup fails (network, a 5xx, a refusal) gets the plain no mehen.toml refusal", async () => {
    const clone = tempDir("mehen-env-clone-")
    try {
      git(clone, "init", "-q")
      git(clone, "remote", "add", "origin", "git@github.com:example/demo.git")
      const lookup = `/v1/projects?remote=${encodeURIComponent("github.com/example/demo")}`
      for (const failure of [new VaultNetworkError("connection refused"), new VaultApiError(500, { error: "internal", message: "Try again." }), new VaultApiError(403, { error: "workload_required", message: "Act through a workload." })]) {
        const failing = new FakeVaultApi().on("GET", lookup, () => {
          throw failure
        })
        const deps = fakeDeps(failing, clone)
        expect(await envCommand(["check"], deps)).toBe(EXIT.error)
        expect(deps.err.text()).toContain("no mehen.toml in")
        expect(deps.err.text()).toContain("Run mehen init at the repo root to create the project and write mehen.toml.")
      }
    } finally {
      removeDir(clone)
    }
  })

  test("--help prints the usage and exits 0", async () => {
    const deps = fakeDeps(api(), repo)
    expect(await envCommand(["--help"], deps)).toBe(EXIT.ok)
    expect(deps.out.text()).toContain("mehen env ls [--env <env>] [--json]")
  })
})

describe("mehen env set", () => {
  test("PUTs the variable for the environment", async () => {
    const fake = api()
    const deps = fakeDeps(fake, repo)
    expect(await envCommand(["set", "DATABASE_URL", "--env", "dev", "--item", "dev-db", "--field", "url"], deps)).toBe(EXIT.ok)
    expect(fake.calls.at(-1)).toEqual({ method: "PUT", path: "/v1/projects/prj_test/vars/DATABASE_URL", body: { env: "dev", item: "dev-db", field: "url" } })
    expect(deps.out.text()).toContain("DATABASE_URL now resolves from vault item dev-db#url for env=dev")
  })

  test("a plain value", async () => {
    const fake = api().on("PUT", "/v1/projects/prj_test/vars/LOG_LEVEL", () => project)
    const deps = fakeDeps(fake, repo)
    expect(await envCommand(["set", "LOG_LEVEL", "--env", "dev", "--plain", "debug"], deps)).toBe(EXIT.ok)
    expect(fake.calls.at(-1)?.body).toEqual({ env: "dev", plain: "debug" })
    expect(deps.err.text()).toContain('mehen: warning: mehen.toml gives LOG_LEVEL a plain value; change it to LOG_LEVEL = "vault"')
    expect(deps.out.text()).toBe("LOG_LEVEL now resolves from a plain value for env=dev\n")
  })

  test("a field name with an escape is spelled out in the confirmation", async () => {
    const deps = fakeDeps(api(), repo)
    expect(await envCommand(["set", "DATABASE_URL", "--env", "dev", "--item", "dev-db", "--field", "url\u001b[2K"], deps)).toBe(EXIT.ok)
    expect(deps.out.text()).not.toContain("\u001b")
    expect(deps.out.text()).toBe("DATABASE_URL now resolves from vault item dev-db#url\\u001B[2K for env=dev\n")
  })

  test("with neither --item nor --plain, explains how to get the credential into the vault", async () => {
    const fake = api()
    const deps = fakeDeps(fake, repo)
    expect(await envCommand(["set", "DATABASE_URL", "--env", "dev"], deps)).toBe(EXIT.usage)
    expect(deps.err.text()).toContain("mehen request <kind> --name <slug>")
    expect(deps.err.text()).toContain("mehen env set DATABASE_URL --env dev --item <slug>")
    expect(fake.calls).toHaveLength(0)
  })

  test("refuses ambiguous or malformed input before calling the vault", async () => {
    const fake = api()
    for (const argv of [
      ["set", "DATABASE_URL", "--item", "dev-db"],
      ["set", "DATABASE_URL", "--env", "dev", "--item", "dev-db", "--plain", "x"],
      ["set", "DATABASE_URL", "--env", "dev", "--field", "url"],
      ["set", "BAD-NAME", "--env", "dev", "--plain", "x"],
      ["set", "DATABASE_URL", "--env", "dev", "--item", "Not_A_Slug"],
      ["frobnicate"],
    ]) {
      expect(await envCommand(argv, fakeDeps(fake, repo))).toBe(EXIT.usage)
    }
    expect(fake.calls).toHaveLength(0)
  })
})

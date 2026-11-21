import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { EXIT, type RunVar } from "@mehen/protocol/api"
import { newPlaceholder } from "@mehen/protocol"
import { LEASE_ONLY_HOST } from "@mehen/protocol/binding"
import { VaultApiError, VaultNetworkError } from "../vault-api.ts"
import { FakeVaultApi, fakeDeps, git, itemDescription, removeDir, runCreated, tempDir, withTimeout, writeManifest } from "./fake-vault-api.ts"
import { RUN_LOG_FILE, RUN_LOG_MAX_BYTES, cleanRun, readRunLog } from "./run-log.ts"
import { RUN_USAGE, parseRunArgs, runCommand, runHelp, streamsWrites } from "./run.ts"

let repo: string

beforeAll(() => {
  repo = tempDir("mehen-run-test-")
  git(repo, "init", "-q")
  git(repo, "remote", "add", "origin", "https://github.com/example/demo.git")
  git(repo, "commit", "-q", "--allow-empty", "-m", "first")
  writeManifest(
    repo,
    ['project = "prj_test"', 'default_env = "dev"', "", "[vars]", 'OPENAI_API_KEY = "vault"', 'OPENAI_BASE_URL = "vault"', 'DATABASE_URL = "vault"', 'LOG_LEVEL = "info"', ""].join("\n"),
  )
})

afterAll(() => {
  if (repo !== undefined) removeDir(repo)
})

const placeholder = newPlaceholder("sk-proj-x")

function vars(overrides: Partial<Record<string, RunVar>> = {}): RunVar[] {
  const defaults: Record<string, RunVar> = {
    OPENAI_API_KEY: { name: "OPENAI_API_KEY", delivery: "plain", value: "not-secret" },
    OPENAI_BASE_URL: { name: "OPENAI_BASE_URL", delivery: "plain", value: "https://example.test" },
    DATABASE_URL: { name: "DATABASE_URL", delivery: "plain", value: "postgres://localhost/dev" },
  }
  return Object.values({ ...defaults, ...overrides }).filter((v): v is RunVar => v !== undefined)
}

function apiWith(runVars: RunVar[], extra: Partial<Parameters<typeof runCreated>[0]> = {}): FakeVaultApi {
  return new FakeVaultApi().on("POST", "/v1/runs", () => runCreated({ vars: runVars, ...extra }))
}

function bunScript(script: string): string[] {
  return [process.execPath, "-e", script]
}

describe("mehen run", () => {
  test("posts the run, prints what it resolved, ends the run and exits with the child's code", async () => {
    const api = apiWith(vars())
    const deps = fakeDeps(api, repo)
    const code = await withTimeout(runCommand(["--", "sh", "-c", "exit 7"], deps), 15_000, "mehen run")
    expect(code).toBe(7)
    const post = api.calls.find((c) => c.method === "POST" && c.path === "/v1/runs")
    const head = git(repo, "rev-parse", "--short", "HEAD")
    expect(post?.body).toEqual({
      project: "prj_test",
      env: "dev",
      envSource: "default",
      remote: "github.com/example/demo",
      worktree: repo,
      head,
      vars: ["OPENAI_API_KEY", "OPENAI_BASE_URL", "DATABASE_URL"],
      command: "sh -c",
      argv: ["sh", "-c", "exit 7"],
    })
    expect(deps.err.text()).toContain(`mehen: prj_test env=dev worktree=${repo} head=${head}\n`)
    expect(api.called("DELETE", "/v1/runs/run_test1")).toBe(true)
  })

  test("--env wins over MEHEN_ENV, MEHEN_ENV over default_env, and envSource says which", async () => {
    const flagged = apiWith(vars())
    expect(await runCommand(["--env", "staging", "--approval", "apr_1", "true"], fakeDeps(flagged, repo, { MEHEN_ENV: "test" }))).toBe(0)
    expect(flagged.calls[0]?.body).toMatchObject({ env: "staging", envSource: "flag", approval: "apr_1" })
    const fromVar = apiWith(vars())
    const deps = fakeDeps(fromVar, repo, { MEHEN_ENV: "test" })
    expect(await runCommand(["true"], deps)).toBe(0)
    expect(fromVar.calls[0]?.body).toMatchObject({ env: "test", envSource: "env-var" })
    expect(deps.err.text()).toContain("env=test")
  })

  test("missing variables fail before exec, by name, with the next step in the shared next: layout", async () => {
    const missing = vars({
      DATABASE_URL: { name: "DATABASE_URL", delivery: "missing", next: { say: "Ask a human to add the dev database.", url: "https://vault.test/w/test-space/i/int_1", command: "mehen wait int_1" } },
      OPENAI_BASE_URL: undefined,
    })
    const api = apiWith(missing)
    const deps = fakeDeps(api, repo)
    const marker = join(repo, "child-ran")
    const code = await runCommand(["--", "sh", "-c", `touch ${marker}`], deps)
    expect(code).toBe(EXIT.human)
    expect(existsSync(marker)).toBe(false)
    // After the banner: mehen: <why>, then one heading per variable with next:, open: and run: under it.
    expect(deps.err.text().split("\n").slice(1)).toEqual([
      "mehen: not starting sh: OPENAI_BASE_URL, DATABASE_URL have no value for env=dev",
      "OPENAI_BASE_URL:",
      "  next: The vault returned nothing for OPENAI_BASE_URL. Check how it resolves with mehen env ls --env dev.",
      "DATABASE_URL:",
      "  next: Ask a human to add the dev database.",
      "  open: https://vault.test/w/test-space/i/int_1",
      "  run:  mehen wait int_1",
      "",
    ])
    expect(api.called("DELETE", "/v1/runs/run_test1")).toBe(true)
    // On a TTY the mehen: prefix and the labels are dim; the words are the same.
    const coloured = fakeDeps(apiWith(missing), repo, { FORCE_COLOR: "1" })
    expect(await runCommand(["--", "true"], coloured)).toBe(EXIT.human)
    const text = coloured.err.text()
    expect(text).toContain("\u001b[2mmehen:\u001b[0m not starting true: OPENAI_BASE_URL, DATABASE_URL have no value for env=dev\n")
    expect(text).toContain("DATABASE_URL:\n  \u001b[2mnext:\u001b[0m Ask a human to add the dev database.\n  \u001b[2mopen:\u001b[0m https://vault.test/w/test-space/i/int_1\n  \u001b[2mrun:\u001b[0m  mehen wait int_1\n")
    // A missing variable's next with a link off the vault: the link is never printed.
    const foreign = fakeDeps(apiWith(vars({ DATABASE_URL: { name: "DATABASE_URL", delivery: "missing", next: { say: "Ask a human.", url: "https://evil.example/i/int_1" } } })), repo)
    expect(await runCommand(["--", "true"], foreign)).toBe(EXIT.human)
    expect(foreign.err.text()).not.toContain("evil.example")
    expect(foreign.err.text()).toContain("  mehen: warning: The vault returned a link that is not on https://vault.test")
  })

  test("a next step or environment name from the vault with an escape or a hidden character is spelled out", async () => {
    const hostile = apiWith(vars({ DATABASE_URL: { name: "DATABASE_URL", delivery: "missing", next: { say: "Ask\u001b[2K\u001b[32m a human\u202e.", command: "mehen wait int_1\u001b[2J" } } }), { env: "dev\u200b" })
    const deps = fakeDeps(hostile, repo)
    expect(await runCommand(["--", "true"], deps)).toBe(EXIT.human)
    const err = deps.err.text()
    expect(err).not.toContain("\u001b")
    expect(err).not.toContain("\u202e")
    expect(err).not.toContain("\u200b")
    expect(err).toContain("mehen: not starting true: DATABASE_URL has no value for env=dev[ZWSP U+200B]\n")
    expect(err).toContain("  next: Ask\\u001B[2K\\u001B[32m a human[RLO U+202E].\n  run:  mehen wait int_1\\u001B[2J\n")
  })

  test("a project id in mehen.toml with a hidden character or an escape is spelled out in the banner", async () => {
    const dir = tempDir("mehen-run-hostile-")
    try {
      // TOML spells a control character as an escape; the parsed id carries the real one.
      writeManifest(dir, 'project = "prj_\\u202Eevil\\u001B[31m"\ndefault_env = "dev"\n[vars]\n')
      const api = apiWith([])
      const deps = fakeDeps(api, dir)
      expect(await runCommand(["--", "true"], deps)).toBe(0)
      expect(deps.err.text()).not.toContain("\u001b")
      expect(deps.err.text()).toContain("mehen: prj_[RLO U+202E]evil\\u001B[31m env=dev worktree=")
      // What goes to the vault is the manifest's own text; only the terminal gets the spelled form.
      expect(api.calls[0]?.body).toMatchObject({ project: "prj_\u202eevil\u001b[31m" })
    } finally {
      removeDir(dir)
    }
  })

  test("child environment: parent minus MEHEN_* and declared ambient names, plus plain values, placeholders, base URLs and the relay", async () => {
    const api = apiWith(
      vars({
        OPENAI_API_KEY: { name: "OPENAI_API_KEY", delivery: "placeholder", value: placeholder, item: "openai-personal", hosts: ["api.openai.com"] },
        OPENAI_BASE_URL: { name: "OPENAI_BASE_URL", delivery: "base-url", value: "https://api.openai.com/v1", item: "openai-personal" },
      }),
      { interceptHosts: ["api.openai.com"] },
    )
    const deps = fakeDeps(api, repo, { DATABASE_URL: "postgres://prod-from-another-shell", MEHEN_TOKEN: "x", MEHEN_ENV: "dev", KEEP_ME: "1" })
    const out = join(repo, "child-env.json")
    const script = `const fs = require("fs"); const e = process.env; fs.writeFileSync(${JSON.stringify(out)}, JSON.stringify({ env: e, caMode: (fs.statSync(e.NODE_EXTRA_CA_CERTS).mode & 0o777).toString(8), bundleMode: (fs.statSync(e.SSL_CERT_FILE).mode & 0o777).toString(8), bundle: fs.readFileSync(e.SSL_CERT_FILE, "utf8"), ca: fs.readFileSync(e.NODE_EXTRA_CA_CERTS, "utf8") }))`
    expect(await withTimeout(runCommand(bunScript(script), deps), 15_000, "mehen run")).toBe(0)
    const seen = JSON.parse(readFileSync(out, "utf8")) as { env: Record<string, string>; caMode: string; bundleMode: string; bundle: string; ca: string }
    const env = seen.env
    expect(env.OPENAI_API_KEY).toBe(placeholder)
    expect(env.DATABASE_URL).toBe("postgres://localhost/dev")
    expect(env.LOG_LEVEL).toBe("info")
    expect(env.KEEP_ME).toBe("1")
    expect(Object.keys(env).filter((k) => k.startsWith("MEHEN_"))).toEqual([])
    expect(env.HTTPS_PROXY).toMatch(/^http:\/\/mehen:[A-Za-z0-9_-]+@127\.0\.0\.1:\d+$/)
    expect(env.HTTP_PROXY).toBe(env.HTTPS_PROXY)
    expect(env.NO_PROXY).toBe("")
    expect(env.NODE_USE_ENV_PROXY).toBe("1")
    const port = new URL(env.HTTPS_PROXY ?? "").port
    expect(env.OPENAI_BASE_URL).toMatch(new RegExp(`^http://127\\.0\\.0\\.1:${port}/r/[A-Za-z0-9_-]+/openai-personal/v1$`))
    for (const name of ["REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "AWS_CA_BUNDLE", "DENO_CERT"]) expect(env[name]).toBe(env.SSL_CERT_FILE)
    expect(seen.caMode).toBe("600")
    expect(seen.bundleMode).toBe("600")
    expect(seen.bundle).toContain(seen.ca.trim())
    expect(seen.bundle.match(/BEGIN CERTIFICATE/g)?.length ?? 0).toBeGreaterThan(1)
    expect(existsSync(env.NODE_EXTRA_CA_CERTS ?? "")).toBe(false)
    expect(existsSync(env.SSL_CERT_FILE ?? "")).toBe(false)
    expect(deps.err.text()).toContain("ignoring DATABASE_URL from your shell")
    expect(deps.err.text()).not.toContain("prod-from-another-shell")
  })

  test("end to end: curl in the child reaches an intercept host through the relay, placeholder intact for the vault", async () => {
    const api = apiWith(vars({ OPENAI_API_KEY: { name: "OPENAI_API_KEY", delivery: "placeholder", value: placeholder, item: "openai-personal", hosts: ["api.openai.com"] } }), {
      interceptHosts: ["api.openai.com"],
    })
    const out = join(repo, "curl-out.json")
    const deps = fakeDeps(api, repo)
    const code = await withTimeout(
      runCommand(["sh", "-c", `curl -sS --max-time 10 -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models > ${out}`], deps),
      20_000,
      "mehen run with curl",
    )
    expect(code).toBe(0)
    expect(api.relayCalls).toHaveLength(1)
    expect(api.relayCalls[0]).toMatchObject({ run: "run_test1", method: "GET", url: "https://api.openai.com/v1/models" })
    expect(api.relayCalls[0]?.headers).toContainEqual(["Authorization", `Bearer ${placeholder}`])
    expect(JSON.parse(readFileSync(out, "utf8")).echoed.run).toBe("run_test1")
    expect(deps.err.text()).not.toContain("came through mehen's local relay")
  })

  test("leased values are redacted from the child's stdout and stderr, across writes", async () => {
    const lease = "postgres://app:s3cr3t-lease-pw@db.internal/app"
    const api = apiWith(vars({ DATABASE_URL: { name: "DATABASE_URL", delivery: "lease", value: lease, item: "dev-db" } }))
    const deps = fakeDeps(api, repo)
    const script = [
      "const v = process.env.DATABASE_URL",
      "process.stdout.write('url: ' + v.slice(0, 20))",
      "await Bun.sleep(30)",
      "process.stdout.write(v.slice(20) + ' ok\\n')",
      "process.stderr.write('err ' + v + '\\n')",
    ].join(";")
    expect(await withTimeout(runCommand(bunScript(script), deps), 15_000, "mehen run")).toBe(0)
    expect(deps.out.text()).toBe("url: [redacted:DATABASE_URL] ok\n")
    expect(deps.err.text()).toContain("err [redacted:DATABASE_URL]\n")
    expect(deps.err.text()).not.toContain("s3cr3t")
  })

  test("vault refusals and an unreachable vault map to exit codes", async () => {
    const refusing = (body: ConstructorParameters<typeof VaultApiError>[1], status: number) =>
      new FakeVaultApi().on("POST", "/v1/runs", () => {
        throw new VaultApiError(status, body)
      })
    const expiresAt = new Date(Date.now() + 58 * 60_000).toISOString()
    const approvalBody = { error: "approval_required", message: "env=prod needs an approval.", approval: "apr_9", bindingCode: "KQ7M", expiresAt, next: { say: "Ask Alex.", url: "https://vault.test/w/test-space/a/apr_9", command: "mehen wait apr_9" } } as const
    const approval = fakeDeps(refusing(approvalBody, 409), repo)
    expect(await runCommand(["--env", "prod", "true"], approval)).toBe(EXIT.approval)
    // The same ask block every other command prints (output.ts writeError): the
    // binding code is the check: line, and there is no code: or run: line.
    expect(approval.err.text().split("\n").slice(1)).toEqual([
      "mehen: env=prod needs an approval.",
      "next: Ask Alex.",
      "Human needed: approve a request",
      "  open:    https://vault.test/w/test-space/a/apr_9",
      "  what:    env=prod needs an approval",
      "  check:   the page shows code KQ7M",
      expect.stringMatching(/^  expires: in 58 min \(/),
      "  then:    mehen wait apr_9 --timeout 60 --json",
      "",
    ])
    expect(approval.out.text()).toBe("")
    // On a TTY: dim mehen: prefix and labels, bold code, nothing else styled.
    const coloured = fakeDeps(refusing(approvalBody, 409), repo, { FORCE_COLOR: "1" })
    expect(await runCommand(["--env", "prod", "true"], coloured)).toBe(EXIT.approval)
    expect(coloured.err.text()).toContain("\u001b[2mmehen:\u001b[0m env=prod needs an approval.\n\u001b[2mnext:\u001b[0m Ask Alex.\n")
    expect(coloured.err.text()).toContain("  \u001b[2mcheck:  \u001b[0m the page shows code \u001b[1mKQ7M\u001b[0m\n")
    // A link that is not on the configured vault is never printed, in text or --json; the exit code is the error's own.
    for (const url of ["https://evil.example/a/apr_9", "https://vault.test.evil.example/a/apr_9", "https://alex@vault.test/a/apr_9", "https://vault.test:8443/a/apr_9", "http://vault.test/a/apr_9", "https://vault.test/w/test-space/a/apr_9\u200b"]) {
      const foreign = fakeDeps(refusing({ error: "approval_required", message: "env=prod needs an approval.", bindingCode: "KQ7M", next: { say: `Open ${url} now.`, url, command: "mehen wait apr_9" } }, 409), repo)
      expect(await runCommand(["--env", "prod", "true"], foreign)).toBe(EXIT.approval)
      const text = foreign.err.text()
      expect(text).toContain("mehen: warning: The vault returned a link that is not on https://vault.test")
      expect(text).not.toContain("evil.example")
      expect(text).not.toContain("\u200b")
      expect(text).not.toContain("open:")
      expect(text).not.toContain("Open http")
      const asJson = fakeDeps(refusing({ error: "approval_required", message: "env=prod needs an approval.", bindingCode: "KQ7M", next: { say: `Open ${url} now.`, url, command: "mehen wait apr_9" } }, 409), repo)
      expect(await runCommand(["--env", "prod", "true"], asJson)).toBe(EXIT.approval)
      expect(asJson.out.text()).toBe("")
    }
    // A hostile message cannot steer the terminal.
    const hostile = fakeDeps(refusing({ error: "remote_mismatch", message: "not this\u001b[2K\u001b[32m repo\u202e", next: { say: "Fine\u001b[A", command: "mehen init\u001b[2J" } }, 403), repo)
    expect(await runCommand(["true"], hostile)).toBe(EXIT.refused)
    expect(hostile.err.text()).not.toContain("\u001b")
    expect(hostile.err.text()).toContain("mehen: not this\\u001B[2K\\u001B[32m repo[RLO U+202E]\nnext: Fine\\u001B[A\n  run:  mehen init\\u001B[2J\n")
    expect(await runCommand(["true"], fakeDeps(refusing({ error: "remote_mismatch", message: "not this repo" }, 403), repo))).toBe(EXIT.refused)
    const down = new FakeVaultApi().on("POST", "/v1/runs", () => {
      throw new TypeError("Unable to connect")
    })
    const deps = fakeDeps(down, repo)
    expect(await runCommand(["true"], deps)).toBe(EXIT.transient)
    expect(deps.err.text()).toContain("could not reach the vault at https://vault.test")
    expect(down.calls.some((c) => c.method === "DELETE")).toBe(false)
  })

  test("usage errors", async () => {
    const api = new FakeVaultApi()
    expect(await runCommand([], fakeDeps(api, repo))).toBe(EXIT.usage)
    expect(await runCommand(["--env"], fakeDeps(api, repo))).toBe(EXIT.usage)
    const deps = fakeDeps(api, repo)
    expect(await runCommand(["--bogus", "x"], deps)).toBe(EXIT.usage)
    expect(deps.err.text()).toBe(`mehen: Unknown option --bogus for \`${RUN_USAGE}\`.\nnext: Check the usage with \`mehen run --help\`.\n  run:  mehen run --help\n`)
    expect(api.calls).toHaveLength(0)
  })

  test("a checkout with no mehen.toml whose remote is a project names it and sends the agent to mehen init, writing nothing and starting no run", async () => {
    const clone = tempDir("mehen-run-clone-")
    try {
      git(clone, "init", "-q")
      git(clone, "remote", "add", "origin", "https://github.com/example/demo.git")
      const lookup = `/v1/projects?remote=${encodeURIComponent("github.com/example/demo")}`
      const api = apiWith(vars()).on("GET", lookup, () => ({ id: "prj_test", slug: "demo", defaultEnv: "dev", environments: [{ name: "dev", protected: false, variables: ["OPENAI_API_KEY"] }] }))
      const deps = fakeDeps(api, clone)
      expect(await runCommand(["--", "sh", "-c", "exit 0"], deps)).toBe(EXIT.error)
      expect(deps.err.text()).toBe("mehen: no mehen.toml in this checkout, but its remote github.com/example/demo is project demo (prj_test)\n  next: run mehen init to bind this checkout to project demo\n  run:  mehen init\n")
      expect(api.calls.map((c) => `${c.method} ${c.path}`)).toEqual([`GET ${lookup}`])
      expect(existsSync(join(clone, "mehen.toml"))).toBe(false)
    } finally {
      removeDir(clone)
    }
  })

  test("a checkout with no mehen.toml whose remote lookup cannot reach the vault gets the plain no mehen.toml refusal and starts no run", async () => {
    const clone = tempDir("mehen-run-clone-")
    try {
      git(clone, "init", "-q")
      git(clone, "remote", "add", "origin", "https://github.com/example/demo.git")
      const lookup = `/v1/projects?remote=${encodeURIComponent("github.com/example/demo")}`
      const api = apiWith(vars()).on("GET", lookup, () => {
        throw new VaultNetworkError("connection refused")
      })
      const deps = fakeDeps(api, clone)
      expect(await runCommand(["--", "sh", "-c", "exit 0"], deps)).toBe(EXIT.error)
      expect(deps.err.text()).toContain("no mehen.toml in")
      expect(api.calls.map((c) => `${c.method} ${c.path}`)).toEqual([`GET ${lookup}`])
    } finally {
      removeDir(clone)
    }
  })

  test("--stop-grace takes whole seconds from 1 to 300; anything else is a usage error before the vault is called", async () => {
    expect(parseRunArgs(["--stop-grace", "45", "bun", "serve"])).toEqual({ stopGraceMs: 45_000, command: ["bun", "serve"] })
    expect(parseRunArgs(["--stop-grace=300", "--env", "dev", "--", "bun"])).toEqual({ stopGraceMs: 300_000, env: "dev", command: ["bun"] })
    expect(parseRunArgs(["--env=dev", "--approval=apr_1", "bun"])).toEqual({ env: "dev", approval: "apr_1", command: ["bun"] })
    expect(runHelp(["--stop-grace", "10", "--help"])).toBe(RUN_USAGE)
    for (const value of ["0", "301", "1.5", "ten", "", "1e2"]) {
      const api = new FakeVaultApi()
      const deps = fakeDeps(api, repo)
      expect(await runCommand([`--stop-grace=${value}`, "true"], deps)).toBe(EXIT.usage)
      expect(deps.err.text()).toContain("--stop-grace takes whole seconds from 1 to 300.")
      expect(api.calls).toHaveLength(0)
    }
    expect(await runCommand(["--stop-grace", "true"], fakeDeps(new FakeVaultApi(), repo))).toBe(EXIT.usage)
  })

  test("at its maximum life the child is asked to stop, the run is ended and mehen exits 7 with the reason on stderr", async () => {
    const endsAt = new Date(Date.now() + 1500).toISOString()
    const api = apiWith(vars(), { expiresAt: endsAt, endsAt }).on("DELETE", "/v1/runs/run_test1", () => ({}))
    const deps = fakeDeps(api, repo)
    const started = Date.now()
    expect(await withTimeout(runCommand(["--stop-grace", "1", "sleep", "30"], deps), 10_000, "mehen run")).toBe(EXIT.transient)
    expect(Date.now() - started).toBeLessThan(5000)
    expect(deps.err.text()).toContain("reaches its maximum life")
    expect(deps.err.text()).toContain("mehen: run run_test1 has reached its maximum life; its child processes were stopped.\n")
    expect(api.called("DELETE", "/v1/runs/run_test1")).toBe(true)
  })

  test("--stream-writes, or MEHEN_RUN_STREAM_WRITES=1, has the local relay stream every write's answer", () => {
    const args = parseRunArgs(["--stream-writes", "--env", "dev", "--", "node", "app.js"])
    expect(args).toEqual({ streamWrites: true, env: "dev", command: ["node", "app.js"] })
    expect(runHelp(["--stream-writes", "--help"])).toBe(RUN_USAGE)
    expect([streamsWrites(args, {}), streamsWrites({}, { MEHEN_RUN_STREAM_WRITES: "1" }), streamsWrites({}, { MEHEN_RUN_STREAM_WRITES: "0" }), streamsWrites({}, {})]).toEqual([true, true, false, false])
  })

  test("--service asks for a service run and the banner says so; a vault without service runs is named with the run's end", async () => {
    expect(parseRunArgs(["--service", "--env", "dev", "bun", "serve"])).toEqual({ service: true, env: "dev", command: ["bun", "serve"] })
    expect(parseRunArgs(["bun", "--service"])).toEqual({ command: ["bun", "--service"] })
    expect(runHelp(["--service", "--help"])).toBe(RUN_USAGE)
    const api = apiWith(vars(), { endsAt: null })
    const deps = fakeDeps(api, repo)
    expect(await withTimeout(runCommand(["--service", "--", "true"], deps), 15_000, "mehen run")).toBe(0)
    expect(api.calls.find((c) => c.method === "POST" && c.path === "/v1/runs")?.body).toMatchObject({ service: true, argv: ["true"] })
    expect(deps.err.text()).toContain(`mehen: prj_test env=dev service worktree=${repo} head=`)
    expect(deps.err.text()).not.toContain("not a service run")
    const ordinary = apiWith(vars())
    expect(await runCommand(["true"], fakeDeps(ordinary, repo))).toBe(0)
    expect(ordinary.calls[0]?.body).not.toHaveProperty("service")
    const endsAt = new Date(Date.now() + 12 * 3_600_000).toISOString()
    const older = fakeDeps(apiWith(vars(), { endsAt }), repo)
    expect(await runCommand(["--service", "true"], older)).toBe(0)
    expect(older.err.text()).toContain(`run run_test1 is not a service run: this vault does not offer them, so it ends at ${endsAt}`)
    // A vault from before endsAt names no end: still not a service run.
    const oldest = fakeDeps(new FakeVaultApi().on("POST", "/v1/runs", () => { const { endsAt: _endsAt, ...created } = runCreated({ vars: vars() }); return created }), repo)
    expect(await runCommand(["--service", "true"], oldest)).toBe(0)
    expect(oldest.err.text()).toContain("run run_test1 is not a service run: this vault does not offer them, so it ends at its maximum life")
  })

  test("a .env or .env.* next to the run is named once, with mehen adopt file as the next step; examples are not, and the run goes ahead", async () => {
    const dir = tempDir("mehen-run-dotenv-")
    try {
      git(dir, "init", "-q")
      writeManifest(dir, 'project = "prj_test"\ndefault_env = "dev"\n[vars]\nOPENAI_API_KEY = "vault"\n')
      for (const name of [".env", ".env.local", ".env.example", ".env.sample", ".env.template"]) writeFileSync(join(dir, name), "OPENAI_API_KEY=old\n")
      const deps = fakeDeps(apiWith([{ name: "OPENAI_API_KEY", delivery: "plain", value: "x" }]), dir)
      expect(await runCommand(["--", "sh", "-c", "exit 3"], deps)).toBe(3)
      const err = deps.err.text()
      expect(err.match(/warning:/g)).toHaveLength(1)
      expect(err).toContain("mehen: warning: .env, .env.local are next to this run: Bun, Next.js, Vite, dotenv and others load them by themselves, so sh can see their plaintext values instead of the vault's\n")
      expect(err).toContain("  run:  mehen adopt file .env\n  run:  mehen adopt file .env.local\n")
      expect(err).not.toContain(".env.example")
      expect(err).not.toContain("OPENAI_API_KEY=old")
      // From a subfolder, the manifest's folder and the working folder are both checked.
      const sub = join(dir, "app")
      mkdirSync(sub)
      writeFileSync(join(sub, ".env.production"), "A=1\n")
      const nested = fakeDeps(apiWith([{ name: "OPENAI_API_KEY", delivery: "plain", value: "x" }]), sub)
      expect(await runCommand(["--", "true"], nested)).toBe(0)
      expect(nested.err.text()).toContain(`mehen: warning: ${join(dir, ".env")}, ${join(dir, ".env.local")}, .env.production are next to this run`)
    } finally {
      removeDir(dir)
    }
  })

  test("a run with placeholders whose child never reached an intercept host warns once that it may have bypassed the proxy; plain and leased runs do not", async () => {
    const placed = vars({ OPENAI_API_KEY: { name: "OPENAI_API_KEY", delivery: "placeholder", value: placeholder, item: "openai-personal", hosts: ["api.openai.com"] } })
    const deps = fakeDeps(apiWith(placed, { interceptHosts: ["api.openai.com"] }), repo)
    expect(await withTimeout(runCommand(["--", "sh", "-c", "exit 1"], deps), 15_000, "mehen run")).toBe(1)
    const err = deps.err.text()
    expect(err.match(/warning:/g)).toHaveLength(1)
    expect(err).toContain("mehen: warning: no connection to api.openai.com came through mehen's local relay. If sh called it, it bypassed the proxy (some HTTP clients ignore HTTPS_PROXY) and the API saw only the placeholder\n")
    expect(err).toContain("  next: Check that the program's HTTP client uses HTTPS_PROXY and the run's CA: https://docs.mehen.dev/guides/run-compatibility\n")
    const lease = fakeDeps(apiWith(vars({ DATABASE_URL: { name: "DATABASE_URL", delivery: "lease", value: "postgres://u:p@db/x", item: "dev-db" } })), repo)
    expect(await runCommand(["--", "true"], lease)).toBe(0)
    expect(lease.err.text()).not.toContain("warning:")
    const baseUrl = fakeDeps(apiWith(vars({ OPENAI_BASE_URL: { name: "OPENAI_BASE_URL", delivery: "base-url", value: "https://api.openai.com/v1", item: "openai-personal" } })), repo)
    expect(await withTimeout(runCommand(["--", "true"], baseUrl), 15_000, "mehen run")).toBe(0)
    expect(baseUrl.err.text()).not.toContain("warning:")
  })

  test("with placeholders, a Node too old for NODE_USE_ENV_PROXY on the child's PATH is named with the minimum; a current one, or no placeholders, is not", async () => {
    const placed = vars({ OPENAI_API_KEY: { name: "OPENAI_API_KEY", delivery: "placeholder", value: placeholder, item: "openai-personal", hosts: ["api.openai.com"] } })
    const nodeAt = (version: string) => {
      const bin = tempDir("mehen-run-node-")
      writeFileSync(join(bin, "node"), `#!/bin/sh\nif [ "$1" = "--version" ]; then env > "${bin}/probe-env"; echo ${version}; fi\nexit 0\n`)
      chmodSync(join(bin, "node"), 0o755)
      return bin
    }
    const old = nodeAt("v20.11.0")
    const current = nodeAt("v24.5.0")
    try {
      const withLease = [...placed.filter((v) => v.name !== "DATABASE_URL"), { name: "DATABASE_URL", delivery: "lease", value: "postgres://app:probe-lease-pw@db/x", item: "dev-db" } satisfies RunVar]
      const deps = fakeDeps(apiWith(withLease, { interceptHosts: ["api.openai.com"] }), repo, { PATH: `${old}:/usr/bin:/bin` })
      expect(await withTimeout(runCommand(["--", "node", "app.js"], deps), 15_000, "mehen run")).toBe(0)
      // The version check is its own process: the placeholder and the proxy, never a leased value.
      const probed = readFileSync(join(old, "probe-env"), "utf8")
      expect(probed).toContain(`OPENAI_API_KEY=${placeholder}`)
      expect(probed).not.toContain("probe-lease-pw")
      expect(probed).not.toContain("DATABASE_URL=")
      expect(deps.err.text()).toContain("mehen: warning: Node v20.11.0 ignores NODE_USE_ENV_PROXY, so its requests skip mehen's local relay: a placeholder they send goes straight to the API, which answers 401\n  next: Use Node 22.21.0 or later on 22, or 24.5.0 or later.")
      const fine = fakeDeps(apiWith(placed, { interceptHosts: ["api.openai.com"] }), repo, { PATH: `${current}:/usr/bin:/bin` })
      expect(await withTimeout(runCommand(["--", "node", "app.js"], fine), 15_000, "mehen run")).toBe(0)
      expect(fine.err.text()).not.toContain("Node v")
      const plain = fakeDeps(apiWith(vars()), repo, { PATH: `${old}:/usr/bin:/bin` })
      expect(await runCommand(["--", "node", "app.js"], plain)).toBe(0)
      expect(plain.err.text()).not.toContain("Node v")
    } finally {
      removeDir(old)
      removeDir(current)
    }
  })

  test("a command that cannot start still ends the run", async () => {
    const api = apiWith(vars())
    const deps = fakeDeps(api, repo)
    expect(await runCommand(["mehen-no-such-command-anywhere"], deps)).toBe(EXIT.error)
    expect(deps.err.text()).toContain("could not start mehen-no-such-command-anywhere")
    expect(api.called("DELETE", "/v1/runs/run_test1")).toBe(true)
  })

  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    test(`${signal} is forwarded to the child, the run is ended and the CA file removed`, async () => {
      const dir = tempDir("mehen-signal-test-")
      writeManifest(dir, 'project = "prj_test"\ndefault_env = "dev"\n[vars]\nOPENAI_API_KEY = "vault"\n')
      const harness = Bun.spawn([process.execPath, join(import.meta.dir, "testdata", "signal-harness.ts"), dir], { stdout: "pipe", stderr: "pipe", timeout: 50_000 })
      let childPid = 0
      let text = ""
      try {
        const reader = harness.stdout.getReader()
        await withTimeout(
          (async () => {
            while (!text.includes("child up")) {
              const { done, value } = await reader.read()
              if (done) throw new Error(`harness ended early: ${text}`)
              text += new TextDecoder().decode(value)
            }
          })(),
          30_000,
          "child start",
        )
        const [, caPath = "", pid = "0"] = text.match(/child up (\S+) (\d+)/) ?? []
        childPid = Number(pid)
        expect(existsSync(caPath)).toBe(true)
        harness.kill(signal)
        try {
          await withTimeout(harness.exited, 20_000, "harness exit")
          await withTimeout(
            (async () => {
              for (let chunk = await reader.read(); !chunk.done; chunk = await reader.read()) text += new TextDecoder().decode(chunk.value)
            })(),
            5_000,
            "harness output",
          )
        } catch (error) {
          harness.kill("SIGKILL")
          const stderr = await withTimeout(new Response(harness.stderr).text(), 2_000, "harness stderr").catch(() => "(unread)")
          throw new Error(`${error instanceof Error ? error.message : String(error)}; harness exit ${harness.exitCode} signal ${harness.signalCode}; stdout ${JSON.stringify(text)}; stderr ${JSON.stringify(stderr)}`)
        }
        expect(text).toContain(`child got ${signal}`)
        expect(text).toContain("vault: run_test1 ended")
        expect(text).toContain("mehen exit 42")
        expect(harness.exitCode).toBe(42)
        // Stopped before anything called the API: no bypass warning.
        expect(await withTimeout(new Response(harness.stderr).text(), 5_000, "harness stderr")).not.toContain("came through mehen's local relay")
        expect(existsSync(caPath)).toBe(false)
      } finally {
        harness.kill("SIGKILL")
        // The child is in its own process group: a failed run must not leave it behind.
        if (childPid > 0) {
          try {
            process.kill(-childPid, "SIGKILL")
          } catch {
            // Already gone.
          }
        }
        removeDir(dir)
      }
    }, 60_000)
  }
})

describe("mehen run --item", () => {
  let bare: string

  beforeAll(() => {
    bare = tempDir("mehen-run-adhoc-")
  })

  afterAll(() => {
    if (bare !== undefined) removeDir(bare)
  })

  function describing(answers: Record<string, () => unknown>): FakeVaultApi {
    const api = new FakeVaultApi()
    for (const [slug, answer] of Object.entries(answers)) api.on("GET", `/v1/items/${slug}`, answer)
    return api
  }

  const curl = (out: string, auth = '-H "Authorization: Bearer $OPENAI_API_KEY"') => ["sh", "-c", `curl -sS --max-time 10 ${auth} https://api.openai.com/v1/models > ${out}`]

  test("with no mehen.toml: the item's variable holds a stand-in, each request to its host is an item-mode relay call, and no vault run is made", async () => {
    const api = describing({ openai: () => itemDescription() })
    const deps = fakeDeps(api, bare)
    const out = join(bare, "models.json")
    const envOut = join(bare, "key.txt")
    const code = await withTimeout(runCommand(["--item", "openai", "--", "sh", "-c", `printf %s "$OPENAI_API_KEY" > ${envOut}; ${curl(out)[2]}`], deps), 20_000, "mehen run --item")
    expect(code).toBe(0)
    const standIn = readFileSync(envOut, "utf8")
    expect(standIn).toMatch(/^sk-proj-jvph[0-9A-Za-z]{24}$/)
    expect(api.relayCalls).toHaveLength(1)
    expect(api.relayCalls[0]).toMatchObject({ item: "openai", method: "GET", url: "https://api.openai.com/v1/models" })
    expect(api.relayCalls[0]?.run).toBeUndefined()
    expect(api.relayCalls[0]?.headers).toContainEqual(["Authorization", `Bearer ${standIn}`])
    expect(JSON.parse(readFileSync(out, "utf8")).echoed.item).toBe("openai")
    expect(api.calls.map((c) => `${c.method} ${c.path}`)).toEqual(["GET /v1/items/openai"])
    const err = deps.err.text()
    expect(err).toBe("mehen: ad hoc openai=OPENAI_API_KEY (each request is a fetch)\n")
  })

  test("the run CA permits exactly the hosts the vault returned, a wildcard as the subtree it admits", async () => {
    const api = describing({ azure: () => itemDescription({ slug: "azure", provider: null, binding: { hosts: ["*.openai.azure.com", "api.example.net"] } }) })
    const out = join(bare, "constraints.txt")
    const code = await withTimeout(runCommand(["--item", "azure=AZURE_KEY", "--", "sh", "-c", `openssl x509 -in "$NODE_EXTRA_CA_CERTS" -noout -ext nameConstraints > ${out}`], fakeDeps(api, bare)), 20_000, "mehen run --item")
    expect(code).toBe(0)
    const text = readFileSync(out, "utf8")
    expect(text).toContain("Permitted:")
    expect(text).toContain("DNS:.openai.azure.com")
    expect(text).toContain("DNS:api.example.net")
    expect(text.match(/DNS:/g)).toHaveLength(2)
    expect(text).toContain("Excluded:")
  })

  test("a request to the item's host without the stand-in is refused by the relay and never reaches the vault", async () => {
    const api = describing({ openai: () => itemDescription() })
    const out = join(bare, "refused.json")
    expect(await withTimeout(runCommand(["--item", "openai", "--", ...curl(out, "")], fakeDeps(api, bare)), 20_000, "mehen run --item")).toBe(0)
    expect(JSON.parse(readFileSync(out, "utf8"))).toMatchObject({ error: "forbidden" })
    expect(api.relayCalls).toHaveLength(0)
  })

  test("what the vault refuses for the item, a credential behind a protected environment included, reaches the program as vault_fetch's refusal", async () => {
    const api = describing({ openai: () => itemDescription() })
    api.relayHandler = () => {
      throw new VaultApiError(404, { error: "not_found", message: 'No credential called "openai".' })
    }
    const out = join(bare, "protected.json")
    expect(await withTimeout(runCommand(["--item", "openai", "--", ...curl(out)], fakeDeps(api, bare)), 20_000, "mehen run --item")).toBe(0)
    expect(JSON.parse(readFileSync(out, "utf8"))).toEqual({ error: "not_found", message: 'No credential called "openai".' })
    expect(api.relayCalls).toHaveLength(1)
  })

  test("a run whose program never reached the item's host gets the bypass warning; the stand-in replaces the shell's value, with a warning", async () => {
    const api = describing({ openai: () => itemDescription() })
    const deps = fakeDeps(api, bare, { OPENAI_API_KEY: "sk-from-the-shell" })
    expect(await withTimeout(runCommand(["--item", "openai", "--", "true"], deps), 20_000, "mehen run --item")).toBe(0)
    const err = deps.err.text()
    expect(err).toContain("mehen: warning: ignoring OPENAI_API_KEY from your shell; --item openai sets it\n")
    expect(err).toContain("mehen: warning: no connection to api.openai.com came through mehen's local relay.")
    expect(err).not.toContain("sk-from-the-shell")
  })

  test("refused before anything starts: a lease-only credential, one the vault will not show this machine, and a vault too old to describe it", async () => {
    const marker = join(bare, "started")
    const cases: [string, () => unknown, number, string][] = [
      ["db", () => itemDescription({ slug: "db", binding: { hosts: [LEASE_ONLY_HOST] }, injection: null }), EXIT.refused, "mehen: --item db: it is a lease-only credential"],
      ["mine", () => { throw new VaultApiError(404, { error: "not_found", message: "No credential." }) }, EXIT.error, "mehen: --item mine: the vault does not let this machine use mine outside a project"],
      ["openai", () => ({ slug: "openai", provider: "openai", status: "active" }), EXIT.error, "mehen: --item openai: this vault cannot serve an ad hoc run"],
    ]
    for (const [slug, answer, code, line] of cases) {
      const api = describing({ [slug]: answer })
      const deps = fakeDeps(api, bare)
      expect(await runCommand(["--item", `${slug}=K`, "--", "sh", "-c", `touch ${marker}`], deps), slug).toBe(code)
      expect(deps.err.text(), slug).toContain(line)
      expect(deps.err.text(), slug).toContain("  next: ")
      expect(existsSync(marker), slug).toBe(false)
      expect(api.relayCalls).toHaveLength(0)
    }
  })

  test("usage errors before the vault is called: a bad variable name, the same item twice, or --env, --approval or --service with no project", async () => {
    for (const argv of [["--item", "openai=1BAD", "true"], ["--item", "openai", "--item", "openai=B", "true"]]) {
      const api = new FakeVaultApi()
      expect(await runCommand(argv, fakeDeps(api, bare)), argv.join(" ")).toBe(EXIT.usage)
      expect(api.calls).toHaveLength(0)
    }
    for (const flag of [["--env", "dev"], ["--approval", "apr_1"], ["--service"]]) {
      const api = describing({ openai: () => itemDescription() })
      const deps = fakeDeps(api, bare)
      expect(await runCommand(["--item", "openai", ...flag, "true"], deps)).toBe(EXIT.usage)
      expect(deps.err.text()).toContain(`${flag[0]} needs a project, and there is no mehen.toml here`)
      expect(api.calls).toHaveLength(0)
    }
  })

  test("in a checkout with mehen.toml: the project's run goes on beside the item, and an item setting a declared variable is refused before any run", async () => {
    const api = apiWith(vars(), {}).on("GET", "/v1/items/github", () => itemDescription({ slug: "github", provider: "github-pat", binding: { hosts: ["api.github.com"] }, injection: { in: "header", name: "Authorization", format: "Bearer {token}" }, secretFields: [{ name: "token", prefix: "ghp_" }] }))
    const out = join(repo, "both.json")
    const deps = fakeDeps(api, repo)
    expect(await withTimeout(runCommand(["--item", "github", "--", "sh", "-c", `printf '%s %s' "$GITHUB_TOKEN" "$DATABASE_URL" > ${out}`], deps), 20_000, "mehen run --item in a project")).toBe(0)
    const [token, database] = readFileSync(out, "utf8").split(" ")
    expect(token).toMatch(/^ghp_jvph[0-9A-Za-z]{24}$/)
    expect(database).toBe("postgres://localhost/dev")
    expect(api.called("POST", "/v1/runs")).toBe(true)
    expect(api.called("DELETE", "/v1/runs/run_test1")).toBe(true)
    expect(deps.err.text()).toContain("mehen: ad hoc github=GITHUB_TOKEN (each request is a fetch)\n")

    const clash = apiWith(vars()).on("GET", "/v1/items/openai", () => itemDescription())
    const refused = fakeDeps(clash, repo)
    expect(await runCommand(["--item", "openai", "--", "true"], refused)).toBe(EXIT.usage)
    expect(refused.err.text()).toContain("--item openai sets OPENAI_API_KEY, which this checkout's mehen.toml also declares.")
    expect(clash.called("POST", "/v1/runs")).toBe(false)
  })

  test("an item bound to a host the project's run intercepts is refused, and the run is ended", async () => {
    const api = apiWith(vars({ OPENAI_API_KEY: { name: "OPENAI_API_KEY", delivery: "placeholder", value: placeholder, item: "openai-personal", hosts: ["api.openai.com"] } }), { interceptHosts: ["api.openai.com"] })
      .on("GET", "/v1/items/second", () => itemDescription({ slug: "second" }))
    const deps = fakeDeps(api, repo)
    expect(await runCommand(["--item", "second=SECOND_KEY", "--", "true"], deps)).toBe(EXIT.usage)
    expect(deps.err.text()).toContain("--item second is bound to api.openai.com, which this project's run already intercepts")
    expect(api.called("DELETE", "/v1/runs/run_test1")).toBe(true)
  })
})

describe("runHelp", () => {
  test("is mehen run's own --help, not the child's", () => {
    expect(runHelp(["--help"])).toBe(RUN_USAGE)
    expect(runHelp(["--env", "prod", "-h"])).toBe(RUN_USAGE)
    expect(runHelp(["--", "bun", "--help"])).toBeNull()
    expect(runHelp(["bun", "--help"])).toBeNull()
    expect(runHelp(["--env", "--help", "bun"])).toBeNull()
  })

  test("runCommand prints the usage and exits 0 without calling the vault", async () => {
    const api = apiWith(vars())
    const deps = fakeDeps(api, repo)
    expect(await runCommand(["--help"], deps)).toBe(EXIT.ok)
    expect(deps.out.text()).toBe(`usage: ${RUN_USAGE}\n`)
    expect(api.calls).toHaveLength(0)
  })
})

describe("the run log", () => {
  function logDir(): { dir: string; path: string } {
    const dir = tempDir("mehen-run-log-")
    return { dir, path: join(dir, RUN_LOG_FILE) }
  }

  test("a finished run adds one line, with no command line, and a failing child's exit", async () => {
    const { dir, path } = logDir()
    try {
      const deps = { ...fakeDeps(apiWith(vars()), repo), runLog: path }
      expect(await runCommand(["--", "sh", "-c", "exit 0", "argv-SENTINEL-word"], deps)).toBe(0)
      expect(await runCommand(["--service", "--", "sh", "-c", "exit 7"], { ...fakeDeps(apiWith(vars()), repo), runLog: path })).toBe(7)
      const text = readFileSync(path, "utf8")
      expect(text).not.toContain("SENTINEL")
      expect(text).not.toContain("exit 0")
      expect(statSync(path).mode & 0o777).toBe(0o600)
      const lines = text.trimEnd().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>)
      expect(lines).toHaveLength(2)
      expect(Object.keys(lines[0] ?? {}).sort()).toEqual(["at", "endedAt", "env", "exit", "project", "root", "service"])
      expect(lines.map((l) => [l.exit, l.root, l.project, l.env, l.service])).toEqual([[0, repo, "prj_test", "dev", false], [7, repo, "prj_test", "dev", true]])
      expect(await readRunLog(path)).toHaveLength(2)
    } finally {
      removeDir(dir)
    }
  })

  test("a child ended by a SIGTERM mehen run passed on is logged with the signal and forwarded, and counts as clean; a crash does not", async () => {
    const { dir, path } = logDir()
    try {
      const started = join(dir, "started")
      const running = runCommand(["--", "sh", "-c", `touch ${started}; sleep 5`], { ...fakeDeps(apiWith(vars()), repo), runLog: path })
      for (let i = 0; i < 250 && !existsSync(started); i++) await Bun.sleep(20)
      // What a service manager or a parent shell sends to mehen run itself.
      process.emit("SIGTERM")
      await withTimeout(running, 4000, "the run to end on the passed-on SIGTERM")
      expect(await runCommand(["--", "sh", "-c", "kill -SEGV $$"], { ...fakeDeps(apiWith(vars()), repo), runLog: path })).toBe(128 + 11)
      const entries = await readRunLog(path)
      expect(entries.map((e) => [e.exit, e.signal, e.forwarded])).toEqual([["SIGTERM", "SIGTERM", true], ["SIGSEGV", undefined, undefined]])
      expect(entries.map(cleanRun)).toEqual([true, false])
    } finally {
      removeDir(dir)
    }
  })

  test("over 1 MiB, the log keeps its newest half", async () => {
    const { dir, path } = logDir()
    try {
      const old = { at: "2026-10-01T10:00:00.000Z", endedAt: "2026-10-01T10:00:01.000Z", exit: 0, root: "/Users/sam/code/old", project: "prj_old", env: "dev", service: false }
      const line = `${JSON.stringify(old)}\n`
      writeFileSync(path, line.repeat(Math.ceil(RUN_LOG_MAX_BYTES / line.length) + 10), { mode: 0o600 })
      expect(await runCommand(["--", "true"], { ...fakeDeps(apiWith(vars()), repo), runLog: path })).toBe(0)
      const size = statSync(path).size
      expect(size).toBeLessThanOrEqual(RUN_LOG_MAX_BYTES / 2)
      expect(size).toBeGreaterThan(RUN_LOG_MAX_BYTES / 2 - 2 * line.length)
      const entries = await readRunLog(path)
      expect(entries.at(-1)).toMatchObject({ root: repo, exit: 0 })
      expect(entries.slice(0, -1).every((e) => e.root === "/Users/sam/code/old")).toBe(true)
    } finally {
      removeDir(dir)
    }
  })

  test("a link at the log's path is refused, with one warning, and the run's exit is unchanged", async () => {
    const { dir, path } = logDir()
    try {
      const target = join(dir, "elsewhere")
      writeFileSync(target, "")
      symlinkSync(target, path)
      const deps = { ...fakeDeps(apiWith(vars()), repo), runLog: path }
      expect(await runCommand(["--", "sh", "-c", "exit 3"], deps)).toBe(3)
      expect(readFileSync(target, "utf8")).toBe("")
      expect(deps.err.text().match(/warning: could not add this run/g)).toHaveLength(1)
      expect(readRunLog(path)).rejects.toThrow()
    } finally {
      removeDir(dir)
    }
  })
})

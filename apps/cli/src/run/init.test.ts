import { describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { EXIT, type Project, type ProjectBinding } from "@mehen/protocol/api"
import { VaultApiError } from "../vault-api.ts"
import { FakeVaultApi, fakeDeps, git, removeDir, tempDir } from "./fake-vault-api.ts"
import { INIT_USAGE, initCommand, slugFrom } from "./init.ts"
import { parseManifest } from "./manifest.ts"

const LOOKUP = `/v1/projects?remote=${encodeURIComponent("github.com/example/my_repo")}`
const BOUND: ProjectBinding = {
  id: "prj_bound1",
  slug: "my-repo",
  defaultEnv: "dev",
  environments: [
    { name: "dev", protected: false, variables: ["LOG_LEVEL", "OPENAI_API_KEY"] },
    { name: "prod", protected: true, variables: ["DATABASE_URL", "OPENAI_API_KEY"] },
  ],
}

function projectApi(bound: ProjectBinding | null = null): FakeVaultApi {
  return new FakeVaultApi().on("GET", LOOKUP, () => {
    if (bound === null) throw new VaultApiError(404, { error: "not_found", message: "No such object." })
    return bound
  }).on("POST", "/v1/projects", (body) => {
    const input = body as { slug: string; defaultEnv: string; remote: string | null; environments: { name: string }[] }
    const project: Project = {
      id: "prj_new1",
      slug: input.slug,
      remotes: input.remote === null ? [] : [input.remote],
      defaultEnv: input.defaultEnv,
      environments: input.environments.map((e) => ({ name: e.name, protected: e.name === "prod", fences: [] })),
      vars: [],
    }
    return project
  })
}

describe("mehen init", () => {
  test("creates the project with the remote and writes mehen.toml at the worktree root", async () => {
    const repo = tempDir("mehen-init-test-")
    try {
      git(repo, "init", "-q")
      git(repo, "remote", "add", "origin", "git@github.com:Example/My_Repo.git")
      mkdirSync(join(repo, "sub"))
      const api = projectApi()
      const deps = fakeDeps(api, join(repo, "sub"))
      expect(await initCommand(["--env", "dev", "--env", "prod"], deps)).toBe(EXIT.ok)
      expect(api.calls[1]?.body).toEqual({
        slug: "my-repo",
        remote: "github.com/example/my_repo",
        environments: [
          { name: "dev", protected: false },
          { name: "prod", protected: false },
        ],
        defaultEnv: "dev",
      })
      const manifest = parseManifest(join(repo, "mehen.toml"), readFileSync(join(repo, "mehen.toml"), "utf8"))
      expect(manifest).toMatchObject({ project: "prj_new1", workspace: "tn_test00000001", vault: "https://vault.test", defaultEnv: "dev", vars: [] })
      expect(readFileSync(join(repo, "mehen.toml"), "utf8")).toContain('workspace = "tn_test00000001"  # workspace Test Space (test-space); the id prefix is historical\nvault = "https://vault.test"\n')
      expect(deps.out.text()).toContain("created project my-repo (prj_new1) bound to github.com/example/my_repo")
      expect(api.calls.map((c) => `${c.method} ${c.path}`)).toEqual([`GET ${LOOKUP}`, "POST /v1/projects"])
    } finally {
      removeDir(repo)
    }
  })

  test("a checkout whose remote is already a project binds to it: mehen.toml names it with every variable it defines, and nothing is created", async () => {
    const repo = tempDir("mehen-init-test-")
    try {
      git(repo, "init", "-q")
      git(repo, "remote", "add", "origin", "https://github.com/Example/My_Repo.git")
      const api = projectApi(BOUND)
      const deps = fakeDeps(api, repo)
      expect(await initCommand([], deps)).toBe(EXIT.ok)
      expect(api.called("POST", "/v1/projects")).toBe(false)
      const path = join(repo, "mehen.toml")
      expect(parseManifest(path, readFileSync(path, "utf8"))).toMatchObject({
        project: "prj_bound1",
        workspace: "tn_test00000001",
        vault: "https://vault.test",
        defaultEnv: "dev",
        vars: ["DATABASE_URL", "LOG_LEVEL", "OPENAI_API_KEY"].map((name) => ({ name, source: "vault" })),
      })
      expect(deps.out.text()).toBe(`bound this checkout to project my-repo (prj_bound1); wrote ${path}\n`)

      // --json says so with bound: true, and --slug naming the bound project is the same bind.
      const worktree = tempDir("mehen-init-test-")
      try {
        git(worktree, "init", "-q")
        git(worktree, "remote", "add", "origin", "git@github.com:example/my_repo.git")
        const json = fakeDeps(api, worktree)
        expect(await initCommand(["--json", "--slug", "my-repo"], json)).toBe(EXIT.ok)
        expect(JSON.parse(json.out.text())).toEqual({
          project: "prj_bound1",
          slug: "my-repo",
          path: join(worktree, "mehen.toml"),
          remote: "github.com/example/my_repo",
          defaultEnv: "dev",
          next: { say: "commit mehen.toml so every checkout and worktree of this repo gets it, then mehen env check" },
          bound: true,
        })
        expect(api.called("POST", "/v1/projects")).toBe(false)
      } finally {
        removeDir(worktree)
      }
    } finally {
      removeDir(repo)
    }
  })

  test("--slug naming another project than the one the remote is bound to is refused, naming the bound project, and writes nothing", async () => {
    const repo = tempDir("mehen-init-test-")
    try {
      git(repo, "init", "-q")
      git(repo, "remote", "add", "origin", "git@github.com:Example/My_Repo.git")
      const api = projectApi(BOUND)
      const deps = fakeDeps(api, repo)
      expect(await initCommand(["--json", "--slug", "other"], deps)).toBe(EXIT.error)
      expect(JSON.parse(deps.out.text())).toEqual({
        error: "failed",
        message: "this checkout's remote github.com/example/my_repo is already project my-repo (prj_bound1); mehen init does not create other beside it",
        next: { say: "Run mehen init without --slug to bind this checkout to project my-repo.", command: "mehen init" },
      })
      expect(existsSync(join(repo, "mehen.toml"))).toBe(false)
      expect(api.called("POST", "/v1/projects")).toBe(false)
    } finally {
      removeDir(repo)
    }
  })

  test("--env when the remote is already a project is refused, naming the project and the project page, and writes nothing", async () => {
    const repo = tempDir("mehen-init-test-")
    try {
      git(repo, "init", "-q")
      git(repo, "remote", "add", "origin", "git@github.com:Example/My_Repo.git")
      const api = projectApi(BOUND)
      const deps = fakeDeps(api, repo)
      expect(await initCommand(["--json", "--env", "staging"], deps)).toBe(EXIT.error)
      expect(JSON.parse(deps.out.text())).toEqual({
        error: "failed",
        message: "this checkout's remote github.com/example/my_repo is already project my-repo (prj_bound1); mehen init does not change its environments",
        next: { say: "Run mehen init without --env to bind this checkout to project my-repo; its environments are changed on the project page.", command: "mehen init" },
      })
      expect(existsSync(join(repo, "mehen.toml"))).toBe(false)
      expect(api.called("POST", "/v1/projects")).toBe(false)
    } finally {
      removeDir(repo)
    }
  })

  test("never overwrites an existing mehen.toml, even when the remote is a project", async () => {
    const repo = tempDir("mehen-init-test-")
    try {
      git(repo, "init", "-q")
      git(repo, "remote", "add", "origin", "git@github.com:Example/My_Repo.git")
      writeFileSync(join(repo, "mehen.toml"), 'project = "prj_old"\n')
      const api = projectApi(BOUND)
      expect(await initCommand([], fakeDeps(api, repo))).toBe(EXIT.error)
      expect(api.calls).toHaveLength(0)
      expect(readFileSync(join(repo, "mehen.toml"), "utf8")).toBe('project = "prj_old"\n')
    } finally {
      removeDir(repo)
    }
  })

  test("a vault from before the lookup (405) is an unbound remote: the project is created as before", async () => {
    const repo = tempDir("mehen-init-test-")
    try {
      git(repo, "init", "-q")
      git(repo, "remote", "add", "origin", "git@github.com:Example/My_Repo.git")
      const api = projectApi().on("GET", LOOKUP, () => {
        throw new VaultApiError(405, { error: "bad_request", message: "Method not allowed." })
      })
      expect(await initCommand([], fakeDeps(api, repo))).toBe(EXIT.ok)
      expect(api.called("POST", "/v1/projects")).toBe(true)
    } finally {
      removeDir(repo)
    }
  })

  test("--json prints the project and the absolute mehen.toml path as one object, and the same report", async () => {
    const parent = tempDir("mehen-init-test-")
    const dir = join(parent, "plain")
    mkdirSync(dir)
    try {
      const api = projectApi()
      const deps = fakeDeps(api, dir)
      expect(await initCommand(["--json", "--slug", "demo"], deps)).toBe(EXIT.ok)
      expect(JSON.parse(deps.out.text())).toEqual({
        project: "prj_new1",
        slug: "demo",
        path: join(realpathSync(dir), "mehen.toml"),
        remote: null,
        defaultEnv: "dev",
        next: { say: "declare variables under [vars] in mehen.toml, commit it, then mehen env set <NAME> --env dev --item <slug>" },
        warning: "this directory has no origin remote, so the project is not bound to a repo",
      })
      expect(deps.err.text()).toBe("")
      expect(parseManifest(join(dir, "mehen.toml"), readFileSync(join(dir, "mehen.toml"), "utf8")).project).toBe("prj_new1")
      const again = fakeDeps(api, dir)
      expect(await initCommand(["--json"], again)).toBe(EXIT.error)
      expect(JSON.parse(again.out.text())).toMatchObject({ error: "failed", message: `${join(realpathSync(dir), "mehen.toml")} already exists; mehen init does not overwrite it` })
      const usage = fakeDeps(api, dir)
      expect(await initCommand(["--json", "--slug", "Bad Slug"], usage)).toBe(EXIT.usage)
      expect(JSON.parse(usage.out.text())).toMatchObject({ error: "usage" })
    } finally {
      removeDir(parent)
    }
  })

  test("refuses to overwrite an existing mehen.toml, before creating anything", async () => {
    const repo = tempDir("mehen-init-test-")
    try {
      git(repo, "init", "-q")
      writeFileSync(join(repo, "mehen.toml"), 'project = "prj_old"\n')
      const api = projectApi()
      const deps = fakeDeps(api, repo)
      expect(await initCommand(["--slug", "demo"], deps)).toBe(EXIT.error)
      expect(deps.err.text()).toContain("already exists; mehen init does not overwrite it")
      expect(api.calls).toHaveLength(0)
      expect(readFileSync(join(repo, "mehen.toml"), "utf8")).toBe('project = "prj_old"\n')
    } finally {
      removeDir(repo)
    }
  })

  test("outside a repo: the directory name as slug, dev as the only environment, no remote", async () => {
    const parent = tempDir("mehen-init-test-")
    const dir = join(parent, "Side Project")
    mkdirSync(dir)
    try {
      const api = projectApi()
      const deps = fakeDeps(api, dir)
      expect(await initCommand([], deps)).toBe(EXIT.ok)
      expect(api.calls[0]?.body).toEqual({ slug: "side-project", remote: null, environments: [{ name: "dev", protected: false }], defaultEnv: "dev" })
      expect(deps.err.text()).toBe(
        "mehen: warning: this directory has no origin remote, so the project is not bound to a repo\n  next: declare variables under [vars] in mehen.toml, commit it, then mehen env set <NAME> --env dev --item <slug>\n",
      )
      // On a TTY the mehen: prefix, warning: and the next: label are styled; the words are the same.
      const coloured = fakeDeps(projectApi(), tempDir("mehen-init-colour-"), { FORCE_COLOR: "1" })
      try {
        expect(await initCommand([], coloured)).toBe(EXIT.ok)
        expect(coloured.err.text()).toBe(
          "\u001b[2mmehen:\u001b[0m \u001b[31mwarning:\u001b[0m this directory has no origin remote, so the project is not bound to a repo\n  \u001b[2mnext:\u001b[0m declare variables under [vars] in mehen.toml, commit it, then mehen env set <NAME> --env dev --item <slug>\n",
        )
      } finally {
        removeDir(coloured.cwd as string)
      }
    } finally {
      removeDir(parent)
    }
  })

  test("a project slug or id from the vault with an escape or a hidden character is spelled out", async () => {
    const parent = tempDir("mehen-init-test-")
    const dir = join(parent, "plain")
    mkdirSync(dir)
    try {
      const api = new FakeVaultApi().on("POST", "/v1/projects", () => ({ id: "prj_\u001b[31mred", slug: "plain\u200b", remotes: [], defaultEnv: "dev", environments: [{ name: "dev", protected: false, fences: [] }], vars: [] }))
      const deps = fakeDeps(api, dir)
      expect(await initCommand([], deps)).toBe(EXIT.ok)
      expect(deps.out.text()).not.toContain("\u001b")
      expect(deps.out.text()).toContain("created project plain[ZWSP U+200B] (prj_\\u001B[31mred) bound to no remote")
    } finally {
      removeDir(parent)
    }
  })

  test("bad slugs and environment names are usage errors", async () => {
    const dir = tempDir("mehen-init-test-")
    try {
      const api = projectApi()
      expect(await initCommand(["--slug", "Bad Slug"], fakeDeps(api, dir))).toBe(EXIT.usage)
      expect(await initCommand(["--slug", "ok-slug", "--env", "Prod!"], fakeDeps(api, dir))).toBe(EXIT.usage)
      expect(await initCommand(["stray"], fakeDeps(api, dir))).toBe(EXIT.usage)
      expect(api.calls).toHaveLength(0)
    } finally {
      removeDir(dir)
    }
  })

  test("--help prints the usage and exits 0 without creating anything", async () => {
    const fake = projectApi()
    const deps = fakeDeps(fake, tempDir("mehen-init-help-"))
    try {
      expect(await initCommand(["--help"], deps)).toBe(EXIT.ok)
      expect(deps.out.text()).toBe(`usage: ${INIT_USAGE}\n`)
      expect(fake.calls).toHaveLength(0)
    } finally {
      removeDir(deps.cwd as string)
    }
  })

  test("slugFrom", () => {
    expect(slugFrom("My_Repo")).toBe("my-repo")
    expect(slugFrom("123-app")).toBe("app")
    expect(slugFrom("--")).toBe("")
  })
})

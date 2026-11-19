import { describe, expect, test } from "bun:test"
import { chmodSync, mkdirSync } from "node:fs"
import { join } from "node:path"
import { CliError } from "../errors.ts"
import { CommandError } from "./deps.ts"
import { git, removeDir, tempDir, writeManifest } from "./fake-vault-api.ts"
import { findManifest, gitFacts, locateManifest, manifestWorkspace, normaliseRemote, parseManifest } from "./manifest.ts"

describe("normaliseRemote", () => {
  test.each([
    ["git@github.com:a/b.git", "github.com/a/b"],
    ["https://github.com/a/b", "github.com/a/b"],
    ["https://github.com/a/b.git/", "github.com/a/b"],
    ["ssh://git@github.com/a/b.git", "github.com/a/b"],
    ["ssh://git@github.com:22/a/b.git", "github.com/a/b"],
    ["https://user:token@GitHub.com/Example/Foo.git", "github.com/example/foo"],
    ["git://gitlab.example.com/group/sub/repo.git", "gitlab.example.com/group/sub/repo"],
  ])("%s becomes %s", (url, expected) => {
    expect(normaliseRemote(url)).toBe(expected)
  })

  test("no origin is no remote", () => {
    expect(normaliseRemote(null)).toBeNull()
  })

  test.each([["/srv/git/repo.git"], ["file:///srv/git/repo.git"], ["../sibling"], ["https://github.com/"]])("%s is no remote", (url) => {
    expect(normaliseRemote(url)).toBeNull()
  })
})

describe("manifest discovery", () => {
  test("a mehen.toml above the worktree root is ignored", () => {
    const outer = tempDir()
    try {
      writeManifest(outer, 'project = "prj_outer"\n')
      const repo = join(outer, "repo")
      mkdirSync(join(repo, "src", "deep"), { recursive: true })
      git(repo, "init", "-q")
      const facts = gitFacts(join(repo, "src", "deep"))
      expect(facts.root).toBe(repo)
      expect(findManifest(join(repo, "src", "deep"), facts.root)).toBeNull()
      expect(() => locateManifest(join(repo, "src", "deep"))).toThrow(CommandError)
    } finally {
      removeDir(outer)
    }
  })

  test("walks up to the nearest mehen.toml inside the worktree", () => {
    const repo = tempDir()
    try {
      git(repo, "init", "-q")
      writeManifest(repo, 'project = "prj_root"\n')
      mkdirSync(join(repo, "packages", "app", "src"), { recursive: true })
      writeManifest(join(repo, "packages", "app"), 'project = "prj_app"\n')
      expect(findManifest(join(repo, "packages", "app", "src"), repo)).toBe(join(repo, "packages", "app", "mehen.toml"))
      expect(locateManifest(join(repo, "packages")).manifest.project).toBe("prj_root")
    } finally {
      removeDir(repo)
    }
  })

  test("outside a repo only the current directory counts", () => {
    const outer = tempDir()
    try {
      writeManifest(outer, 'project = "prj_outer"\n')
      mkdirSync(join(outer, "child"))
      expect(findManifest(join(outer, "child"), null)).toBeNull()
      expect(findManifest(outer, null)).toBe(join(outer, "mehen.toml"))
    } finally {
      removeDir(outer)
    }
  })

  test("git facts: normalised origin and short head, null without them", () => {
    const repo = tempDir()
    try {
      git(repo, "init", "-q")
      expect(gitFacts(repo)).toEqual({ root: repo, remote: null, head: null })
      git(repo, "remote", "add", "origin", "git@github.com:example/foo.git")
      git(repo, "commit", "-q", "--allow-empty", "-m", "first")
      const facts = gitFacts(repo)
      expect(facts.remote).toBe("github.com/example/foo")
      expect(facts.head).toMatch(/^[0-9a-f]{7,}$/)
    } finally {
      removeDir(repo)
    }
  })
})

describe("parseManifest", () => {
  test('"vault" comes from the vault, anything else is a plain value', () => {
    const manifest = parseManifest("/x/mehen.toml", 'project = "prj_1"\ndefault_env = "dev"\n[vars]\nOPENAI_API_KEY = "vault"\nLOG_LEVEL = "info"\nPORT = 3000\n')
    expect(manifest).toEqual({
      path: "/x/mehen.toml",
      project: "prj_1",
      workspace: null,
      vault: null,
      defaultEnv: "dev",
      vars: [
        { name: "OPENAI_API_KEY", source: "vault" },
        { name: "LOG_LEVEL", source: "plain", value: "info" },
        { name: "PORT", source: "plain", value: "3000" },
      ],
    })
  })

  test("refuses a manifest without a project or with a bad variable", () => {
    expect(() => parseManifest("/x/mehen.toml", 'default_env = "dev"\n')).toThrow(/project/)
    expect(() => parseManifest("/x/mehen.toml", 'project = "p"\n[vars]\nA = ["x"]\n')).toThrow(/A must be/)
    expect(() => parseManifest("/x/mehen.toml", "project = \n")).toThrow(CommandError)
  })

  test("workspace is the workspace id and vault a canonical origin (design 6.5); both optional, neither guessed", () => {
    const bound = parseManifest("/x/mehen.toml", 'project = "prj_1"\nworkspace = "tn_8fQ2abcdef"  # workspace Northwind (northwind)\nvault = "https://app.mehen.dev/"\n')
    expect(bound).toMatchObject({ workspace: "tn_8fQ2abcdef", vault: "https://app.mehen.dev" })
    expect(parseManifest("/x/mehen.toml", 'project = "prj_1"\nworkspace = "tn_8fQ2abcdef"\n')).toMatchObject({ workspace: "tn_8fQ2abcdef", vault: null })
    expect(parseManifest("/x/mehen.toml", 'project = "prj_1"\nvault = "http://127.0.0.1:8787"\n').vault).toBe("http://127.0.0.1:8787")
    for (const bad of ['workspace = "northwind"', 'workspace = 7', 'vault = "https://user@app.mehen.dev"', 'vault = "https://app.mehen.dev/vault"', 'vault = "http://app.mehen.dev"', 'vault = "https://app.mehen.dev?x=1"', 'vault = "https://app.mehen.dev#x"', 'vault = 7']) {
      expect(() => parseManifest("/x/mehen.toml", `project = "prj_1"\n${bad}\n`)).toThrow(CommandError)
    }
  })
})

describe("manifestWorkspace", () => {
  test("the cwd's manifest as a selection hint: null without one; present but invalid or unreadable refuses (workspace_unbound), never a silent null", () => {
    const repo = tempDir()
    try {
      git(repo, "init", "-q")
      expect(manifestWorkspace(repo)).toBeNull()
      writeManifest(repo, 'project = "prj_1"\nworkspace = "tn_8fQ2abcdef"\nvault = "https://app.mehen.dev"\n')
      const sub = join(repo, "a", "b")
      mkdirSync(sub, { recursive: true })
      expect(manifestWorkspace(sub)).toEqual({ path: join(repo, "mehen.toml"), project: "prj_1", workspace: "tn_8fQ2abcdef", vault: "https://app.mehen.dev" })
      writeManifest(repo, 'project = "prj_1"\n')
      expect(manifestWorkspace(repo)).toEqual({ path: join(repo, "mehen.toml"), project: "prj_1", workspace: null, vault: null })
      // Present but broken: a local refusal that trusts nothing in the file, its origin included.
      for (const broken of ["project = \n", 'project = "prj_1"\nworkspace = "tn_8fQ2abcdef"\nvault = "https://app.mehen.dev/forbidden-path"\n', 'project = "prj_1"\nworkspace = "tn_8fQ2abcdef"\nvault = "https://user@app.mehen.dev"\n', 'project = "prj_1"\nworkspace = "not-an-id"\n', 'project = "prj_1"\n[vars]\nA = ["x"]\n', "{ not toml"]) {
        writeManifest(repo, broken)
        let thrown: unknown
        try { manifestWorkspace(repo) } catch (error) { thrown = error }
        expect(thrown).toBeInstanceOf(CliError)
        expect((thrown as CliError).code).toBe("workspace_unbound")
        expect((thrown as CliError).next).toMatchObject({ command: "mehen workspace bind" })
      }
      // Unreadable: the same refusal.
      writeManifest(repo, 'project = "prj_1"\n')
      chmodSync(join(repo, "mehen.toml"), 0o000)
      try {
        expect(() => manifestWorkspace(repo)).toThrow(CliError)
      } finally {
        chmodSync(join(repo, "mehen.toml"), 0o644)
      }
      expect(manifestWorkspace(repo)).toEqual({ path: join(repo, "mehen.toml"), project: "prj_1", workspace: null, vault: null })
    } finally {
      removeDir(repo)
    }
  })
})

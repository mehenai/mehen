import { afterEach, describe, expect, test } from "bun:test"
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { CliError } from "../errors.ts"
import { errorJson, errorLines } from "../output.ts"
import { tempDir } from "../testing/run-mehen.ts"
import { plainText, segments, styler } from "../tty.ts"
import { STOP_WAIT_MS, isServeOf, LAUNCHD_LABEL, type Runner, SYSTEMD_UNIT, ServiceError, defaultRunner, installService, serviceEnvironment, systemdState, launchdPath, launchdPlist, removeService, serviceKind, systemdPath, systemdUnit } from "./service.ts"
import { openerFor } from "./browser.ts"
import { agentLines, custodyLine, enrolContext, enrolLines, ensureUpGuardLevel, parseUpGuard, textLines, timedOut } from "./index.ts"
import { keyringAdvice } from "../local-vault.ts"

const plan = { kind: "launchd" as const, command: ["/Users/a/.local/bin/mehen", "serve", "--port", "7787", "--data", "/Users/a/Library/Application Support/Mehen/vault"], dataDir: "/Users/a/Library/Application Support/Mehen/vault", home: "/Users/a", logFile: "/Users/a/Library/Application Support/Mehen/vault/serve.log" }

describe("the launchd agent", () => {
  test("runs mehen serve at login, keeps it alive and makes its files private", () => {
    const plist = launchdPlist(plan)
    expect(plist).toContain(`<string>${LAUNCHD_LABEL}</string>`)
    expect(plist).toContain("<string>/Users/a/Library/Application Support/Mehen/vault</string>")
    expect(plist).toContain("<key>RunAtLoad</key>\n  <true/>")
    expect(plist).toContain("<key>KeepAlive</key>\n  <true/>")
    expect(plist).toContain("<key>Umask</key>\n  <integer>63</integer>")
    expect(launchdPath("/Users/a")).toBe("/Users/a/Library/LaunchAgents/dev.mehen.vault.plist")
  })

  test("escapes what XML would read as markup", () => {
    expect(launchdPlist({ ...plan, command: ["/opt/a&b/<mehen>", "serve"] })).toContain("<string>/opt/a&amp;b/&lt;mehen&gt;</string>")
  })
})

describe("the systemd user unit", () => {
  test("restarts mehen serve and runs it with a private umask and no new privileges", () => {
    const unit = systemdUnit({ ...plan, kind: "systemd", command: ["/home/a/.local/bin/mehen", "serve", "--port", "7787", "--data", "/home/a/.local/share/mehen/vault"] })
    expect(unit).toContain("ExecStart=/home/a/.local/bin/mehen serve --port 7787 --data /home/a/.local/share/mehen/vault")
    expect(unit).toContain("Restart=always")
    expect(unit).toContain("UMask=0077")
    expect(unit).toContain("NoNewPrivileges=yes")
    expect(unit).toContain("WantedBy=default.target")
  })

  test("waits for nothing on the network: the vault answers on loopback only", () => {
    const unit = systemdUnit({ ...plan, kind: "systemd" })
    expect(unit).not.toContain("network-online.target")
    expect(unit).not.toContain("After=")
  })

  test("quotes arguments with spaces and escapes what systemd would expand", () => {
    const unit = systemdUnit({ ...plan, kind: "systemd", command: ["/home/a/my bin/mehen", "serve", "--data", "/home/a/$HOME/100%"] })
    expect(unit).toContain('ExecStart="/home/a/my bin/mehen" serve --data "/home/a/$$HOME/100%%"')
  })

  test("lives under XDG_CONFIG_HOME when it is set", () => {
    expect(systemdPath("/home/a", {})).toBe("/home/a/.config/systemd/user/mehen-vault.service")
    expect(systemdPath("/home/a", { XDG_CONFIG_HOME: "/cfg" })).toBe("/cfg/systemd/user/mehen-vault.service")
  })
})

describe("the environment the service runs with", () => {
  const set = { MEHEN_HOME: "/Users/a/My Mehen", MEHEN_NO_AUTO_UPDATE: "1", PATH: "/usr/bin", MEHEN_VAULT_URL: "https://elsewhere.example" }

  test("carries MEHEN_HOME and MEHEN_NO_AUTO_UPDATE when set, and nothing else", () => {
    expect(serviceEnvironment(set)).toEqual({ MEHEN_HOME: "/Users/a/My Mehen", MEHEN_NO_AUTO_UPDATE: "1" })
    expect(serviceEnvironment({ MEHEN_HOME: "/h" })).toEqual({ MEHEN_HOME: "/h" })
    expect(serviceEnvironment({ MEHEN_HOME: "", PATH: "/usr/bin" })).toEqual({})
  })

  test("refuses a value with a line break rather than write a broken unit or plist", () => {
    expect(() => serviceEnvironment({ MEHEN_HOME: "/h\nExecStart=/bin/evil" })).toThrow(ServiceError)
  })

  test("launchd: EnvironmentVariables when set, escaped; no dict when unset", () => {
    const plist = launchdPlist({ ...plan, environment: serviceEnvironment({ ...set, MEHEN_HOME: "/Users/a/<home>&co" }) })
    expect(plist).toContain("<key>EnvironmentVariables</key>\n  <dict>\n    <key>MEHEN_HOME</key>\n    <string>/Users/a/&lt;home&gt;&amp;co</string>\n    <key>MEHEN_NO_AUTO_UPDATE</key>\n    <string>1</string>\n  </dict>")
    expect(launchdPlist(plan)).not.toContain("EnvironmentVariables")
    expect(launchdPlist({ ...plan, environment: serviceEnvironment({}) })).not.toContain("EnvironmentVariables")
  })

  test("systemd: one quoted Environment= per variable when set, with what systemd expands escaped; none when unset", () => {
    const unit = systemdUnit({ ...plan, kind: "systemd", environment: serviceEnvironment({ MEHEN_HOME: '/home/a/100% "mehen"\\x', MEHEN_NO_AUTO_UPDATE: "1" }) })
    expect(unit).toContain('Environment="MEHEN_HOME=/home/a/100%% \\"mehen\\"\\\\x"\n')
    expect(unit).toContain('Environment="MEHEN_NO_AUTO_UPDATE=1"\n')
    const bare = systemdUnit({ ...plan, kind: "systemd" })
    expect(bare).not.toContain("MEHEN_HOME")
    expect(bare.match(/^Environment=/gm)).toHaveLength(1)
  })
})

describe("which service", () => {
  test("MEHEN_SERVICE wins; a run from source gets a process; a Mac gets launchd", () => {
    expect(serviceKind({ MEHEN_SERVICE: "process" }, "darwin", true)).toBe("process")
    expect(serviceKind({}, "darwin", false)).toBe("process")
    expect(serviceKind({}, "darwin", true)).toBe("launchd")
    expect(serviceKind({}, "win32", true)).toBe("process")
  })
})

describe("the browser", () => {
  test("MEHEN_BROWSER names the opener, none turns it off, a desktop session uses xdg-open", () => {
    expect(openerFor({ MEHEN_BROWSER: "/usr/bin/firefox" }, "linux")).toEqual(["/usr/bin/firefox"])
    expect(openerFor({ MEHEN_BROWSER: "none" }, "darwin")).toBeNull()
    expect(openerFor({}, "darwin")).toEqual(["open"])
    expect(openerFor({ DISPLAY: ":0" }, "linux")).toEqual(["xdg-open"])
    expect(openerFor({}, "linux")).toBeNull()
  })
})

describe("the enrolment lines", () => {
  test("a person at the terminal gets the fingerprint the page asks them to complete", () => {
    expect(enrolLines("http://localhost:7787/w/home/e/ABCD", true, "M6W2 SXSX GAJJ 855Q")).toEqual(["Opened http://localhost:7787/w/home/e/ABCD", "This machine's fingerprint is M6W2 SXSX GAJJ 855Q. The page shows all but one of its groups: type the one it hides, then accept with your passkey.", "This carries on by itself."])
    expect(enrolLines("http://localhost:7787/w/home/e/ABCD", false, null)).toEqual(["Open http://localhost:7787/w/home/e/ABCD", "Accept this machine with your passkey.", "This carries on by itself."])
  })

  test("carries mehen enrol's coloured words and hidden group under the fingerprint, and none without one", () => {
    const s = styler(true)
    const words = [segments("  ", s.dim("words:  "), " puppy (violet)"), segments("  ", s.dim("hidden: "), " the page hides the third group, ", s.bold("PXT0"), ": type it on the page")]
    const lines = enrolLines("http://localhost:7787/w/home/e/ABCD", true, "5NZV DP67 PXT0 DB6E", words)
    expect(lines.map(plainText)).toEqual(["Opened http://localhost:7787/w/home/e/ABCD", "This machine's fingerprint is 5NZV DP67 PXT0 DB6E. The page shows all but one of its groups: type the one it hides, then accept with your passkey.", "  words:   puppy (violet)", "  hidden:  the page hides the third group, PXT0: type it on the page", "This carries on by itself."])
    expect(enrolLines("http://localhost:7787/w/home/e/ABCD", true, null, words)).toHaveLength(3)
  })
})

describe("the enrolment's context", () => {
  test("names the workspace from the local vault's own state, and null for a vault that does not give its id", () => {
    expect(enrolContext("http://localhost:7787", { id: "tn_home0000001", slug: "home", name: "Home" })).toEqual({ origin: "http://localhost:7787", workspace: { id: "tn_home0000001", slug: "home", name: "Home" }, device: null })
    expect(enrolContext("http://localhost:7787", { slug: "home", name: "Home" })).toEqual({ origin: "http://localhost:7787", workspace: null, device: null })
  })
})

describe("plain text", () => {
  test("the CLI's own text is one line per line break; lines given as a list stay one line each", () => {
    expect(textLines("Agents (restart them to pick Mehen up):\n  pi: wired")).toEqual(["Agents (restart them to pick Mehen up):", "  pi: wired"])
    expect(textLines(["Workspace: Home\nEvil (home)"])).toEqual(["Workspace: Home\nEvil (home)"])
  })
})

describe("a timeout", () => {
  const writer = { isTTY: false, write: () => true }

  test("says to run mehen up again and shows the local link, with no warning about it", () => {
    const error = timedOut("a passkey and a workspace", "http://localhost:7799/local/v1/start")
    const vault = { vaultUrl: "https://app.mehen.dev", workspaceSlug: null }
    const lines = errorLines(error, writer, { vaultUrl: vault }).map(plainText)
    expect(lines).toEqual(["mehen: Still waiting for a passkey and a workspace on http://localhost:7799/local/v1/start.", "next: Run `mehen up` again when it is done; it picks up where it stopped."])
    expect(errorJson(error, { vaultUrl: vault })).toMatchObject({ error: "timeout", message: "Still waiting for a passkey and a workspace on http://localhost:7799/local/v1/start.", next: { say: "Run `mehen up` again when it is done; it picks up where it stopped." } })
  })

  test("another command's link off the vault is still refused with the warning", () => {
    const off = new CliError("timeout", "Still waiting.", { say: "Wait.", url: "http://localhost:7799/local/v1/start" })
    const lines = errorLines(off, writer, { vaultUrl: { vaultUrl: "https://app.mehen.dev", workspaceSlug: null } }).map(plainText)
    expect(lines[1]).toContain("The vault returned a link that is not on https://app.mehen.dev")
  })
})

describe("the keyring advice", () => {
  const desktop = { platform: "linux" as const, env: { DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/user/1000/bus" }, hasSecretTool: false }

  test("on a Linux desktop with a session bus and no secret-tool, says what to install, unlock and restart", () => {
    const advice = keyringAdvice(desktop, "systemd")
    expect(advice).toContain("install secret-tool (Debian and Ubuntu: libsecret-tools; Fedora and Arch: libsecret)")
    expect(advice).toContain("make sure the login keyring is unlocked")
    expect(advice).toContain("`systemctl --user restart mehen-vault.service`")
    expect(advice).toContain("it then moves the key into the keyring")
    expect(keyringAdvice(desktop, "process")).toContain("`mehen up --remove`, then `mehen up`")
    expect(custodyLine("file", advice)).toBe(` The vault's key is in a file only you can read; see \`mehen doctor\`. ${advice}`)
  })

  test("says nothing with secret-tool, without a session bus, off Linux, or for a key already out of a file", () => {
    expect(keyringAdvice({ ...desktop, hasSecretTool: true }, "systemd")).toBeNull()
    expect(keyringAdvice({ ...desktop, env: {} }, "systemd")).toBeNull()
    expect(keyringAdvice({ ...desktop, platform: "darwin" }, "launchd")).toBeNull()
    expect(custodyLine("keyring", "advice")).toBe(" The vault's key is in your login keyring.")
    expect(custodyLine("file")).toBe(" The vault's key is in a file only you can read; see `mehen doctor`.")
  })
})

describe("removing and reinstalling the service waits for the job to stop, and never takes an unanswered question for gone", () => {
  let home: { path: string; remove(): Promise<void> } | null = null
  afterEach(async () => {
    await home?.remove()
    home = null
  })

  // A clock the fake sleep moves, and a runner that answers from a script
  // per command and records each command with the time budget it was given.
  type Answer = { code: number | null; out: string }
  function machine(answers: Record<string, (call: number) => Answer>) {
    let clock = 0
    const ran: { cmd: string; timeoutMs: number }[] = []
    const calls = new Map<string, number>()
    const runner: Runner = (cmd, timeoutMs) => {
      const key = cmd.slice(0, 3).join(" ")
      ran.push({ cmd: key, timeoutMs })
      const n = calls.get(key) ?? 0
      calls.set(key, n + 1)
      const answer = Object.entries(answers).find(([prefix]) => key.startsWith(prefix))?.[1]
      return answer ? answer(n) : { code: 0, out: "" }
    }
    return { runner, ran, sleep: (ms: number) => void (clock += ms), now: () => clock, at: () => clock }
  }
  const notFound: Answer = { code: 113, out: 'Could not find service "dev.mehen.vault" in domain for port' }
  const loaded: Answer = { code: 0, out: "dev.mehen.vault = { state = running }" }
  const state = (load: string, active: string): Answer => ({ code: 0, out: `LoadState=${load}\nActiveState=${active}` })

  test("launchd: still loaded for the first prints after bootout, then not found: removed, plist and all", async () => {
    home = await tempDir()
    const m = machine({ "launchctl print": (n) => (n < 3 ? loaded : notFound) })
    await Bun.write(launchdPath(home.path), "plist")
    expect(removeService("launchd", "/data", home.path, {}, m)).toEqual([])
    expect(existsSync(launchdPath(home.path))).toBe(false)
    expect(m.ran.map((r) => r.cmd.split(" ").slice(0, 2).join(" "))).toEqual(["launchctl bootout", "launchctl print", "launchctl print", "launchctl print", "launchctl print"])
  })

  test("launchd: a print that fails for another reason is not taken for gone, and the plist stays", async () => {
    home = await tempDir()
    const m = machine({ "launchctl print": () => ({ code: 5, out: "Input/output error" }) })
    await Bun.write(launchdPath(home.path), "plist")
    const problems = removeService("launchd", "/data", home.path, {}, m)
    expect(problems).toHaveLength(1)
    expect(problems[0]).toContain("could not confirm")
    expect(problems[0]).toContain("Input/output error")
    expect(existsSync(launchdPath(home.path))).toBe(true)
  })

  test("launchd: a job that stays loaded is reported, and the plist stays", async () => {
    home = await tempDir()
    const m = machine({ "launchctl print": () => loaded })
    await Bun.write(launchdPath(home.path), "plist")
    const problems = removeService("launchd", "/data", home.path, {}, m)
    expect(problems[0]).toContain(`launchctl still has ${LAUNCHD_LABEL} loaded`)
    expect(existsSync(launchdPath(home.path))).toBe(true)
  })

  test("launchd: a bootout that fails, with the job still there, is reported; one whose job is confirmed gone is not", async () => {
    home = await tempDir()
    await Bun.write(launchdPath(home.path), "plist")
    const failed = machine({ "launchctl bootout": () => ({ code: 1, out: "Boot-out failed: 1: Operation not permitted" }), "launchctl print": () => loaded })
    const problems = removeService("launchd", "/data", home.path, {}, failed)
    expect(problems.join(" ")).toContain("Operation not permitted")
    expect(existsSync(launchdPath(home.path))).toBe(true)
    // Already unloaded (a run that stopped after bootout): bootout says not found, and so does print.
    const gone = machine({ "launchctl bootout": () => ({ code: 3, out: "Boot-out failed: 3: No such process" }), "launchctl print": () => notFound })
    expect(removeService("launchd", "/data", home.path, {}, gone)).toEqual([])
    expect(existsSync(launchdPath(home.path))).toBe(false)
  })

  test("launchd: install waits between bootout and bootstrap until the job is not found", async () => {
    home = await tempDir()
    const m = machine({ "launchctl print": (n) => (n < 2 ? loaded : notFound) })
    installService({ ...plan, home: home.path, environment: { MEHEN_HOME: "/Users/a/mh", MEHEN_NO_AUTO_UPDATE: "1" } }, {}, m)
    expect(await Bun.file(launchdPath(home.path)).text()).toContain("<key>MEHEN_HOME</key>\n    <string>/Users/a/mh</string>")
    expect(m.ran.map((r) => r.cmd.split(" ").slice(0, 2).join(" "))).toEqual(["launchctl bootout", "launchctl print", "launchctl print", "launchctl print", "launchctl bootstrap"])
  })

  test("systemd: install writes the environment into the unit it enables", async () => {
    home = await tempDir()
    const m = machine({})
    const env = { XDG_CONFIG_HOME: home.path }
    installService({ ...plan, kind: "systemd", home: home.path, environment: { MEHEN_NO_AUTO_UPDATE: "1" } }, env, m)
    const unit = await Bun.file(systemdPath(home.path, env)).text()
    expect(unit).toContain('Environment="MEHEN_NO_AUTO_UPDATE=1"')
    expect(unit).not.toContain("MEHEN_HOME")
    expect(m.ran.map((r) => r.cmd)).toEqual(["systemctl --user daemon-reload", "systemctl --user enable", "systemctl --user restart"])
  })

  test("systemd: deactivating, then inactive, is waited through and then removed", async () => {
    home = await tempDir()
    const m = machine({ "systemctl --user show": (n) => (n < 2 ? state("loaded", "deactivating") : state("loaded", "inactive")) })
    const env = { XDG_CONFIG_HOME: home.path }
    await Bun.write(systemdPath(home.path, env), "unit")
    expect(removeService("systemd", "/data", home.path, env, m)).toEqual([])
    expect(existsSync(systemdPath(home.path, env))).toBe(false)
    expect(m.ran.filter((r) => r.cmd === "systemctl --user show")).toHaveLength(3)
    expect(m.ran.at(-1)?.cmd).toBe("systemctl --user daemon-reload")
  })

  test("systemd: a bus that does not answer is not taken for stopped, and the unit stays", async () => {
    home = await tempDir()
    const m = machine({ "systemctl --user show": () => ({ code: 1, out: "Failed to connect to bus: No medium found" }) })
    const env = { XDG_CONFIG_HOME: home.path }
    await Bun.write(systemdPath(home.path, env), "unit")
    const problems = removeService("systemd", "/data", home.path, env, m)
    expect(problems).toHaveLength(1)
    expect(problems[0]).toContain("could not confirm")
    expect(problems[0]).toContain("Failed to connect to bus")
    expect(existsSync(systemdPath(home.path, env))).toBe(true)
  })

  test("systemd: activating or active through the wait is still running; the unit stays", async () => {
    home = await tempDir()
    const env = { XDG_CONFIG_HOME: home.path }
    await Bun.write(systemdPath(home.path, env), "unit")
    for (const active of ["active", "activating", "reloading"]) {
      const problems = removeService("systemd", "/data", home.path, env, machine({ "systemctl --user show": () => state("loaded", active) }))
      expect(problems[0]).toContain(`${SYSTEMD_UNIT} is still running`)
      expect(existsSync(systemdPath(home.path, env))).toBe(true)
    }
  })

  test("systemd: a disable --now that fails is reported and the unit stays, unless the unit is confirmed not there at all", async () => {
    home = await tempDir()
    const env = { XDG_CONFIG_HOME: home.path }
    await Bun.write(systemdPath(home.path, env), "unit")
    const failed = machine({ "systemctl --user disable": () => ({ code: 1, out: "Failed to disable unit: Access denied" }), "systemctl --user show": () => state("loaded", "inactive") })
    const problems = removeService("systemd", "/data", home.path, env, failed)
    expect(problems.join(" ")).toContain("Access denied")
    expect(existsSync(systemdPath(home.path, env))).toBe(true)
    const absent = machine({ "systemctl --user disable": () => ({ code: 1, out: "Unit file mehen-vault.service does not exist." }), "systemctl --user show": () => state("not-found", "inactive") })
    expect(removeService("systemd", "/data", home.path, env, absent)).toEqual([])
  })

  test("systemd: ActiveState decides before LoadState; a running unit whose file is gone is still there", () => {
    const of = (load: string, active: string) => systemdState(state(load, active)).state
    for (const active of ["active", "activating", "deactivating", "reloading", "refreshing"]) {
      expect({ active, state: of("not-found", active) }).toEqual({ active, state: "there" })
      expect({ active, state: of("loaded", active) }).toEqual({ active, state: "there" })
    }
    expect(of("not-found", "inactive")).toBe("gone")
    expect(of("not-found", "failed")).toBe("gone")
    expect(of("loaded", "inactive")).toBe("gone")
    expect(of("not-found", "maintenance")).toBe("unknown")
    expect(of("masked", "inactive")).toBe("gone")
    expect(of("bad-setting", "something-new")).toBe("unknown")
  })

  test("systemd: a unit still running after its file was removed and reloaded is not removed, and its record stays", async () => {
    home = await tempDir()
    const env = { XDG_CONFIG_HOME: home.path }
    await Bun.write(systemdPath(home.path, env), "unit")
    const m = machine({ "systemctl --user disable": () => ({ code: 1, out: "Unit file mehen-vault.service does not exist." }), "systemctl --user show": () => state("not-found", "active") })
    const problems = removeService("systemd", "/data", home.path, env, m)
    expect(problems).toHaveLength(1)
    expect(problems[0]).toContain("does not exist")
    expect(existsSync(systemdPath(home.path, env))).toBe(true)
  })

  // A runner whose every command takes `takes(timeoutMs)` of the clock,
  // recording when it started.
  function timed(m: ReturnType<typeof machine>, takes: (cmd: string, timeoutMs: number) => number) {
    const started: { cmd: string; at: number; timeoutMs: number }[] = []
    const runner: Runner = (cmd, timeoutMs) => {
      const key = cmd.slice(0, 3).join(" ")
      started.push({ cmd: key, at: m.at(), timeoutMs })
      m.sleep(Math.min(timeoutMs, takes(key, timeoutMs)))
      return m.runner(cmd, timeoutMs)
    }
    return { runner, started }
  }

  test("the wait is a wall-clock deadline: nothing starts after it, and nothing is given time past it, the stop included", async () => {
    home = await tempDir()
    const env = { XDG_CONFIG_HOME: home.path }
    await Bun.write(systemdPath(home.path, env), "unit")
    const m = machine({ "systemctl --user show": () => state("loaded", "deactivating") })
    const t = timed(m, () => 1000)
    const problems = removeService("systemd", "/data", home.path, env, { ...m, runner: t.runner, waitMs: 5000 })
    expect(problems[0]).toContain("still running")
    expect(m.at()).toBeLessThanOrEqual(5000)
    expect(t.started[0]).toEqual({ cmd: "systemctl --user disable", at: 0, timeoutMs: 5000 })
    for (const run of t.started) {
      expect(run.at).toBeLessThan(5000)
      expect(run.at + run.timeoutMs).toBeLessThanOrEqual(5000)
    }
  })

  test("a stop that uses the whole budget leaves no time to confirm anything: unknown, and the unit stays", async () => {
    home = await tempDir()
    const env = { XDG_CONFIG_HOME: home.path }
    await Bun.write(systemdPath(home.path, env), "unit")
    const m = machine({ "systemctl --user disable": () => ({ code: null, out: "(timed out)" }), "systemctl --user show": () => state("loaded", "inactive") })
    const t = timed(m, (_cmd, timeoutMs) => timeoutMs)
    const problems = removeService("systemd", "/data", home.path, env, { ...m, runner: t.runner, waitMs: 5000 })
    expect(t.started.map((r) => r.cmd)).toEqual(["systemctl --user disable"])
    expect(problems[0]).toMatch(/could not confirm|failed/)
    expect(existsSync(systemdPath(home.path, env))).toBe(true)
    expect(m.at()).toBeLessThanOrEqual(5000)
  })

  test("a slow daemon-reload at the end is held to what is left of the same budget", async () => {
    home = await tempDir()
    const env = { XDG_CONFIG_HOME: home.path }
    await Bun.write(systemdPath(home.path, env), "unit")
    const m = machine({ "systemctl --user show": () => state("loaded", "inactive") })
    const t = timed(m, (cmd, timeoutMs) => (cmd === "systemctl --user daemon-reload" ? 60_000 : Math.min(timeoutMs, 100)))
    expect(removeService("systemd", "/data", home.path, env, { ...m, runner: t.runner, waitMs: 5000 })).toEqual([])
    const reload = t.started.find((r) => r.cmd === "systemctl --user daemon-reload")
    expect(reload).toBeDefined()
    expect(reload!.at + reload!.timeoutMs).toBeLessThanOrEqual(5000)
    expect(m.at()).toBeLessThanOrEqual(5000)
  })

  test("process: a ps that does not answer is not taken for gone; its pid file stays", async () => {
    home = await tempDir()
    await Bun.write(join(home.path, "serve.pid"), "4242")
    const m = machine({ ps: () => ({ code: null, out: "(timed out)" }) })
    const problems = removeService("process", home.path, home.path, {}, m)
    expect(problems[0]).toContain("could not confirm")
    expect(existsSync(join(home.path, "serve.pid"))).toBe(true)
    // ps answers that no such process exists: gone, and the pid file goes.
    const gone = machine({ ps: () => ({ code: 1, out: "" }) })
    expect(removeService("process", home.path, home.path, {}, gone)).toEqual([])
    expect(existsSync(join(home.path, "serve.pid"))).toBe(false)
    expect(gone.ran.every((r) => r.timeoutMs <= STOP_WAIT_MS)).toBe(true)
  })

  test("the real runner ends a command at its budget", () => {
    const begun = Date.now()
    expect(defaultRunner(["sleep", "5"], 300)).toMatchObject({ code: null })
    expect(Date.now() - begun).toBeLessThan(3000)
    expect(defaultRunner(["sh", "-c", "echo hi; exit 3"], 5000)).toEqual({ code: 3, out: "hi" })
  })
})

describe("which process is this vault's", () => {
  test("serve with exactly this data folder as its last argument, never a prefix of it", () => {
    expect(isServeOf("/usr/local/bin/mehen serve --port 7787 --data /home/a/vault", "/home/a/vault")).toBe(true)
    expect(isServeOf("/usr/local/bin/mehen serve --port 7787 --data /home/a/vault2", "/home/a/vault")).toBe(false)
    expect(isServeOf("/usr/local/bin/mehen serve --port 7787 --data /home/a/vault/sub", "/home/a/vault")).toBe(false)
    expect(isServeOf("/usr/bin/sleep 30", "/home/a/vault")).toBe(false)
  })
})

describe("the agent lines", () => {
  test("each agent the guard covers says whether its guard is on, and why not", () => {
    const setup = { agents: ["claude-code", "pi", "cursor", "codex", "gemini"].map((name) => ({ name, mcp: "added" })) }
    const guard = { agents: [{ agent: "claude-code", status: "added" }, { agent: "pi", status: "unchanged" }, { agent: "cursor", status: "skipped", reason: "hooks.json: Malformed agent settings." }, { agent: "codex", status: "added" }] }
    expect(agentLines(setup, guard).split("\n").slice(1)).toEqual([
      "  claude-code: wired, guard on",
      "  pi: wired, guard on",
      "  cursor: wired, guard not on (hooks.json: Malformed agent settings.)",
      "  codex: wired, guard on once you trust it in Codex's /hooks",
      "  gemini: wired",
    ])
    expect(agentLines(setup, null)).toContain("  cursor: wired, guard not on (run `mehen guard install` to see why)")
  })
})

describe("review fixes: the agent lines and the level", () => {
  test("installed hooks with the level at warn or off are not reported as guard on", () => {
    const setup = { agents: [{ name: "cursor", mcp: "added" }, { name: "codex", mcp: "added" }] }
    const agents = [{ agent: "cursor", status: "unchanged" }, { agent: "codex", status: "unchanged" }]
    expect(agentLines(setup, { agents, level: "block" })).toContain("  cursor: wired, guard on")
    expect(agentLines(setup, { agents, level: "warn" })).toContain("  cursor: wired, guard installed, warn only")
    expect(agentLines(setup, { agents, level: "warn" })).toContain("mehen guard block")
    expect(agentLines(setup, { agents, level: "block" })).not.toContain("warn mode")
    expect(agentLines(setup, { agents, level: "off" })).toContain("  cursor: wired, guard installed, guard off")
    expect(agentLines(setup, { agents, level: "off" })).toContain("  codex: wired, guard installed, guard off")
    expect(agentLines(setup, { agents, level: "off" })).not.toContain("warn mode")
  })
})

describe("mehen up guard defaults", () => {
  test("parseUpGuard accepts warn, block and off, and refuses anything else", () => {
    expect(parseUpGuard(null)).toBeNull()
    expect(parseUpGuard("warn")).toBe("warn")
    expect(parseUpGuard("block")).toBe("block")
    expect(parseUpGuard("off")).toBe("off")
    expect(() => parseUpGuard("strict")).toThrow(CliError)
  })

  test("a fresh home starts at warn; re-runs keep an existing choice; explicit --guard overrides", async () => {
    const dir = await tempDir()
    try {
      expect(ensureUpGuardLevel(dir.path, null)).toBe("warn")
      const path = join(dir.path, "guard.json")
      expect(JSON.parse(readFileSync(path, "utf8"))).toEqual({ level: "warn" })
      expect(statSync(path).mode & 0o777).toBe(0o600)

      // Re-running with a saved choice leaves it alone.
      writeFileSync(path, '{"level":"block"}\n', { mode: 0o600 })
      expect(ensureUpGuardLevel(dir.path, null)).toBeNull()
      expect(JSON.parse(readFileSync(path, "utf8"))).toEqual({ level: "block" })

      // Explicit --guard overrides.
      expect(ensureUpGuardLevel(dir.path, "off")).toBe("off")
      expect(JSON.parse(readFileSync(path, "utf8"))).toEqual({ level: "off" })
    } finally {
      await dir.remove()
    }
  })
})

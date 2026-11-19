import { afterEach, describe, expect, test } from "bun:test"
import { existsSync } from "node:fs"
import { CliError } from "../errors.ts"
import { errorJson, errorLines } from "../output.ts"
import { tempDir } from "../testing/run-mehen.ts"
import { plainText, segments, styler } from "../tty.ts"
import { isServeOf, LAUNCHD_LABEL, type Runner, SYSTEMD_UNIT, ServiceError, installService, serviceEnvironment, launchdPath, launchdPlist, removeService, serviceKind, systemdPath, systemdUnit } from "./service.ts"
import { openerFor } from "./browser.ts"
import { custodyLine, enrolContext, enrolLines, textLines, timedOut } from "./index.ts"
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

describe("removing and reinstalling the service waits for the job to stop", () => {
  let home: { path: string; remove(): Promise<void> } | null = null
  afterEach(async () => {
    await home?.remove()
    home = null
  })

  // launchctl or systemctl answering "still there" for the first `loaded`
  // asks, and the commands in the order they ran.
  function fake(loaded: number, ask: string): { runner: Runner; ran: string[] } {
    const ran: string[] = []
    let asked = 0
    const runner: Runner = (cmd) => {
      ran.push(cmd.slice(0, 3).join(" "))
      if (cmd.includes(ask)) return { code: asked++ < loaded ? 0 : 1, out: "" }
      return { code: 0, out: "" }
    }
    return { runner, ran }
  }
  const sleep = () => undefined

  test("launchd: a job still loaded for the first prints after bootout is removed, plist and all, once it goes", async () => {
    home = await tempDir()
    const { runner, ran } = fake(3, "print")
    await Bun.write(launchdPath(home.path), "plist")
    expect(removeService("launchd", "/data", home.path, {}, { runner, sleep })).toEqual([])
    expect(existsSync(launchdPath(home.path))).toBe(false)
    expect(ran.map((c) => c.split(" ").slice(0, 2).join(" "))).toEqual(["launchctl bootout", "launchctl print", "launchctl print", "launchctl print", "launchctl print"])
  })

  test("launchd: a job that never goes is reported, and its plist kept so the record stays", async () => {
    home = await tempDir()
    const { runner } = fake(Number.POSITIVE_INFINITY, "print")
    await Bun.write(launchdPath(home.path), "plist")
    const problems = removeService("launchd", "/data", home.path, {}, { runner, sleep })
    expect(problems).toHaveLength(1)
    expect(problems[0]).toContain(`launchctl still has ${LAUNCHD_LABEL} loaded`)
    expect(existsSync(launchdPath(home.path))).toBe(true)
  })

  test("launchd: install waits between bootout and bootstrap, and writes the environment into the plist", async () => {
    home = await tempDir()
    const { runner, ran } = fake(2, "print")
    installService({ ...plan, home: home.path, environment: { MEHEN_HOME: "/Users/a/mh", MEHEN_NO_AUTO_UPDATE: "1" } }, {}, { runner, sleep })
    expect(await Bun.file(launchdPath(home.path)).text()).toContain("<key>MEHEN_HOME</key>\n    <string>/Users/a/mh</string>")
    expect(ran.map((c) => c.split(" ").slice(0, 2).join(" "))).toEqual(["launchctl bootout", "launchctl print", "launchctl print", "launchctl print", "launchctl bootstrap"])
  })

  test("systemd: install writes the environment into the unit it enables", async () => {
    home = await tempDir()
    const { runner, ran } = fake(0, "is-active")
    const env = { XDG_CONFIG_HOME: home.path }
    installService({ ...plan, kind: "systemd", home: home.path, environment: { MEHEN_NO_AUTO_UPDATE: "1" } }, env, { runner, sleep })
    const unit = await Bun.file(systemdPath(home.path, env)).text()
    expect(unit).toContain('Environment="MEHEN_NO_AUTO_UPDATE=1"')
    expect(unit).not.toContain("MEHEN_HOME")
    expect(ran).toEqual(["systemctl --user daemon-reload", "systemctl --user enable", "systemctl --user restart"])
  })

  test("systemd: a unit still active for a moment after disable --now is removed once it stops", async () => {
    home = await tempDir()
    const { runner, ran } = fake(2, "is-active")
    const env = { XDG_CONFIG_HOME: home.path }
    await Bun.write(systemdPath(home.path, env), "unit")
    expect(removeService("systemd", "/data", home.path, env, { runner, sleep })).toEqual([])
    expect(existsSync(systemdPath(home.path, env))).toBe(false)
    expect(ran.filter((c) => c === "systemctl --user is-active")).toHaveLength(3)
    expect(ran.at(-1)).toBe("systemctl --user daemon-reload")
  })

  test("systemd: a unit that stays active is reported and its file kept", async () => {
    home = await tempDir()
    const { runner } = fake(Number.POSITIVE_INFINITY, "is-active")
    const env = { XDG_CONFIG_HOME: home.path }
    await Bun.write(systemdPath(home.path, env), "unit")
    expect(removeService("systemd", "/data", home.path, env, { runner, sleep })).toEqual([`${SYSTEMD_UNIT} is still running; run \`systemctl --user disable --now ${SYSTEMD_UNIT}\``])
    expect(existsSync(systemdPath(home.path, env))).toBe(true)
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

import { describe, expect, test } from "bun:test"
import { isServeOf, LAUNCHD_LABEL, launchdPath, launchdPlist, serviceKind, systemdPath, systemdUnit } from "./service.ts"
import { openerFor } from "./browser.ts"
import { enrolLines } from "./index.ts"

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

  test("quotes arguments with spaces and escapes what systemd would expand", () => {
    const unit = systemdUnit({ ...plan, kind: "systemd", command: ["/home/a/my bin/mehen", "serve", "--data", "/home/a/$HOME/100%"] })
    expect(unit).toContain('ExecStart="/home/a/my bin/mehen" serve --data "/home/a/$$HOME/100%%"')
  })

  test("lives under XDG_CONFIG_HOME when it is set", () => {
    expect(systemdPath("/home/a", {})).toBe("/home/a/.config/systemd/user/mehen-vault.service")
    expect(systemdPath("/home/a", { XDG_CONFIG_HOME: "/cfg" })).toBe("/cfg/systemd/user/mehen-vault.service")
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
    expect(enrolLines("http://localhost:7787/w/home/e/ABCD", true, "M6W2 SXSX GAJJ 855Q")).toBe("Opened http://localhost:7787/w/home/e/ABCD\nThis machine's fingerprint is M6W2 SXSX GAJJ 855Q. The page shows all but one of its groups: type the one it hides, then accept with your passkey.\nThis carries on by itself.")
    expect(enrolLines("http://localhost:7787/w/home/e/ABCD", false, null)).toBe("Open http://localhost:7787/w/home/e/ABCD\nAccept this machine with your passkey.\nThis carries on by itself.")
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

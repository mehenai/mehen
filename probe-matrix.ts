import { spawn } from "node:child_process"
import { mkdtempSync, readFileSync, existsSync, rmSync } from "node:fs"
import { join } from "node:path"
const C = "/usr/bin/google-chrome"
const RT = process.env.RUNNER_TEMP ?? "/tmp"
type Case = { name: string; tmpdir: string; profileIn: string; flags: string[]; stdio: "ignore" | "pipe" }
const base = ["--headless=new", "--no-first-run", "--no-default-browser-check", "--remote-debugging-port=0"]
const launcher = [...base.slice(0, 3), "--disable-gpu", "--hide-scrollbars", ...base.slice(3)]
const cases: Case[] = [
  { name: "A launcher as CI: TMPDIR+profile in RUNNER_TEMP, ignore", tmpdir: RT, profileIn: RT, flags: launcher, stdio: "ignore" },
  { name: "B same, stderr piped", tmpdir: RT, profileIn: RT, flags: launcher, stdio: "pipe" },
  { name: "C TMPDIR+profile in /tmp", tmpdir: "/tmp", profileIn: "/tmp", flags: launcher, stdio: "pipe" },
  { name: "D TMPDIR RUNNER_TEMP, profile /tmp", tmpdir: RT, profileIn: "/tmp", flags: launcher, stdio: "pipe" },
  { name: "E TMPDIR /tmp, profile RUNNER_TEMP", tmpdir: "/tmp", profileIn: RT, flags: launcher, stdio: "pipe" },
  { name: "F no --disable-gpu, RUNNER_TEMP", tmpdir: RT, profileIn: RT, flags: launcher.filter((f) => f !== "--disable-gpu"), stdio: "pipe" },
  { name: "A again", tmpdir: RT, profileIn: RT, flags: launcher, stdio: "ignore" },
]
for (const c of cases) {
  const profile = mkdtempSync(join(c.profileIn, "pr-"))
  const t = Date.now()
  const child = spawn(C, [...c.flags, `--user-data-dir=${profile}`, "about:blank"], { stdio: ["ignore", "ignore", c.stdio], env: { ...process.env, TMPDIR: c.tmpdir } })
  let err = ""
  child.stderr?.on("data", (d) => (err += String(d)))
  let ms = -1
  while (Date.now() - t < 60_000) {
    const f = join(profile, "DevToolsActivePort")
    if (existsSync(f) && readFileSync(f, "utf8").includes("\n")) { ms = Date.now() - t; break }
    if (child.exitCode !== null) break
    await Bun.sleep(20)
  }
  const listening = /DevTools listening[^\n]*/.exec(err)?.[0] ?? ""
  console.log(`${c.name}: ${ms < 0 ? `NO PORT FILE after ${Date.now() - t} ms, exit ${child.exitCode}` : `${ms} ms`} ${listening ? "(stderr says listening)" : ""}`)
  for (const line of err.split("\n").filter((l) => l && !/dbus|NameOwnerChanged|org.freedesktop/.test(l)).slice(0, 8)) console.log(`    ${line.slice(0, 220)}`)
  child.kill(); await Bun.sleep(500); rmSync(profile, { recursive: true, force: true })
}

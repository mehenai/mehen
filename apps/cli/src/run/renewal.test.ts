import { afterEach, beforeEach, describe, expect, jest, spyOn, test } from "bun:test"
import { EXIT, type ExitCode } from "@mehen/protocol/api"
import * as tty from "node:tty"
import * as childProcess from "node:child_process"
import { VaultApiError } from "../vault-api.ts"
import { reportFailure } from "./deps.ts"
import { FakeVaultApi, capture, fakeDeps, removeDir, runCreated, tempDir, writeManifest } from "./fake-vault-api.ts"
import { runCommand } from "./run.ts"
import { watchRunAuthority } from "./renewal.ts"

const MINUTE = 60_000
const START = Date.parse("2026-10-26T12:00:00Z")
const SECRET = "postgres://app:never-print-this-lease@db.example/app"

beforeEach(() => { jest.useFakeTimers({ now: START }) })
afterEach(() => {
  jest.restoreAllMocks()
  jest.clearAllTimers()
  jest.useRealTimers()
})

async function advance(ms: number): Promise<void> {
  jest.advanceTimersByTime(ms)
  for (let i = 0; i < 10; i++) await Promise.resolve()
}

function setup(renew: () => unknown, expiry = START + 15 * MINUTE, end: number | null = START + 12 * 60 * MINUTE, stopGraceMs?: number) {
  const api = new FakeVaultApi().on("POST", "/v1/runs/run_test1/renew", renew)
  const order: string[] = []
  const signals: [number, string | number | undefined][] = []
  spyOn(process, "kill").mockImplementation((pid, signal) => {
    signals.push([pid, signal])
    order.push(String(signal))
    return true
  })
  let exit: (code: number) => void = () => {}
  const child = { pid: 43210, exited: new Promise<number>((resolve) => { exit = resolve }) }
  const warnings = capture()
  const authority = watchRunAuthority({
    api, run: runCreated({ expiresAt: new Date(expiry).toISOString(), endsAt: end === null ? null : new Date(end).toISOString() }), child, detached: true,
    ...(stopGraceMs !== undefined ? { stopGraceMs } : {}),
    closeCredentials: async () => { order.push("close") },
    warn: (message) => { warnings.write(`${message}\n`) },
  })
  return { api, signals, order, authority, child, exit, warnings }
}

function fakePs(snapshots: (string | Error)[]) {
  return spyOn(childProcess, "execFile").mockImplementation(((_file: string, _args: string[], _options: childProcess.ExecFileOptions, callback: (error: Error | null, stdout: string) => void) => {
    const snapshot = snapshots.shift()
    if (snapshot === undefined) throw new Error("Unexpected ps snapshot")
    if (snapshot instanceof Error) callback(snapshot, "")
    else callback(null, snapshot)
    return {} as childProcess.ChildProcess
  }) as typeof childProcess.execFile)
}

function setupTerminal(snapshots: (string | Error)[]) {
  const ps = fakePs(snapshots)
  const signals: [number, string | number | undefined][] = []
  const order: string[] = []
  spyOn(process, "kill").mockImplementation((pid, signal) => {
    signals.push([pid, signal])
    order.push(String(signal))
    return true
  })
  let exit: (code: number) => void = () => {}
  const child = { pid: 43210, exited: new Promise<number>((resolve) => { exit = resolve }) }
  const authority = watchRunAuthority({
    api: new FakeVaultApi(), run: runCreated({ expiresAt: new Date(START + 1000).toISOString() }), child, detached: false,
    closeCredentials: async () => { order.push("close") }, warn: () => {},
  })
  return { ps, signals, order, authority, exit }
}

async function tickToDeadline(): Promise<void> {
  for (let i = 0; i < 36; i++) await advance(25_000)
}

function printedFailure(api: FakeVaultApi, error: unknown, exit: ExitCode = EXIT.transient): string {
  const deps = fakeDeps(api, "/tmp")
  expect(reportFailure(deps, error)).toBe(exit)
  expect(deps.err.text()).toContain("next:")
  expect(deps.err.text()).toContain("mehen run -- <command> [args...]")
  return deps.err.text()
}

describe("run renewal authority", () => {
  test("network failures warn once, close listeners at expiry and terminate the whole group with TERM then KILL", async () => {
    const state = setup(() => { throw new Error(SECRET) })
    await advance(5 * MINUTE)
    expect(state.api.calls).toHaveLength(1)
    await advance(999)
    expect(state.api.calls).toHaveLength(1)
    await advance(1)
    expect(state.api.calls).toHaveLength(2)
    for (let i = 0; i < 21; i++) await advance(25_000)
    await advance(14 * MINUTE - (Date.now() - START))
    expect(state.warnings.text()).toContain("run run_test1 has at most 60 seconds")
    expect(state.signals).toEqual([])
    await advance(MINUTE)
    expect(state.order).toEqual(["close", "SIGTERM"])
    expect(state.signals).toEqual([[-43210, "SIGTERM"]])
    const callsAtExpiry = state.api.calls.length
    await advance(9999)
    expect(state.signals).toHaveLength(1)
    await advance(1)
    expect(state.signals).toEqual([[-43210, "SIGTERM"], [-43210, "SIGKILL"]])
    const error = await state.authority.failure
    const printed = printedFailure(state.api, error)
    expect(printed).toContain("last confirmed expiry")
    expect(printed + state.warnings.text()).not.toContain(SECRET)
    expect(state.warnings.text().split("\n").filter(Boolean)).toHaveLength(1)
    expect(state.api.calls).toHaveLength(callsAtExpiry)
    state.authority.dispose()
    expect(jest.getTimerCount()).toBe(0)
  })

  test("a transient failure that recovers updates the confirmed expiry without terminating the child", async () => {
    let calls = 0
    const state = setup(() => {
      if (++calls < 3) throw new Error(SECRET)
      return { run: "run_test1", expiresAt: new Date(Date.now() + 15 * MINUTE).toISOString() }
    })
    await advance(5 * MINUTE)
    await advance(1000)
    await advance(2000)
    expect(calls).toBe(3)
    for (let i = 0; i < 3; i++) await advance(5 * MINUTE)
    expect(state.signals).toEqual([])
    expect(state.warnings.text()).toBe("")
    state.authority.dispose()
    await advance(30 * MINUTE)
    expect(state.signals).toEqual([])
    expect(jest.getTimerCount()).toBe(0)
  })

  const refusals = [
    ["not_found", 404, EXIT.error], ["device_revoked", 403, EXIT.identity], ["frozen", 403, EXIT.human], ["forbidden", 403, EXIT.refused],
    ["unauthenticated", 401, EXIT.identity], ["proof_invalid", 401, EXIT.identity], ["conflict", 409, EXIT.transient],
    ["remote_mismatch", 403, EXIT.refused], ["owner_inactive", 403, EXIT.human], ["project_unshared", 403, EXIT.human], ["workload_ended", 403, EXIT.identity],
  ] as const
  for (const [error, status, exit] of refusals) {
    test(`${error} stops the child at once with exit ${exit} without printing the server's message or next`, async () => {
      const state = setup(() => { throw new VaultApiError(status, { error, message: SECRET, next: { say: SECRET } }) })
      await advance(5 * MINUTE)
      expect(state.order).toEqual(["close", "SIGTERM"])
      expect(state.signals).toEqual([[-43210, "SIGTERM"]])
      state.exit(143)
      await advance(0)
      expect(state.signals).toEqual([[-43210, "SIGTERM"], [-43210, "SIGKILL"]])
      const printed = printedFailure(state.api, await state.authority.failure, exit)
      expect(printed + state.warnings.text()).not.toContain(SECRET)
      expect(state.warnings.text()).toBe("")
      expect(jest.getTimerCount()).toBe(0)
      await advance(30_000)
      expect(state.signals).toEqual([[-43210, "SIGTERM"], [-43210, "SIGKILL"]])
    })
  }

  for (const [error, status] of [["rate_limited", 429], ["upstream_failed", 502], ["refresh_retrying", 409], ["internal", 403]] as const) {
    test(`a ${status} ${error} renewal answer is retried, not terminal`, async () => {
      let calls = 0
      const state = setup(() => {
        if (++calls < 3) throw new VaultApiError(status, { error, message: SECRET })
        return { run: "run_test1", expiresAt: new Date(Date.now() + 15 * MINUTE).toISOString() }
      })
      await advance(5 * MINUTE)
      await advance(1000)
      await advance(2000)
      expect(calls).toBe(3)
      expect(state.signals).toEqual([])
      expect(state.order).toEqual([])
      state.authority.dispose()
    })
  }

  // A renewal answers as the vault does: never past the run's hard end.
  function cappedAt(end: number) {
    return () => ({ run: "run_test1", expiresAt: new Date(Math.min(Date.now() + 15 * MINUTE, end)).toISOString() })
  }

  test("at its maximum life the child gets SIGTERM ten seconds before the end with the relay still up, then KILL and the relay closes at the end, exit 7", async () => {
    const end = START + 10 * MINUTE
    const state = setup(cappedAt(end), end, end)
    await advance(8 * MINUTE + 49_999)
    expect(state.warnings.text()).toBe("")
    await advance(1)
    expect(state.warnings.text()).toBe(`run run_test1 reaches its maximum life at ${new Date(end).toISOString()} and renewal cannot extend it; its child processes will be asked to stop in 60 seconds.\n`)
    expect(state.warnings.text()).not.toContain("if renewal fails")
    await advance(59_999)
    expect(state.signals).toEqual([])
    await advance(1)
    expect(state.order).toEqual(["SIGTERM"])
    expect(state.authority.stopping).toBe(true)
    await advance(9999)
    expect(state.order).toEqual(["SIGTERM"])
    await advance(1)
    expect(state.order).toEqual(["SIGTERM", "SIGKILL", "close"])
    expect(state.signals).toEqual([[-43210, "SIGTERM"], [-43210, "SIGKILL"]])
    const printed = printedFailure(state.api, await state.authority.failure, EXIT.transient)
    expect(printed).toContain("run run_test1 has reached its maximum life; its child processes were stopped.")
    expect(printed).toContain("Start a new run to continue.")
    expect(state.api.calls).toHaveLength(1)
    expect(jest.getTimerCount()).toBe(0)
  })

  test("a child that exits during the maximum-life grace is killed at once and the relay closes, exit 7", async () => {
    const end = START + 10 * MINUTE
    const state = setup(cappedAt(end), end, end, 2 * MINUTE)
    await advance(8 * MINUTE)
    expect(state.order).toEqual(["SIGTERM"])
    await advance(5000)
    state.exit(0)
    await advance(0)
    expect(state.order).toEqual(["SIGTERM", "SIGKILL", "close"])
    expect((await state.authority.failure).code).toBe(EXIT.transient)
    expect(jest.getTimerCount()).toBe(0)
  })

  for (const [end, killAt] of [[START + 22 * MINUTE, START + 20 * MINUTE + 10_000], [START + 20 * MINUTE + 5000, START + 20 * MINUTE + 5000]] as const) {
    test(`authority lost during the maximum-life grace closes the relay at once and kills ${(killAt - START - 20 * MINUTE) / 1000} s later with the refusal's exit`, async () => {
      const state = setup(() => {
        if (Date.now() >= START + 20 * MINUTE) throw new VaultApiError(403, { error: "device_revoked", message: SECRET })
        return cappedAt(end)()
      }, START + 15 * MINUTE, end, 5 * MINUTE)
      await advance(end - 5 * MINUTE - START)
      expect(state.order).toEqual(["SIGTERM"])
      await advance(START + 20 * MINUTE - Date.now())
      expect(state.order).toEqual(["SIGTERM", "close"])
      await advance(killAt - Date.now() - 1)
      expect(state.signals).toEqual([[-43210, "SIGTERM"]])
      await advance(1)
      expect(state.signals).toEqual([[-43210, "SIGTERM"], [-43210, "SIGKILL"]])
      const printed = printedFailure(state.api, await state.authority.failure, EXIT.identity)
      expect(printed).toContain("lost access because this machine was revoked")
      expect(printed).not.toContain(SECRET)
      expect(jest.getTimerCount()).toBe(0)
    })
  }

  test("a run without a hard end, as from an older vault, is never stopped for its maximum life", async () => {
    const state = setup(() => ({ run: "run_test1", expiresAt: new Date(Date.now() + 15 * MINUTE).toISOString() }), START + 15 * MINUTE, null)
    for (let i = 0; i < 13 * 12; i++) await advance(5 * MINUTE)
    expect(state.signals).toEqual([])
    expect(state.warnings.text()).toBe("")
    state.authority.dispose()
    expect(jest.getTimerCount()).toBe(0)
  })

  test("a service run, whose renewals name no hard end, renews past twelve hours and is never stopped for a maximum life", async () => {
    const state = setup(() => ({ run: "run_test1", expiresAt: new Date(Date.now() + 15 * MINUTE).toISOString(), endsAt: null }), START + 15 * MINUTE, null)
    for (let i = 0; i < 13 * 12; i++) await advance(5 * MINUTE)
    expect(state.api.calls.filter((c) => c.path === "/v1/runs/run_test1/renew")).toHaveLength(13 * 12)
    expect(state.signals).toEqual([])
    expect(state.warnings.text()).toBe("")
    state.authority.dispose()
    expect(jest.getTimerCount()).toBe(0)
  })

  test("a leader exiting during termination gets exactly one immediate group KILL, never a delayed one", async () => {
    const state = setup(() => {}, START + 1000)
    await advance(1000)
    expect(state.signals).toEqual([[-43210, "SIGTERM"]])
    await advance(2000)
    state.exit(143)
    await advance(0)
    expect(state.signals).toEqual([[-43210, "SIGTERM"], [-43210, "SIGKILL"]])
    await state.authority.failure
    await advance(30_000)
    expect(state.signals).toEqual([[-43210, "SIGTERM"], [-43210, "SIGKILL"]])
    expect(jest.getTimerCount()).toBe(0)
  })

  test("a live leader gets exactly one delayed group KILL at the grace deadline", async () => {
    const state = setup(() => {}, START + 1000)
    await advance(1000)
    await advance(9999)
    expect(state.signals).toEqual([[-43210, "SIGTERM"]])
    await advance(1)
    expect(state.signals).toEqual([[-43210, "SIGTERM"], [-43210, "SIGKILL"]])
    state.exit(137)
    await advance(30_000)
    expect(state.signals).toHaveLength(2)
    expect(jest.getTimerCount()).toBe(0)
  })

  test("terminal authority loss closes listeners, then signals only the child tree using bounded shell-free ps", async () => {
    const snapshot = `1 0
9999 1
43210 9999
43211 43210
43212 43211
54321 9999
${process.pid} 9999
`
    const state = setupTerminal([snapshot, snapshot])
    await advance(1000)
    expect(state.order).toEqual(["close", "SIGTERM", "SIGTERM", "SIGTERM"])
    expect(state.signals).toEqual([[43212, "SIGTERM"], [43211, "SIGTERM"], [43210, "SIGTERM"]])
    await advance(8999)
    expect(state.ps).toHaveBeenCalledTimes(1)
    await advance(1)
    expect(state.signals).toEqual([
      [43212, "SIGTERM"], [43211, "SIGTERM"], [43210, "SIGTERM"],
      [43212, "SIGKILL"], [43211, "SIGKILL"], [43210, "SIGKILL"],
    ])
    expect(state.ps).toHaveBeenCalledTimes(2)
    for (const call of state.ps.mock.calls) {
      expect(call.slice(0, 3)).toEqual(["ps", ["-A", "-o", "pid=,ppid="], {
        timeout: 1000, maxBuffer: 1024 * 1024, encoding: "utf8", shell: false, killSignal: "SIGKILL",
      }])
    }
    await state.authority.failure
    state.exit(137)
    await advance(30_000)
    expect(state.signals).toHaveLength(6)
    expect(jest.getTimerCount()).toBe(0)
  })

  test("terminal KILL rechecks ancestry and skips exited or re-parented descendants", async () => {
    const state = setupTerminal([
      "43210 1\n43211 43210\n43212 43211\n43213 43210\n",
      "43210 1\n43211 43210\n43212 1\n9999 1\n",
    ])
    await advance(1000)
    expect(state.signals).toEqual([[43212, "SIGTERM"], [43213, "SIGTERM"], [43211, "SIGTERM"], [43210, "SIGTERM"]])
    await advance(9000)
    expect(state.signals.slice(4)).toEqual([[43211, "SIGKILL"], [43210, "SIGKILL"]])
    await state.authority.failure
    expect(state.ps).toHaveBeenCalledTimes(2)
  })

  test("a terminal leader exiting during termination is never signalled again", async () => {
    const state = setupTerminal(["43210 1\n43211 43210\n"])
    await advance(1000)
    expect(state.signals).toEqual([[43211, "SIGTERM"], [43210, "SIGTERM"]])
    state.exit(143)
    await advance(0)
    await state.authority.failure
    await advance(30_000)
    expect(state.signals).toEqual([[43211, "SIGTERM"], [43210, "SIGTERM"]])
    expect(state.ps).toHaveBeenCalledTimes(1)
    expect(jest.getTimerCount()).toBe(0)
  })

  test("a terminal descendant reported exited by kill is never signalled again, even if its pid reappears", async () => {
    const snapshot = "43210 1\n43211 43210\n"
    const state = setupTerminal([snapshot, snapshot])
    const signals: [number, string | number | undefined][] = []
    spyOn(process, "kill").mockImplementation((pid, signal) => {
      signals.push([pid, signal])
      if (pid === 43211) throw Object.assign(new Error("No process"), { code: "ESRCH" })
      return true
    })
    await advance(1000)
    await advance(9000)
    expect(signals).toEqual([[43211, "SIGTERM"], [43210, "SIGTERM"], [43210, "SIGKILL"]])
    await state.authority.failure
  })

  test("an in-flight terminal ps snapshot cannot signal anything after the leader exits", async () => {
    const state = setupTerminal([])
    let release = () => {}
    state.ps.mockImplementation(((_file: string, _args: string[], _options: childProcess.ExecFileOptions, callback: (error: Error | null, stdout: string) => void) => {
      release = () => { callback(null, "43210 1\n43211 43210\n") }
      return {} as childProcess.ChildProcess
    }) as typeof childProcess.execFile)
    await advance(1000)
    expect(state.order).toEqual(["close"])
    state.exit(0)
    await advance(0)
    await state.authority.failure
    release()
    await advance(30_000)
    expect(state.signals).toEqual([])
    expect(state.ps).toHaveBeenCalledTimes(1)
    expect(jest.getTimerCount()).toBe(0)
  })

  test("a failed terminal ps snapshot never targets an unknown pid or group", async () => {
    const state = setupTerminal([new Error(SECRET), new Error(SECRET)])
    await advance(1000)
    await advance(9000)
    expect(state.signals).toEqual([[43210, "SIGTERM"], [43210, "SIGKILL"]])
    expect(String(await state.authority.failure)).not.toContain(SECRET)
  })

  test("a hanging renewal cannot extend authority and its late response cannot resurrect the run", async () => {
    let release: (value: unknown) => void = () => {}
    const state = setup(() => new Promise((resolve) => { release = resolve }))
    await tickToDeadline()
    expect(state.signals).toEqual([[-43210, "SIGTERM"]])
    release({ run: "run_test1", expiresAt: new Date(Date.now() + 15 * MINUTE).toISOString() })
    await advance(10_000)
    expect(state.signals).toEqual([[-43210, "SIGTERM"], [-43210, "SIGKILL"]])
    expect(printedFailure(state.api, await state.authority.failure)).toContain("last confirmed expiry")
    expect(state.api.calls).toHaveLength(1)
  })

  test("the expiry returned by renewal, not the initial expiry, sets the kill deadline", async () => {
    let calls = 0
    const state = setup(() => {
      if (++calls === 1) return { run: "run_test1", expiresAt: new Date(START + 25 * MINUTE).toISOString() }
      throw new Error(SECRET)
    })
    for (let i = 0; i < 24; i++) await advance(MINUTE)
    expect(state.signals).toEqual([])
    expect(state.warnings.text()).toContain("60 seconds")
    await advance(MINUTE)
    expect(state.signals).toEqual([[-43210, "SIGTERM"]])
    await advance(10_000)
    expect(printedFailure(state.api, await state.authority.failure)).not.toContain(SECRET)
  })

  test("mehen run starts a detached child and returns a safe error with next after authority expires", async () => {
    const dir = tempDir("mehen-run-authority-")
    writeManifest(dir, 'project = "prj_test"\ndefault_env = "dev"\n[vars]\nDATABASE_URL = "vault"\n')
    let exit: (code: number) => void = () => {}
    const exited = new Promise<number>((resolve) => { exit = resolve })
    const child = {
      pid: 43210, exited, exitCode: null, signalCode: null,
      stdout: new ReadableStream({ start(controller) { controller.close() } }),
      stderr: new ReadableStream({ start(controller) { controller.close() } }),
    }
    spyOn(tty, "isatty").mockReturnValue(false)
    const spawn = spyOn(Bun, "spawn").mockReturnValue(child as unknown as ReturnType<typeof Bun.spawn>)
    const signals: (string | number | undefined)[] = []
    spyOn(process, "kill").mockImplementation((_pid, signal) => {
      signals.push(signal)
      if (signal === "SIGKILL") exit(137)
      return true
    })
    const api = new FakeVaultApi()
      .on("POST", "/v1/runs", () => runCreated({ vars: [{ name: "DATABASE_URL", delivery: "lease", item: "app-db", value: SECRET }] }))
      .on("POST", "/v1/runs/run_test1/renew", () => { throw new Error(SECRET) })
      .on("DELETE", "/v1/runs/run_test1", () => { throw new Error(SECRET) })
    const deps = fakeDeps(api, dir)
    try {
      const running = runCommand(["test-child"], deps)
      await advance(0)
      expect(spawn.mock.calls[0]?.[1]).toMatchObject({ detached: true })
      await tickToDeadline()
      expect(signals).toEqual(["SIGTERM"])
      await advance(10_000)
      expect(await running).toBe(EXIT.transient)
      expect(signals).toEqual(["SIGTERM", "SIGKILL"])
      expect(deps.err.text()).toContain("last confirmed expiry")
      expect(deps.err.text()).toContain("next:")
      expect(deps.err.text()).toContain("mehen run -- <command> [args...]")
      expect(deps.err.text() + deps.out.text()).not.toContain(SECRET)
      expect(api.called("DELETE", "/v1/runs/run_test1")).toBe(true)
    } finally {
      removeDir(dir)
    }
  })

  for (const [error, status, code] of [["device_revoked", 403, EXIT.identity], ["conflict", 409, EXIT.transient]] as const) {
    test(`mehen run exits ${code} when renewal is refused with ${error}`, async () => {
      const dir = tempDir("mehen-run-refused-")
      writeManifest(dir, 'project = "prj_test"\ndefault_env = "dev"\n[vars]\n')
      let exit: (code: number) => void = () => {}
      const child = { pid: 43210, exited: new Promise<number>((resolve) => { exit = resolve }), exitCode: null, signalCode: "SIGTERM", stdout: null, stderr: null }
      spyOn(tty, "isatty").mockReturnValue(false)
      spyOn(Bun, "spawn").mockReturnValue(child as unknown as ReturnType<typeof Bun.spawn>)
      spyOn(process, "kill").mockImplementation((_pid, signal) => {
        if (signal === "SIGTERM") exit(143)
        return true
      })
      const api = new FakeVaultApi()
        .on("POST", "/v1/runs", () => runCreated())
        .on("POST", "/v1/runs/run_test1/renew", () => { throw new VaultApiError(status, { error, message: SECRET }) })
        .on("DELETE", "/v1/runs/run_test1", () => ({}))
      const deps = fakeDeps(api, dir)
      try {
        const running = runCommand(["test-child"], deps)
        await advance(0)
        await advance(5 * MINUTE)
        expect(await running).toBe(code)
        expect(deps.err.text()).toContain("its child processes were stopped.")
        expect(deps.err.text()).not.toContain(SECRET)
        expect(api.called("DELETE", "/v1/runs/run_test1")).toBe(true)
      } finally {
        exit(143)
        removeDir(dir)
      }
    })
  }

  for (const isTTY of [true, false]) {
    test(`mehen run keeps detached=${!isTTY} for stdin TTY=${isTTY} and sends no signals after normal exit`, async () => {
      const dir = tempDir("mehen-run-tty-")
      writeManifest(dir, 'project = "prj_test"\ndefault_env = "dev"\n[vars]\n')
      let exit: (code: number) => void = () => {}
      const child = {
        pid: 43210, exited: new Promise<number>((resolve) => { exit = resolve }),
        exitCode: 0, signalCode: null, stdout: null, stderr: null,
      }
      const isatty = spyOn(tty, "isatty").mockReturnValue(isTTY)
      const spawn = spyOn(Bun, "spawn").mockReturnValue(child as unknown as ReturnType<typeof Bun.spawn>)
      const kill = spyOn(process, "kill").mockReturnValue(true)
      const api = new FakeVaultApi().on("POST", "/v1/runs", () => runCreated())
      const deps = fakeDeps(api, dir)
      const listeners = [process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")]
      try {
        const running = runCommand(["test-child"], deps)
        await advance(0)
        expect(isatty).toHaveBeenCalledWith(0)
        expect(spawn.mock.calls[0]?.[1]).toMatchObject({ detached: !isTTY, stdin: "inherit" })
        expect([process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")]).toEqual(listeners.map((count) => count + 1))
        exit(0)
        expect(await running).toBe(EXIT.ok)
        await advance(30 * MINUTE)
        expect(kill).not.toHaveBeenCalled()
        expect(api.called("POST", "/v1/runs/run_test1/renew")).toBe(false)
        expect(jest.getTimerCount()).toBe(0)
      } finally {
        exit(0)
        removeDir(dir)
      }
    })
  }

  test("in a terminal, Ctrl-C leaves mehen alive to clean up and pass on the child's own exit code; SIGTERM reaches only the child", async () => {
    const dir = tempDir("mehen-run-tty-signals-")
    writeManifest(dir, 'project = "prj_test"\ndefault_env = "dev"\n[vars]\n')
    let exit: (code: number) => void = () => {}
    const child = {
      pid: 43210, exited: new Promise<number>((resolve) => { exit = resolve }),
      exitCode: 42 as number | null, signalCode: null, stdout: null, stderr: null,
    }
    spyOn(tty, "isatty").mockReturnValue(true)
    spyOn(Bun, "spawn").mockReturnValue(child as unknown as ReturnType<typeof Bun.spawn>)
    const kill = spyOn(process, "kill").mockReturnValue(true)
    const api = new FakeVaultApi().on("POST", "/v1/runs", () => runCreated()).on("DELETE", "/v1/runs/run_test1", () => ({}))
    const deps = fakeDeps(api, dir)
    const before = [process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")]
    try {
      const running = runCommand(["test-child"], deps)
      await advance(0)
      process.emit("SIGINT", "SIGINT")
      expect(kill).not.toHaveBeenCalled()
      process.emit("SIGTERM", "SIGTERM")
      expect(kill.mock.calls).toEqual([[43210, "SIGTERM"]])
      exit(42)
      expect(await running).toBe(42)
      expect(api.called("DELETE", "/v1/runs/run_test1")).toBe(true)
      expect([process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")]).toEqual(before)
    } finally {
      exit(42)
      removeDir(dir)
    }
  })

  for (const expiresAt of [new Date(START - 1).toISOString(), "invalid-expiry"]) {
    test(`mehen run refuses to start a child with an unconfirmed live expiry: ${expiresAt}`, async () => {
      const dir = tempDir("mehen-run-expired-start-")
      writeManifest(dir, 'project = "prj_test"\ndefault_env = "dev"\n[vars]\n')
      const spawn = spyOn(Bun, "spawn").mockImplementation(() => { throw new Error("must not spawn") })
      const api = new FakeVaultApi().on("POST", "/v1/runs", () => runCreated({ expiresAt }))
      const deps = fakeDeps(api, dir)
      try {
        expect(await runCommand(["test-child"], deps)).toBe(EXIT.error)
        expect(spawn).not.toHaveBeenCalled()
        expect(deps.err.text()).toContain("expired before the child could start")
        expect(deps.err.text()).toContain("next:")
        expect(api.called("DELETE", "/v1/runs/run_test1")).toBe(true)
      } finally {
        removeDir(dir)
      }
    })
  }

  test("normal child exit disposes every timer without terminating the group", async () => {
    const state = setup(() => { throw new Error(SECRET) })
    state.exit(0)
    await state.child.exited
    await advance(30 * MINUTE)
    expect(state.signals).toEqual([])
    expect(state.warnings.text()).toBe("")
    expect(state.api.calls).toHaveLength(0)
    expect(jest.getTimerCount()).toBe(0)
  })
})

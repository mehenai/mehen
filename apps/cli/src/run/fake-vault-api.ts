// Test support for the run and relay tests: a scripted VaultApi, captured
// output, temp repos and bounded waits. Not used by the CLI itself.

import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import type { RelayRequestInput, RunCreated } from "@mehen/protocol/api"
import type { VaultApi } from "../vault-api.ts"
import type { Deps, Writer } from "./deps.ts"

export type FakeCall = { method: string; path: string; body: unknown }
type Handler = (body: unknown) => unknown

export class FakeVaultApi implements VaultApi {
  readonly calls: FakeCall[] = []
  readonly relayCalls: RelayRequestInput[] = []
  private readonly routes = new Map<string, Handler>()
  relayHandler: (request: RelayRequestInput) => Response | Promise<Response> = (request) =>
    Response.json({ echoed: request }, { headers: { "Mehen-Upstream": "1" } })

  on(method: string, path: string, handler: Handler): this {
    this.routes.set(`${method} ${path}`, handler)
    return this
  }

  async request<T>(method: "GET" | "POST" | "PUT" | "DELETE", path: string, body?: unknown): Promise<T> {
    this.calls.push({ method, path, body })
    const handler = this.routes.get(`${method} ${path}`)
    if (handler === undefined) return {} as T
    return (await handler(body)) as T
  }

  async relay(request: RelayRequestInput): Promise<Response> {
    this.relayCalls.push(request)
    return this.relayHandler(request)
  }

  called(method: string, path: string): boolean {
    return this.calls.some((call) => call.method === method && call.path === path)
  }
}

export function runCreated(overrides: Partial<RunCreated> = {}): RunCreated {
  return {
    run: "run_test1",
    expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
    endsAt: new Date(Date.now() + 12 * 3_600_000).toISOString(),
    project: { id: "prj_test", slug: "demo" },
    env: "dev",
    vars: [],
    interceptHosts: [],
    fencedHosts: [],
    ...overrides,
  }
}

// GET /v1/items/<slug> for an OpenAI key, as an ad hoc run reads it.
export function itemDescription(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    slug: "openai",
    provider: "openai",
    status: "active",
    hosts: ["api.openai.com"],
    binding: { hosts: ["api.openai.com"] },
    injection: { in: "header", name: "Authorization", format: "Bearer {key}" },
    secretFields: [{ name: "key", set: true, length: 51, prefix: "sk-proj-", fingerprint: "abc" }],
    ...overrides,
  }
}

export type CapturedWriter = Writer & { text(): string }

export function capture(): CapturedWriter {
  const decoder = new TextDecoder()
  let text = ""
  return {
    write(chunk: string | Uint8Array) {
      text += typeof chunk === "string" ? chunk : decoder.decode(chunk)
    },
    text: () => text,
  }
}

export function fakeDeps(api: VaultApi, cwd: string, env: Record<string, string | undefined> = {}): Deps & { out: CapturedWriter; err: CapturedWriter } {
  const out = capture()
  const err = capture()
  return { api, config: { vault: "https://vault.test", tenant: "tn_test00000001", device: "dev_test", workspaceSlug: "test-space", workspaceName: "Test Space" }, stdout: out, stderr: err, cwd, env: { PATH: process.env.PATH, ...env }, out, err }
}

export function tempDir(prefix = "mehen-test-"): string {
  return realpathSync(mkdtempSync(join(tmpdir(), prefix)))
}

export function removeDir(dir: string): void {
  rmSync(dir, { recursive: true, force: true })
}

export function git(cwd: string, ...args: string[]): string {
  const result = Bun.spawnSync(["git", "-c", "user.name=mehen", "-c", "user.email=mehen@test", "-c", "init.defaultBranch=main", ...args], { cwd, stdout: "pipe", stderr: "pipe" })
  if (result.exitCode !== 0) throw new Error(`git ${args.join(" ")}: ${result.stderr.toString()}`)
  return result.stdout.toString().trim()
}

export function writeManifest(dir: string, body: string): void {
  writeFileSync(join(dir, "mehen.toml"), body)
}

export async function withTimeout<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timed out after ${ms} ms: ${what}`)), ms)
  })
  try {
    return await Promise.race([promise, timeout])
  } finally {
    clearTimeout(timer)
  }
}

// Runs a command without blocking the event loop (the servers under test live
// in this process), killed after `ms`.
export async function spawnText(cmd: string[], options: { env?: Record<string, string | undefined>; ms?: number } = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const child = Bun.spawn(cmd, { env: options.env ?? { PATH: process.env.PATH }, stdout: "pipe", stderr: "pipe", timeout: options.ms ?? 15_000 })
  const [stdout, stderr] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text()])
  await child.exited
  return { code: child.exitCode, stdout, stderr }
}

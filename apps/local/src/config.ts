// Where a local vault keeps its data and the address it answers on.
//
// Loopback (the default): bound to 127.0.0.1, its origin http://localhost:<port>.
// With an origin (a home server): its origin and WebAuthn RP ID are that
// name, which must be https because a passkey needs a secure context, and
// it answers that Host only. TLS is whatever sits in front of it (Tailscale
// serve, Caddy), so it still binds loopback unless told otherwise.

import { homedir } from "node:os"
import { join, resolve } from "node:path"

export const DEFAULT_PORT = 7787
const LOOPBACK_BINDS = new Set(["127.0.0.1", "::1", "localhost"])

export type LocalConfig = {
  dataDir: string
  port: number
  hostname: string
  origin: string | null
}

export type Address = {
  origin: string
  rpId: string
  hosts: Set<string>
  loopback: boolean
}

export class LocalConfigError extends Error {
  override readonly name = "LocalConfigError"
}

export function defaultDataDir(env: Record<string, string | undefined> = process.env, platform: NodeJS.Platform = process.platform): string {
  const home = env.HOME ?? homedir()
  if (platform === "darwin") return join(home, "Library", "Application Support", "Mehen", "vault")
  if (platform === "win32") return join(env.LOCALAPPDATA ?? join(home, "AppData", "Local"), "Mehen", "vault")
  return join(env.XDG_DATA_HOME || join(home, ".local", "share"), "mehen", "vault")
}

export function parsePort(raw: string | undefined, fallback = DEFAULT_PORT): number {
  if (raw === undefined || raw === "") return fallback
  const port = Number(raw)
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new LocalConfigError(`The port ${JSON.stringify(raw)} is not a port number (0 to 65535).`)
  return port
}

export function canonicalLocalOrigin(raw: string): string {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw new LocalConfigError(`The origin ${JSON.stringify(raw)} is not a URL. Give the address people open, such as https://mehen.example.ts.net.`)
  }
  if (url.pathname !== "/" || url.search || url.hash || url.username || url.password) throw new LocalConfigError(`The origin ${raw} must be a bare origin, with no path, query or user name.`)
  if (url.protocol !== "https:") throw new LocalConfigError(`The origin ${raw} must use https: a passkey works only in a secure context, and plain http is safe on this machine's loopback only, which needs no origin at all.`)
  return url.origin
}

// The address the vault answers on, once the port is known.
export function addressFor(config: LocalConfig, port: number): Address {
  if (config.origin === null) {
    if (!LOOPBACK_BINDS.has(config.hostname)) throw new LocalConfigError(`Binding ${config.hostname} needs --origin https://<name>: without one, the vault answers on this machine's loopback only.`)
    // URL drops a default port (80) from host, as browsers do in Host.
    const origin = new URL(`http://localhost:${port}`)
    return { origin: origin.origin, rpId: "localhost", hosts: new Set([origin.host, new URL(`http://127.0.0.1:${port}`).host]), loopback: true }
  }
  const url = new URL(config.origin)
  return { origin: url.origin, rpId: url.hostname, hosts: new Set([url.host]), loopback: false }
}

export function resolveConfig(input: { dataDir?: string | undefined; port?: string | number | undefined; hostname?: string | undefined; origin?: string | undefined }, env: Record<string, string | undefined> = process.env): LocalConfig {
  const origin = input.origin ?? env.MEHEN_SERVE_ORIGIN
  return {
    dataDir: resolve(input.dataDir ?? env.MEHEN_SERVE_DATA ?? defaultDataDir(env)),
    port: typeof input.port === "number" ? input.port : parsePort(input.port ?? env.MEHEN_SERVE_PORT),
    hostname: input.hostname ?? env.MEHEN_SERVE_HOST ?? "127.0.0.1",
    origin: origin ? canonicalLocalOrigin(origin) : null,
  }
}

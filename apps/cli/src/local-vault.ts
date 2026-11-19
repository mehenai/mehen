// The vault `mehen up` set up on this machine, as <root>/local-vault.json
// records it: once there is one, it is the vault a new enrolment uses
// unless MEHEN_VAULT_URL names another, and its key custody advice.

import { readFileSync } from "node:fs"
import { join } from "node:path"
import { DEFAULT_VAULT_URL, type Env, canonicalOrigin } from "./config.ts"
import { resolveHome } from "./home.ts"
import { SYSTEMD_UNIT } from "./up/service.ts"

export const LOCAL_VAULT_RECORD = "local-vault.json"

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"])

// The record's origin when it is a vault on this machine: plain http to
// localhost, 127.0.0.1 or [::1] with its port written out, which is all
// `mehen up` ever records. Anything else, and a record that is missing or
// broken, is null, so the default is unchanged. Never throws.
export function localVaultOrigin(root: string): string | null {
  try {
    const value: unknown = JSON.parse(readFileSync(join(root, LOCAL_VAULT_RECORD), "utf8"))
    if (typeof value !== "object" || value === null) return null
    const origin = (value as Record<string, unknown>).origin
    if (typeof origin !== "string") return null
    const canonical = canonicalOrigin(origin)
    const url = new URL(canonical)
    return url.protocol === "http:" && LOCAL_HOSTS.has(url.hostname) && url.port !== "" && canonical === origin ? canonical : null
  } catch {
    return null
  }
}

export type DefaultVault = { url: string; source: "local" | "default" }

// The vault when neither MEHEN_VAULT_URL nor an enrolled slot names one:
// the local vault `mehen up` set up, then Mehen Cloud.
export function defaultVault(env: Env): DefaultVault {
  let root: string | null = null
  try {
    root = resolveHome(env).root
  } catch {
    root = null
  }
  const local = root === null ? null : localVaultOrigin(root)
  return local === null ? { url: DEFAULT_VAULT_URL, source: "default" } : { url: local, source: "local" }
}

export type KeyringHost = { platform: NodeJS.Platform; env: Env; hasSecretTool: boolean }

export function keyringHost(env: Env): KeyringHost {
  return { platform: process.platform, env, hasSecretTool: Bun.which("secret-tool", { PATH: env.PATH ?? "" }) !== null }
}

// A vault keeping its key in a file on a Linux desktop that has a session
// bus but no secret-tool: what moves the key into the login keyring. The
// vault does it at its next start, and keeps the file while the keyring is
// locked.
export function keyringAdvice(host: KeyringHost, service: string | null): string | null {
  if (host.platform !== "linux" || !host.env.DBUS_SESSION_BUS_ADDRESS || host.hasSecretTool) return null
  const restart = service === "systemd" ? `\`systemctl --user restart ${SYSTEMD_UNIT}\`` : "`mehen up --remove`, then `mehen up`"
  return `To move it into your login keyring, install secret-tool (Debian and Ubuntu: libsecret-tools; Fedora and Arch: libsecret), make sure the login keyring is unlocked, and restart the vault (${restart}): it then moves the key into the keyring.`
}

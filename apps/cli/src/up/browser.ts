// Opens a link in the person's browser. MEHEN_BROWSER names a program that
// takes the link as its only argument (a headless box, a test); otherwise
// the platform's own opener. Never through a shell, so a link cannot run
// anything.

import { spawnSync } from "node:child_process"

export function openerFor(env: Record<string, string | undefined>, platform: NodeJS.Platform = process.platform): string[] | null {
  if (env.MEHEN_BROWSER === "none") return null
  if (env.MEHEN_BROWSER) return [env.MEHEN_BROWSER]
  if (platform === "darwin") return ["open"]
  if (platform === "win32") return ["rundll32", "url.dll,FileProtocolHandler"]
  if (env.DISPLAY || env.WAYLAND_DISPLAY) return ["xdg-open"]
  return null
}

export function openUrl(url: string, env: Record<string, string | undefined>, platform: NodeJS.Platform = process.platform): boolean {
  const parsed = new URL(url)
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false
  const opener = openerFor(env, platform)
  if (!opener) return false
  const result = spawnSync(opener[0] as string, [...opener.slice(1), parsed.href], { stdio: "ignore", timeout: 10_000 })
  return result.status === 0
}

// The tunnel that brings a vault on this machine's loopback to the person's
// own browser, for a session they reach this machine through over SSH:
// the passkey page must be opened at the same address, so the same port.
// Null outside SSH, or for a vault not on the loopback.
export function sshTunnel(origin: string, env: Record<string, string | undefined>, host: string): string | null {
  if (!env.SSH_CONNECTION && !env.SSH_CLIENT) return null
  const url = new URL(origin)
  if (url.hostname !== "localhost" && url.hostname !== "127.0.0.1") return null
  const port = url.port || (url.protocol === "https:" ? "443" : "80")
  return `ssh -L ${port}:localhost:${port} ${host}`
}

// The line that says how to reach the page through the tunnel.
export function tunnelLine(tunnel: string): string {
  return `This is an SSH session, so no browser opened here. On your own computer, run \`${tunnel}\` (this machine's name as you reach it), then open the link there.`
}

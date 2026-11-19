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

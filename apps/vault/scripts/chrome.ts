// Headless Chrome over the devtools protocol, shared by the gallery's
// layout check (ui-gallery.ts) and the interaction gate (ui-interact.ts):
// where Chrome is, how it starts with a throwaway profile, and a small
// client for the protocol's messages and events.

import { existsSync } from "node:fs"
import path from "node:path"
import { startChrome, within } from "../../../tools/ci/chrome.ts"

// Where macOS and the Linux packages put Chrome or Chromium, as a path or a
// command on PATH.
export const CHROME_CANDIDATES = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/Applications/Chromium.app/Contents/MacOS/Chromium", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]

export function findChrome(): string | null {
  const dirs = (process.env.PATH ?? "").split(path.delimiter).filter((d) => d !== "")
  for (const candidate of CHROME_CANDIDATES) {
    const paths = candidate.startsWith("/") ? [candidate] : dirs.map((d) => path.join(d, candidate))
    const found = paths.find((p) => existsSync(p))
    if (found !== undefined) return found
  }
  return null
}

type CdpMessage = { id?: number; method?: string; sessionId?: string; params?: Record<string, unknown>; result?: Record<string, unknown>; error?: { message: string } }

export class Cdp {
  private next = 1
  private readonly pending = new Map<number, { resolve: (value: Record<string, unknown>) => void; reject: (error: Error) => void }>()
  private readonly waiters: { method: string; sessionId: string; resolve: () => void }[] = []

  constructor(private readonly ws: WebSocket) {
    ws.addEventListener("message", (event) => {
      const message = JSON.parse(String(event.data)) as CdpMessage
      if (message.id !== undefined) {
        const waiter = this.pending.get(message.id)
        this.pending.delete(message.id)
        if (!waiter) return
        if (message.error) waiter.reject(new Error(message.error.message))
        else waiter.resolve(message.result ?? {})
        return
      }
      if (message.method) {
        const index = this.waiters.findIndex((w) => w.method === message.method && w.sessionId === message.sessionId)
        if (index >= 0) (this.waiters.splice(index, 1)[0] as { resolve: () => void }).resolve()
      }
    })
  }

  send(method: string, params: Record<string, unknown> = {}, sessionId?: string): Promise<Record<string, unknown>> {
    const id = this.next++
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
      this.ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }))
    })
  }

  // Resolves when the event arrives; register before the action that causes it.
  once(method: string, sessionId: string, timeoutMs = 10_000): Promise<void> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`${method} did not fire within ${timeoutMs} ms`)), timeoutMs)
      this.waiters.push({
        method,
        sessionId,
        resolve: () => {
          clearTimeout(timer)
          resolve()
        },
      })
    })
  }
}

// Started the one way every script and test starts Chrome
// (tools/ci/chrome.ts): a profile of its own, a wait sized for a fresh CI
// runner's slow first read of Chrome from disk, and what Chrome printed
// when it does not start.
export async function launchChrome(chromePath: string): Promise<{ cdp: Cdp; close: () => Promise<void> }> {
  const chrome = await startChrome(chromePath, { flags: ["--disable-gpu", "--hide-scrollbars"], profilePrefix: "mehen-gallery-" })
  const ws = new WebSocket(chrome.endpoint)
  try {
    const opened = await within(
      new Promise<true>((resolve, reject) => {
        ws.addEventListener("open", () => resolve(true))
        ws.addEventListener("error", () => reject(new Error(`could not connect to Chrome's devtools socket at ${chrome.endpoint}`)))
      }),
      30_000,
    )
    if (opened === null) throw new Error(`Chrome's devtools socket at ${chrome.endpoint} did not answer within 30 s`)
  } catch (error) {
    ws.close()
    await chrome.close()
    throw error
  }
  const cdp = new Cdp(ws)
  return {
    cdp,
    close: async () => {
      await within(cdp.send("Browser.close").catch(() => undefined), 5_000)
      await chrome.close()
    },
  }
}

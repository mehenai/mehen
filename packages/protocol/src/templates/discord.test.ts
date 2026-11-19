import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { discord } from "./discord.ts"
import { underBroadAllow } from "../../test/template-policy.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(discord.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(discord.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

const API = "https://discord.com/api/v10"

describe("discord", () => {
  it("sends the token as Bot <token>", () => {
    expect(discord.injection).toEqual({ in: "header", name: "Authorization", format: "Bot {key}" })
  })

  it("reaches the HTTP API over https, and nothing that looks like it or lies outside /api", () => {
    expect(reaches("GET", `${API}/users/@me`)).toBe(true)
    expect(reaches("GET", "https://discord.com.evil.test/api/v10/users/@me")).toBe(false)
    expect(reaches("GET", "http://discord.com/api/v10/users/@me")).toBe(false)
    expect(reaches("GET", "https://discordapp.com/api/v10/users/@me")).toBe(false)
    expect(reaches("GET", "https://discord.com/channels/1/2")).toBe(false)
  })

  it("lets reads and the bot's own reactions through", () => {
    expectAll([
      ["GET", `${API}/channels/1/messages?limit=50`, "allow"],
      ["GET", `${API}/guilds/1/members?limit=100`, "allow"],
      ["PUT", `${API}/channels/1/messages/2/reactions/%F0%9F%91%80/@me`, "allow"],
    ])
  })

  it("holds posts and other writes for approval", () => {
    expectAll([
      ["POST", `${API}/channels/1/messages`, "approve"],
      ["POST", "https://discord.com/api/channels/1/messages", "approve"],
      ["POST", `${API}/channels/1/threads`, "approve"],
      ["DELETE", `${API}/channels/1/messages/2`, "approve"],
      ["DELETE", `${API}/users/@me/guilds/1`, "approve"],
    ])
  })

  it("refuses webhooks, invites, roles, permissions, members, bans, the application, OAuth and deleting a server", () => {
    expectAll([
      ["POST", `${API}/channels/1/webhooks`, "deny"],
      ["PATCH", `${API}/webhooks/1`, "deny"],
      ["POST", `${API}/channels/1/invites`, "deny"],
      ["POST", `${API}/guilds/1/roles`, "deny"],
      ["PUT", `${API}/guilds/1/members/2/roles/3`, "deny"],
      ["PUT", `${API}/channels/1/permissions/2`, "deny"],
      ["PATCH", `${API}/guilds/1/members/2`, "deny"],
      ["PUT", `${API}/guilds/1/bans/2`, "deny"],
      ["PATCH", `${API}/applications/@me`, "deny"],
      ["POST", `${API}/oauth2/token`, "deny"],
      ["DELETE", `${API}/guilds/1`, "deny"],
      ["POST", `${API}/channels/1/Webhooks`, "deny"],
    ])
  })
})

describe("discord review fixes", () => {
  it("lets the named reads through and holds every other read", () => {
    expectAll([
      ["GET", `${API}/guilds/1/channels`, "allow"],
      ["GET", `${API}/channels/1/messages/2`, "allow"],
      ["GET", `${API}/guilds/1/integrations`, "approve"],
      ["GET", "https://discord.com/api/channels/1/messages", "approve"],
    ])
  })

  it("refuses webhook reads, which carry each webhook's token, whatever the item's policy says", () => {
    for (const path of [
      "/channels/1/webhooks",
      "/guilds/1/webhooks",
      "/webhooks/2",
    ]) expect({ path, action: underBroadAllow(discord, "GET", `${API}${path}`) }).toEqual({ path, action: "deny" })
  })

  it("refuses following a channel, thread-member changes and changes that can rewrite permission overwrites", () => {
    expectAll([
      ["POST", `${API}/channels/1/followers`, "deny"],
      ["PUT", `${API}/channels/1/thread-members/2`, "deny"],
      ["DELETE", `${API}/channels/1/thread-members/@me`, "deny"],
      ["PATCH", `${API}/channels/1`, "deny"],
      ["POST", `${API}/guilds/1/channels`, "deny"],
      ["PATCH", `${API}/guilds/1/channels`, "deny"],
    ])
  })
})

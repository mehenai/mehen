// Which mark stands for a thing: a template or provider's brand slug, the
// icon for an item kind, a machine or a project. Pure names, no markup, so
// the browser bundle (the command palette) can pick a tile without carrying
// the SVG data; icons.ts renders them.

import type { ItemKind } from "@mehen/protocol/kinds"
import type { BrandSlug, IconName } from "./icons.ts"

// Template and OAuth provider ids to the logo that stands for them. The two
// Microsoft ids have no mark with a clear licence (Simple Icons withdrew
// them), and Fathom (the meeting recorder), HeyGen, Groq, Postmark,
// Firecrawl, Browserbase, Together AI and SerpApi are not in Simple Icons
// (its "Fathom" is the analytics company), so they fall back to a letter
// tile. Fly.io has no mark here yet and falls back the same way.
const BRAND_FOR: Record<string, BrandSlug> = {
  openai: "openai",
  anthropic: "anthropic",
  linear: "linear",
  stripe: "stripe",
  "cloudflare-api-token": "cloudflare",
  "github-pat": "github",
  "github-oauth": "github",
  "github-oauth-client": "github",
  "slack-bot": "slack",
  "google-oauth-client": "google",
  "google-gmail": "gmail",
  "google-calendar": "googlecalendar",
  "google-drive": "googledrive",
  "google-gemini": "googlegemini",
  mistral: "mistralai",
  openrouter: "openrouter",
  "ollama-cloud": "ollama",
  snyk: "snyk",
  vercel: "vercel",
  npm: "npm",
  notion: "notion",
  gitbook: "gitbook",
  sentry: "sentry",
  posthog: "posthog",
  "betterstack-uptime": "betterstack",
  "hetzner-cloud": "hetzner",
  scaleway: "scaleway",
  neon: "neon",
  "hubspot-private-app": "hubspot",
  intercom: "intercom",
  resend: "resend",
  loops: "loops",
  "brave-search": "brave",
  semrush: "semrush",
  elevenlabs: "elevenlabs",
}

export function brandFor(templateOrProvider: string): BrandSlug | null {
  return BRAND_FOR[templateOrProvider] ?? null
}

// The brand's name as a word (the same titles icons.ts puts on the marks;
// a test keeps them equal), for a line such as "Gmail as alex@...".
const BRAND_TITLES: Record<BrandSlug, string> = {
  gmail: "Gmail",
  google: "Google",
  googlecalendar: "Google Calendar",
  googledrive: "Google Drive",
  github: "GitHub",
  openai: "OpenAI",
  anthropic: "Anthropic",
  cloudflare: "Cloudflare",
  linear: "Linear",
  stripe: "Stripe",
  slack: "Slack",
  snyk: "Snyk",
  posthog: "PostHog",
  sentry: "Sentry",
  neon: "Neon",
  vercel: "Vercel",
  notion: "Notion",
  gitbook: "GitBook",
  betterstack: "Better Stack",
  elevenlabs: "ElevenLabs",
  brave: "Brave",
  ollama: "Ollama",
  hetzner: "Hetzner",
  npm: "npm",
  hubspot: "HubSpot",
  googlegemini: "Google Gemini",
  mistralai: "Mistral AI",
  openrouter: "OpenRouter",
  resend: "Resend",
  scaleway: "Scaleway",
  semrush: "Semrush",
  intercom: "Intercom",
  loops: "Loops",
}

export function brandTitle(slug: BrandSlug): string {
  return BRAND_TITLES[slug]
}

export type KindTileKind = ItemKind | "machine" | "project"

export type MachineBackend = "secure-enclave" | "software"

const KIND_ICON: Record<ItemKind, IconName> = {
  "api-key": "key",
  "bearer-token": "key",
  "basic-auth": "lock",
  "custom-headers": "key",
  "oauth-client": "badge",
  "oauth-connection": "link",
  "google-service-account": "badge",
  "github-app": "badge",
  "hmac-key": "key",
  "ssh-key": "lock",
  "password-login": "lock",
  totp: "lock",
  "database-url": "braces",
  "smtp-imap": "mail",
  "cloud-access-key": "key",
  file: "lock",
  note: "lock",
  generic: "key",
}

// A software key on a host with no display is a server; a Secure Enclave
// key on a Mac is a desktop. The name is always shown beside the tile.
export function machineIcon(backend: MachineBackend | string | undefined, name = ""): IconName {
  const lower = name.toLowerCase()
  if (/\b(macbook|laptop)\b/.test(lower)) return "laptop"
  if (/\b(iphone|phone)\b/.test(lower)) return "phone"
  if (/\bwatch\b/.test(lower)) return "watch"
  if (backend === "secure-enclave" || /\b(mac|studio|desktop)\b/.test(lower)) return "desktop"
  return "tower"
}

export function kindIcon(kind: KindTileKind, backend?: MachineBackend | string, name?: string): IconName {
  if (kind === "machine") return machineIcon(backend, name)
  if (kind === "project") return "braces"
  return KIND_ICON[kind] ?? "key"
}

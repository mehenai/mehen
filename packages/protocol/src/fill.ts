// Fill: the vault seals one field of a credential to the asking machine,
// which types it into one web page after checking the page's address. These
// are the shapes and the origin rules both sides share; no route uses them
// yet.
import { z } from "zod"
import { Slug } from "./api.ts"
import { LEASE_ONLY_HOST } from "./binding.ts"
import { PlatformJwkSchema, SealedBoxSchema } from "./platform.ts"
import { PolicyItemIdSchema } from "./policy-mode.ts"
import { ItemUseContextSchema } from "./workspace.ts"

// One spelling per page: https only, no userinfo, no IP literal, an ASCII
// lower-case host (international names as punycode) and the port only when
// it is not 443. Anything else is null, never a guess.
export function fillOrigin(url: string): string | null {
  if (!/^https:\/\//i.test(url)) return null
  const authority = url.slice("https://".length).split(/[/\\?#]/, 1)[0]!
  if (authority.includes("@")) return null
  let parsed: URL
  try { parsed = new URL(url) } catch { return null }
  if (parsed.protocol !== "https:" || parsed.username !== "" || parsed.password !== "") return null
  const host = parsed.hostname
  if (host.startsWith("[") || /^[0-9.]+$/.test(host)) return null
  if (host.length > 253 || !host.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return null
  if (parsed.port === "0") return null
  return parsed.port === "" ? `https://${host}` : `https://${host}:${parsed.port}`
}

const FillOriginSchema = z.string().max(300).refine((origin) => fillOrigin(origin) === origin, "must be an https origin: lower-case host, no path, no IP address")
export const ORIGIN_LIST_MAX = 8
const OriginList = z.array(FillOriginSchema).max(ORIGIN_LIST_MAX).refine((list) => new Set(list).size === list.length, "lists an origin twice")

// The pages a human allowed for one item: more sign-in pages, and pages of
// other services its value may be typed into.
export const ItemBrowserSchema = z.strictObject({ signinOrigins: OriginList, typeInto: OriginList })
export type ItemBrowser = z.infer<typeof ItemBrowserSchema>

export type FillItem = { publicFields: Record<string, string>; binding: { hosts: readonly string[] }; browser?: ItemBrowser | null }

// Sign-in pages: the sign-in address, then each exact binding host (never a
// wildcard or the lease-only host), then those a human added; each once.
export function signinOrigins(item: FillItem): string[] {
  return signinOriginSources(item).map((page) => page.origin)
}

// The same pages, each with where it first came from, for the credential
// page's marks ("from its sign-in address", "from its hosts", "added").
export type SigninOriginSource = "address" | "hosts" | "added"
export function signinOriginSources(item: FillItem): { origin: string; source: SigninOriginSource }[] {
  const candidates: [string | undefined, SigninOriginSource][] = [
    [item.publicFields.url, "address"],
    ...item.binding.hosts.filter((host) => !host.startsWith("*.") && host !== LEASE_ONLY_HOST).map((host): [string, SigninOriginSource] => [`https://${host}`, "hosts"]),
    ...(item.browser?.signinOrigins ?? []).map((origin): [string, SigninOriginSource] => [origin, "added"]),
  ]
  const pages: { origin: string; source: SigninOriginSource }[] = []
  for (const [url, source] of candidates) {
    const origin = url === undefined ? null : fillOrigin(url)
    if (origin !== null && !pages.some((page) => page.origin === origin)) pages.push({ origin, source })
  }
  return pages
}

// Other services' pages are only ever the ones a human listed.
export function typeIntoOrigins(item: FillItem): string[] {
  return [...(item.browser?.typeInto ?? [])]
}

const FillFieldNameSchema = z.string().regex(/^[a-z][a-z0-9_]{0,31}$/)
const ApprovalIdSchema = z.string().regex(/^apr_[A-Za-z0-9_-]{1,60}$/)

// The page is named by its path alone: one sign-in spans several pages, so
// the path is shown and audited but not bound, and a query never leaves the
// machine. Only RFC 3986 path characters, and never a leading "//", so no
// control character, bidi override or host can reach a card or the audit.
export const FillRequestSchema = z.strictObject({
  item: Slug,
  field: FillFieldNameSchema,
  origin: FillOriginSchema,
  page: z.string().max(512).regex(/^\/(?!\/)[A-Za-z0-9\-._~!$&'()*+,;=:@%/]*$/),
  context: ItemUseContextSchema.optional(),
  approval: ApprovalIdSchema.optional(),
  recipient: PlatformJwkSchema,
})
export type FillRequest = z.infer<typeof FillRequestSchema>

// `item` is the item's id: the box is sealed under it (fillSealContext), and
// the machine knows the item only by its slug.
export const FillResponseSchema = z.object({
  box: SealedBoxSchema,
  item: PolicyItemIdSchema,
  field: FillFieldNameSchema,
  input: z.enum(["username", "password", "one-time-code", "secret"]),
  label: z.string().min(1).max(200),
  origin: FillOriginSchema,
  validUntil: z.iso.datetime().optional(),
  by: z.union([
    z.strictObject({ approval: ApprovalIdSchema }),
    z.strictObject({ rule: z.string().regex(/^rul_[A-Za-z0-9_-]{1,60}$/) }),
    z.strictObject({ free: z.literal(true) }),
  ]),
})
export type FillResponse = z.infer<typeof FillResponseSchema>

// What a fill's box is sealed under. It goes into the HKDF info and the AAD
// (seal.ts), so a box opens only for this workspace, item, field, page
// origin and proof, and cannot be replayed into another fill.
export function fillSealContext(c: { workspace: string; item: string; field: string; origin: string; jti: string }): string {
  return `fill/v1/${c.workspace}/${c.item}/${c.field}/${c.origin}/${c.jti}`
}

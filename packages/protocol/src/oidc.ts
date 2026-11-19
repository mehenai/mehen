import { z } from "zod"
import type { IdentityRule, WorkspaceRole } from "./workspace.ts"

export const OIDC_PROVIDERS = { google: { issuer: "https://accounts.google.com", issuers: ["https://accounts.google.com", "accounts.google.com"], authorise: "https://accounts.google.com/o/oauth2/v2/auth", token: "https://oauth2.googleapis.com/token", revocation: "https://oauth2.googleapis.com/revoke", jwks: "https://www.googleapis.com/oauth2/v3/certs", algorithm: "RS256", scopes: ["openid", "email", "profile"], domainClaim: "hd" } } as const
export const OIDC_LIMITS = { tokenBytes: 16_384, jwksBytes: 65_536, claimChars: 4096, clockSkewSeconds: 30, issuedWithinSeconds: 300, fetchTimeoutMs: 5000, unknownKeyRefreshes: 1 } as const
const ClaimsSchema = z.object({ iss: z.enum(OIDC_PROVIDERS.google.issuers), sub: z.string().min(1).max(255), aud: z.string().min(1).max(255), azp: z.string().max(255).optional(), exp: z.number().int().positive(), iat: z.number().int().positive(), nonce: z.string().min(1).max(255), email: z.email().max(254), email_verified: z.literal(true), hd: z.string().min(1).max(253).regex(/^[a-zA-Z0-9]+(?:[.-][a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$/).optional(), name: z.string().max(255).optional() })
export type OidcClaims = { issuer: "https://accounts.google.com"; subject: string; email: string; emailVerified: true; domain: string | null; name: string | null; issuedAt: number; expiresAt: number }
export type OidcClaimRefusal = "claims_invalid" | "audience_invalid" | "nonce_invalid" | "expired" | "issued_at_invalid"
/** Signature/algorithm/kid verification happens BEFORE this pure checker.
 * Numeric dates here are OIDC seconds, not protocol view timestamps. */
export function checkOidcClaims(input: unknown, expected: { clientId: string; nonce: string; now: number }): { ok: true; claims: OidcClaims } | { ok: false; reason: OidcClaimRefusal } {
  try {
    const json = JSON.stringify(input)
    if (json === undefined || new TextEncoder().encode(json).byteLength > OIDC_LIMITS.tokenBytes) return { ok: false, reason: "claims_invalid" }
  } catch { return { ok: false, reason: "claims_invalid" } }
  const parsed = ClaimsSchema.safeParse(input)
  if (!parsed.success) return { ok: false, reason: "claims_invalid" }
  const c = parsed.data
  if (c.aud !== expected.clientId || (c.azp !== undefined && c.azp !== expected.clientId)) return { ok: false, reason: "audience_invalid" }
  if (c.nonce !== expected.nonce) return { ok: false, reason: "nonce_invalid" }
  const now = expected.now / 1000
  if (!Number.isFinite(now) || c.exp <= now - OIDC_LIMITS.clockSkewSeconds) return { ok: false, reason: "expired" }
  if (c.iat > now + OIDC_LIMITS.clockSkewSeconds || c.iat < now - OIDC_LIMITS.issuedWithinSeconds || c.exp <= c.iat) return { ok: false, reason: "issued_at_invalid" }
  return { ok: true, claims: { issuer: OIDC_PROVIDERS.google.issuer, subject: c.sub, email: c.email.toLowerCase(), emailVerified: true, domain: c.hd?.toLowerCase() ?? null, name: c.name ?? null, issuedAt: c.iat, expiresAt: c.exp } }
}
export function satisfiesRule(claims: OidcClaims, rule: IdentityRule, role: WorkspaceRole): boolean {
  return rule === null || !rule.roles.includes(role) || (claims.emailVerified && claims.domain !== null && rule.domains.includes(claims.domain) && claims.email.split("@")[1] === claims.domain)
}
export const IdentityCheckEvidenceSchema = z.strictObject({ id: z.string(), identity: z.string(), claims: z.strictObject({ issuer: z.literal("https://accounts.google.com"), subject: z.string(), email: z.email(), domain: z.string(), name: z.string().nullable() }), account: z.string(), session: z.string(), sessionKind: z.enum(["web", "app"]), securityEpoch: z.number().int().nonnegative(), workspace: z.string(), member: z.string(), ruleRevision: z.number().int().nonnegative(), gateGeneration: z.number().int().nonnegative(), sequence: z.number().int().nonnegative(), startedAt: z.number().int().nonnegative(), succeededAt: z.number().int().nonnegative(), expiresAt: z.number().int().nonnegative(), purpose: z.enum(["session", "enrolment", "acceptance", "rescope", "activation", "promotion", "rule"]), subjectDigest: z.string().nullable() })
export type IdentityCheckEvidence = z.infer<typeof IdentityCheckEvidenceSchema>
export const AppGateCodeSchema = z.strictObject({ codeHash: z.string(), appSessionHash: z.string(), account: z.string(), securityEpoch: z.number().int().nonnegative(), pkceChallenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/), workspace: z.string(), member: z.string(), ruleRevision: z.number().int().nonnegative(), gateGeneration: z.number().int().nonnegative(), result: z.string(), createdAt: z.number().int().nonnegative(), expiresAt: z.number().int().nonnegative(), consumedAt: z.number().int().nonnegative().nullable() }).refine((v) => v.expiresAt > v.createdAt && v.expiresAt <= v.createdAt + 300_000, "App gate codes live at most five minutes")
export type AppGateCode = z.infer<typeof AppGateCodeSchema>
export const AppGateStartSchema = z.strictObject({ workspace: z.string(), pkceChallenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/) })
export const AppGateRedeemSchema = z.strictObject({ code: z.string().min(1).max(256), verifier: z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/) })

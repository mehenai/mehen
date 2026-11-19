// What more than one template or OAuth provider uses: the injection most
// APIs take, the method lists and rules the policies share, GitHub's rules
// (a token and an OAuth connection), and Google's sign-in, refresh and
// lifetimes (Gmail, Calendar and Drive). A helper only one template uses
// lives in that template's file.

import type { Injection, PolicySchema } from "../api.ts"
import type { z } from "zod"
import type { IdentityProbe, Lifetimes, OAuth2Auth, RefreshPolicy } from "../templates.ts"

// Stands for a platform's own callback URL in a client set-up step
// (ClientSetupStep); the page puts the URL in before showing the step.
export const CLIENT_SETUP_CALLBACK = "{callback}"

export const BEARER = (name = "Authorization", format = "Bearer {key}"): Injection => ({ in: "header", name, format })

export type PolicyRuleInput = z.infer<typeof PolicySchema>["rules"][number]
export const WRITES = ["POST", "PUT", "PATCH", "DELETE"]
export const READS = ["GET", "HEAD"]
export const ALLOW_READS: PolicyRuleInput = { action: "allow", methods: READS, note: "reads" }
// Reads of the named routes only. A template whose API has reads that hand
// back secrets allows these, each checked against the provider's response
// schema, and every other read asks.
export const NAMED_READS = (paths: string[], note: string): PolicyRuleInput => ({ action: "allow", methods: READS, paths, note })
export const MODEL_CALLS = "model calls and the data they use"

// GitHub also serves a repository at /repositories/{id} and an organisation
// at /organizations/{id}, so every /repos/{owner}/{repo} and /orgs/{org}
// rule is written for both.
export function githubPaths(...paths: string[]): string[] {
  return paths.flatMap((p) => {
    if (p.startsWith("/repos/*/*/")) return [p, `/repositories/*/${p.slice("/repos/*/*/".length)}`]
    if (p.startsWith("/orgs/*/")) return [p, `/organizations/*/${p.slice("/orgs/*/".length)}`]
    return [p]
  })
}

// What a GitHub token does without a human: reads and read-only GraphQL
// queries. Every write, issues and comments included, needs an approval,
// because a token that can comment on any repository it reaches can post
// data to a public repository an attacker owns. To let agents write freely
// to your own repositories, add allow rules for your owners on the item page,
// for example POST /repos/<you>/*/issues and /repos/<you>/*/issues/*/comments.
export const GITHUB_ALLOWED: PolicyRuleInput[] = [
  ALLOW_READS,
  { action: "allow", methods: ["POST"], paths: ["/graphql"], body: "graphql-query", note: "read-only GraphQL queries" },
]

// The persistence and exfiltration routes of a GitHub token: refused even
// with an approval. A GraphQL request that is not plainly a query, a GET of
// /graphql, or any GraphQL parameter in the URL needs an approval.
export const GITHUB_SENSITIVE: PolicyRuleInput[] = [
  { action: "deny", methods: WRITES, paths: githubPaths("/user/keys/**", "/user/gpg_keys/**", "/user/ssh_signing_keys/**", "/repos/*/*/keys/**"), note: "SSH, signing and deploy keys" },
  { action: "deny", methods: WRITES, paths: githubPaths("/repos/*/*/hooks/**", "/orgs/*/hooks/**"), note: "webhooks" },
  {
    action: "deny",
    methods: WRITES,
    paths: githubPaths(
      "/repos/*/*/collaborators/**",
      "/repos/*/*/invitations/**",
      "/orgs/*/invitations/**",
      "/orgs/*/memberships/**",
      "/orgs/*/teams/*/memberships/**",
      "/orgs/*/outside_collaborators/**",
      "/user/repository_invitations/**",
    ),
    note: "collaborators, invitations and memberships give someone else access",
  },
  {
    action: "deny",
    methods: WRITES,
    paths: githubPaths("/repos/*/*/actions/runners/**", "/orgs/*/actions/runners/**", "/orgs/*/actions/runner-groups/**", "/enterprises/*/actions/runners/**"),
    note: "self-hosted runners and their tokens receive jobs and their secrets",
  },
  { action: "deny", methods: WRITES, paths: githubPaths("/repos/*/*/transfer"), note: "transfers the repository away" },
  { action: "deny", methods: WRITES, paths: ["/user/emails/**", "/user/email/**"], note: "account email addresses reset the password" },
  { action: "deny", methods: WRITES, paths: ["/applications/**", "/authorizations/**"], note: "OAuth tokens and grants" },
  { action: "approve", paths: ["/graphql"], body: "graphql-mutation", note: "GraphQL requests that are not plainly a query" },
]

export const GOOGLE_SCOPE = "https://www.googleapis.com/auth/"

export const GOOGLE_AUTH = (defaults: string[], allowed: string[]): OAuth2Auth => ({
  kind: "oauth2",
  authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
  tokenUrl: "https://oauth2.googleapis.com/token",
  revokeUrl: "https://oauth2.googleapis.com/revoke",
  pkce: "S256",
  clientAuth: "client_secret_post",
  tokenRequestFormat: "form",
  scopes: {
    separator: " ",
    param: "scope",
    identity: ["openid", "email"],
    identityScopes: ["openid", "email", "profile", `${GOOGLE_SCOPE}userinfo.email`, `${GOOGLE_SCOPE}userinfo.profile`],
    defaults: defaults.map((s) => GOOGLE_SCOPE + s),
    allowed: allowed.map((s) => GOOGLE_SCOPE + s),
    shortPrefix: GOOGLE_SCOPE,
  },
  // A refresh token only arrives with offline access and a fresh consent.
  // No include_granted_scopes: with it Google returns the union of every
  // scope the account ever granted this client, so a token could carry more
  // than this connection asked for. The vault gets exactly what it asks for.
  authorizeParams: { access_type: "offline", prompt: "consent select_account" },
  accountHint: { param: "login_hint" },
  tokenResponse: {
    accessToken: "access_token",
    refreshToken: "refresh_token",
    expiresIn: "expires_in",
    refreshTokenExpiresIn: "refresh_token_expires_in",
    grantedScopes: "scope",
  },
})

export const GOOGLE_IDENTITY: IdentityProbe = {
  from: "request",
  request: { method: "GET", url: "https://openidconnect.googleapis.com/v1/userinfo" },
  subject: "sub",
  label: "email",
}

export const GOOGLE_REFRESH: RefreshPolicy = {
  mode: "refresh_token",
  rotation: "none",
  marginSeconds: 300,
  terminalErrors: ["invalid_grant"],
  clientErrors: ["invalid_client", "unauthorized_client"],
}

export const GOOGLE_LIFETIMES: Lifetimes = {
  accessTokenSeconds: 3600,
  refreshTokenIdleSeconds: 180 * 86_400,
  liveRefreshTokensPerClient: 100,
  testingModeRefreshSeconds: 7 * 86_400,
}

export const ACCESS_TOKEN_BEARER: Injection = { in: "header", name: "Authorization", format: "Bearer {access_token}" }

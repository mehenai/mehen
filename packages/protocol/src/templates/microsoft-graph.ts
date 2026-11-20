import type { OAuthProviderTemplate } from "../templates.ts"
import { ACCESS_TOKEN_BEARER, ALLOW_READS, WRITES } from "./shared.ts"

const GRAPH_VERSIONS = ["/v1.0", "/beta"]
const graph = (...paths: string[]) => GRAPH_VERSIONS.flatMap((v) => paths.map((p) => v + p))
// Graph accepts an action by its plain or namespace-qualified name, under
// any path that reaches a message: /me, /users/{id}, mail folders, keys in
// parentheses. Restrictive rules also match the last segment with any
// "qualifier." prefix removed (binding.ts), so "graph.send" is covered too.
const graphActions = (...actions: string[]) => actions.flatMap((a) => [`/**/${a}`, `/**/microsoft.graph.${a}`])

// Without a human: reads. Every write needs an approval: sendMail, drafts
// (createReply and createForward included), events (which can invite and
// email anyone) and their accept, decline or tentative replies, calendar
// and file sharing, and file writes or copies. $batch, mail rules, mailbox settings writes, app
// registrations, subscriptions, and sending, replying to or forwarding a
// stored message by id are refused.
export const microsoftGraph: OAuthProviderTemplate = {
  id: "microsoft-graph",
  family: "microsoft",
  displayName: "Microsoft 365 (Graph)",
  category: "mail",
  docsUrl: "https://learn.microsoft.com/en-us/graph/permissions-reference",
  clientTemplate: "microsoft-oauth-client",
  auth: {
    kind: "oauth2",
    authorizeUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    tokenUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    pkce: "S256",
    clientAuth: "client_secret_post",
    tokenRequestFormat: "form",
    scopes: {
      separator: " ",
      param: "scope",
      identity: ["openid", "profile", "email"],
      offline: "offline_access",
      identityScopes: ["openid", "profile", "email", "offline_access"],
      defaults: ["User.Read", "Mail.ReadWrite", "Mail.Send", "Calendars.ReadWrite"],
      allowed: ["User.Read", "Mail.Read", "Mail.ReadWrite", "Mail.Send", "Calendars.Read", "Calendars.ReadWrite", "Contacts.Read", "Contacts.ReadWrite", "Files.Read", "Files.ReadWrite", "Tasks.ReadWrite"],
    },
    authorizeParams: { prompt: "select_account" },
    accountHint: { param: "login_hint" },
    tokenResponse: { accessToken: "access_token", refreshToken: "refresh_token", expiresIn: "expires_in", grantedScopes: "scope", idToken: "id_token" },
  },
  identity: { from: "id_token", subject: "oid", tenant: "tid", label: "preferred_username" },
  upstream: { baseUrl: "https://graph.microsoft.com/v1.0", binding: { hosts: ["graph.microsoft.com"], paths: ["/v1.0/**", "/beta/**"] }, injection: ACCESS_TOKEN_BEARER },
  // Refresh tokens are replaced on use but the old one keeps working.
  // interaction_required, consent_required and login_required: a person
  // must sign in again (multi-factor, conditional access, new consent).
  refresh: { mode: "refresh_token", rotation: "lenient", marginSeconds: 300, terminalErrors: ["invalid_grant", "interaction_required", "consent_required", "login_required"], clientErrors: ["invalid_client", "unauthorized_client"] },
  lifetimes: { accessTokenSeconds: 3600, refreshTokenIdleSeconds: 90 * 86_400 },
  defaultPolicy: { default: "approve", rules: [ALLOW_READS] },
  sensitiveEndpoints: [
    { action: "deny", paths: graph("/$batch"), why: "a batch carries requests the vault cannot check one by one; send the requests one by one" },
    { action: "deny", methods: WRITES, paths: graph("/**/messageRules/**", "/**/inboxRules/**"), why: "mailbox rules can forward or hide mail" },
    { action: "deny", methods: WRITES, paths: graph("/**/mailboxSettings/**"), why: "forwarding and automatic replies" },
    { action: "deny", methods: WRITES, paths: graph("/applications", "/applications/**", "/servicePrincipals", "/servicePrincipals/**", "/oauth2PermissionGrants", "/oauth2PermissionGrants/**"), why: "app registrations and grants" },
    { action: "deny", methods: ["POST", "PATCH"], paths: graph("/subscriptions", "/subscriptions/**"), why: "change notifications to an outside address" },
    // A stored message can be changed after its send is approved, and a
    // forward or reply carries a message the card cannot show.
    {
      action: "deny",
      methods: WRITES,
      paths: graph(...graphActions("send", "reply", "replyAll", "forward")),
      why: "sending, replying to or forwarding a stored message by id cannot show you what is sent; send the whole message with sendMail instead",
    },
    { action: "approve", methods: ["POST"], paths: graph(...graphActions("sendMail")), why: "sends email as you" },
    { action: "approve", methods: WRITES, paths: graph("/**/permissions", "/**/permissions/**", "/**/invite", "/**/createLink"), why: "shares a file" },
    { action: "approve", methods: WRITES, paths: graph("/**/calendarPermissions", "/**/calendarPermissions/**"), why: "shares a calendar" },
  ],
}

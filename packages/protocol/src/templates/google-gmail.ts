import type { OAuthProviderTemplate } from "../templates.ts"
import { ACCESS_TOKEN_BEARER, ALLOW_READS, GOOGLE_AUTH, GOOGLE_IDENTITY, GOOGLE_LIFETIMES, GOOGLE_REFRESH, WRITES } from "./shared.ts"

const GMAIL = "/gmail/v1/users/*"

// Without a human: reads, creating drafts, and changing a message's or a
// thread's labels. Sending, importing or inserting mail, deletes and
// anything else need an approval. Forwarding, filters, delegates, send-as,
// POP and IMAP and every other settings write, push notifications and
// sending a stored draft by id are refused.
export const googleGmail: OAuthProviderTemplate = {
  id: "google-gmail",
  family: "google",
  displayName: "Gmail",
  category: "mail",
  docsUrl: "https://developers.google.com/gmail/api/auth/scopes",
  clientTemplate: "google-oauth-client",
  auth: GOOGLE_AUTH(["gmail.modify"], ["gmail.readonly", "gmail.metadata", "gmail.labels", "gmail.compose", "gmail.send", "gmail.modify", "gmail.insert"]),
  identity: GOOGLE_IDENTITY,
  upstream: {
    baseUrl: "https://gmail.googleapis.com",
    binding: { hosts: ["gmail.googleapis.com"], paths: ["/gmail/v1/**", "/upload/gmail/v1/**"] },
    injection: ACCESS_TOKEN_BEARER,
  },
  refresh: GOOGLE_REFRESH,
  lifetimes: GOOGLE_LIFETIMES,
  defaultPolicy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "allow", methods: ["POST"], paths: [`${GMAIL}/drafts`, `/upload${GMAIL}/drafts`], note: "creates a draft" },
      { action: "allow", methods: ["POST"], paths: [`${GMAIL}/messages/*/modify`, `${GMAIL}/threads/*/modify`, `${GMAIL}/messages/batchModify`], note: "changes labels" },
    ],
  },
  sensitiveEndpoints: [
    { action: "deny", methods: WRITES, paths: [`${GMAIL}/settings/forwardingAddresses`, `${GMAIL}/settings/forwardingAddresses/**`, `${GMAIL}/settings/autoForwarding`], why: "forwarding sends every message elsewhere" },
    { action: "deny", methods: WRITES, paths: [`${GMAIL}/settings/delegates`, `${GMAIL}/settings/delegates/**`], why: "delegates give someone else the mailbox" },
    { action: "deny", methods: WRITES, paths: [`${GMAIL}/settings/filters`, `${GMAIL}/settings/filters/**`], why: "filters can forward or hide mail" },
    { action: "deny", methods: WRITES, paths: [`${GMAIL}/settings/sendAs`, `${GMAIL}/settings/sendAs/**`], why: "send-as identities" },
    { action: "deny", methods: WRITES, paths: [`${GMAIL}/settings/**`], why: "mailbox settings, POP and IMAP included" },
    { action: "deny", methods: ["POST"], paths: [`${GMAIL}/watch`], why: "push notifications to another project" },
    // A draft can be changed after its send is approved, so the approval
    // could not show what is sent.
    {
      action: "deny",
      paths: [`${GMAIL}/drafts/send`, `/upload${GMAIL}/drafts/send`],
      why: "sending a saved draft by id cannot show you what is sent; send the whole message with messages/send and raw instead",
    },
    // PUT carries the message of a resumable upload.
    { action: "approve", methods: ["POST", "PUT"], paths: [`${GMAIL}/messages/send`, `/upload${GMAIL}/messages/send`], why: "sends email as you" },
    {
      action: "approve",
      methods: ["POST", "PUT"],
      paths: [`${GMAIL}/messages/import`, `${GMAIL}/messages/insert`, `/upload${GMAIL}/messages/import`, `/upload${GMAIL}/messages/insert`],
      why: "puts a message with any sender into the mailbox",
    },
    { action: "approve", methods: ["DELETE"], paths: [`${GMAIL}/messages/*`, `${GMAIL}/threads/*`], why: "permanent deletes" },
    { action: "approve", methods: ["POST"], paths: [`${GMAIL}/messages/batchDelete`], why: "permanent deletes" },
  ],
}

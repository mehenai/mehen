import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, WRITES } from "./shared.ts"

// SendGrid's v3 API, global or EU (for EU regional subusers). Without a
// human: reads. Sending mail, scheduling a Single Send and sending a test
// are pinned to an approval; contacts, lists, templates and everything
// else need one too. API keys, event and inbound parse webhooks,
// teammates, subusers, SSO, scope requests, the IP access list, mail
// forwarding and BCC settings, and the account's email, username and
// password are refused.
// https://www.twilio.com/docs/sendgrid/api-reference
export const sendgrid: Template = {
  id: "sendgrid",
  displayName: "SendGrid API key",
  kind: "api-key",
  category: "customers",
  docsUrl: "https://app.sendgrid.com/settings/api_keys",
  binding: { hosts: ["api.sendgrid.com", "api.eu.sendgrid.com"], paths: ["/v3/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "approve",
        methods: WRITES,
        paths: ["/v3/mail/send", "/v3/marketing/singlesends/*/schedule", "/v3/marketing/test/send_email", "/v3/campaigns/*/schedules/**"],
        note: "sends or schedules mail",
      },
      { action: "deny", methods: WRITES, paths: ["/v3/api_keys/**"], note: "mints, changes or revokes API keys" },
      { action: "deny", methods: WRITES, paths: ["/v3/user/webhooks/**"], note: "event and inbound parse webhooks send mail and events elsewhere" },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/v3/teammates/**", "/v3/subusers/**", "/v3/sso/**", "/v3/scopes/requests/**", "/v3/access_settings/**"],
        note: "teammates, subusers, SSO, scope requests and the IP access list give someone else access",
      },
      { action: "deny", methods: WRITES, paths: ["/v3/mail_settings/forward_spam", "/v3/mail_settings/forward_bounce", "/v3/mail_settings/bcc"], note: "forwards or copies mail elsewhere" },
      { action: "deny", methods: WRITES, paths: ["/v3/user/email", "/v3/user/username", "/v3/user/password"], note: "takes over the account" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "SENDGRID_API_KEY",
  check: { method: "GET", path: "/v3/scopes" },
  fields: { key: { label: "API key", pattern: "^SG\\." } },
  prefixes: ["SG."],
}

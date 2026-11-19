import type { Template } from "../templates.ts"
import { ALLOW_READS, WRITES } from "./shared.ts"

const ACCOUNT = "/2010-04-01/Accounts/*"

// Twilio's core API takes the Account SID and auth token (or an API key
// SID and secret) as HTTP Basic credentials. Product APIs on other hosts
// (Verify, Messaging services, Studio and the rest) are not bound.
// Without a human: reads. Sending a message and placing or changing a
// call are pinned to an approval, since they reach a person and are
// billed; everything else needs one too. API and signing keys,
// subaccounts and changes to an account, phone numbers (buying one, or
// pointing its calls and messages at a URL), TwiML applications and SIP
// domains and credential lists are refused.
// https://www.twilio.com/docs/usage/api
export const twilio: Template = {
  id: "twilio",
  displayName: "Twilio account credentials",
  kind: "basic-auth",
  category: "customers",
  docsUrl: "https://console.twilio.com/",
  binding: { hosts: ["api.twilio.com"], paths: ["/2010-04-01/**"] },
  injection: { in: "basic", username: "username", password: "password" },
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "approve", methods: ["POST"], paths: [`${ACCOUNT}/Messages`, `${ACCOUNT}/Calls`, `${ACCOUNT}/Calls/*`], note: "sends a message or places or changes a call, which is billed" },
      { action: "deny", methods: WRITES, paths: [`${ACCOUNT}/Keys/**`, `${ACCOUNT}/SigningKeys/**`], note: "mints or revokes API and signing keys" },
      { action: "deny", methods: WRITES, paths: ["/2010-04-01/Accounts", ACCOUNT], note: "creates a subaccount, or suspends or closes an account" },
      {
        action: "deny",
        methods: WRITES,
        paths: [`${ACCOUNT}/IncomingPhoneNumbers/**`, `${ACCOUNT}/Applications/**`],
        note: "buys phone numbers or points their calls and messages at a URL",
      },
      { action: "deny", methods: WRITES, paths: [`${ACCOUNT}/SIP/**`], note: "SIP domains and credential lists let someone else place calls" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "TWILIO_AUTH_TOKEN",
  check: { method: "GET", path: "/2010-04-01/Accounts.json" },
  fields: {
    username: { label: "Account SID or API key SID", pattern: "^(AC|SK)[0-9a-f]{32}$" },
    password: { label: "Auth token or API key secret" },
  },
}

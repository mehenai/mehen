import type { Template } from "../templates.ts"
import { NAMED_READS, READS, WRITES } from "./shared.ts"

const ACCOUNT = "/2010-04-01/Accounts/*"

// Twilio's core API takes the Account SID and auth token (or an API key
// SID and secret) as HTTP Basic credentials. Product APIs on other hosts
// (Verify, Messaging services, Studio and the rest) are not bound.
// Without a human: the named reads under an account (messages and their
// media, calls, recordings, conferences, queues, phone numbers, usage and
// the balance). Every other read asks, and the account resource itself is
// pinned to an approval, since it returns the auth token. Sending a
// message and placing or changing a call are pinned to an approval, since
// they reach a person and are billed; everything else needs one too. API
// and signing keys, network traversal tokens, subaccounts and changes to
// an account, phone numbers (buying one, or pointing its calls and
// messages at a URL), TwiML applications and SIP domains and credential
// lists are refused. There is no check: every read names the account SID
// in its path, and a Standard API key's SID is not the account's.
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
      NAMED_READS(
        [
          `${ACCOUNT}/Messages.json`,
          `${ACCOUNT}/Messages/*`,
          `${ACCOUNT}/Messages/*/Media.json`,
          `${ACCOUNT}/Messages/*/Media/*`,
          `${ACCOUNT}/Calls.json`,
          `${ACCOUNT}/Calls/*`,
          `${ACCOUNT}/Calls/*/Recordings.json`,
          `${ACCOUNT}/Recordings.json`,
          `${ACCOUNT}/Recordings/*`,
          `${ACCOUNT}/Conferences.json`,
          `${ACCOUNT}/Conferences/**`,
          `${ACCOUNT}/Queues.json`,
          `${ACCOUNT}/Queues/**`,
          `${ACCOUNT}/IncomingPhoneNumbers.json`,
          `${ACCOUNT}/IncomingPhoneNumbers/*`,
          `${ACCOUNT}/AvailablePhoneNumbers/**`,
          `${ACCOUNT}/Usage/Records.json`,
          `${ACCOUNT}/Usage/Records/**`,
          `${ACCOUNT}/Balance.json`,
        ],
        "reads of messages, calls, recordings, phone numbers, usage and the balance",
      ),
      { action: "approve", methods: READS, paths: ["/2010-04-01/Accounts", ACCOUNT], note: "the account resource returns the auth token" },
      { action: "approve", methods: ["POST"], paths: [`${ACCOUNT}/Messages`, `${ACCOUNT}/Calls`, `${ACCOUNT}/Calls/*`], note: "sends a message or places or changes a call, which is billed" },
      { action: "deny", methods: WRITES, paths: [`${ACCOUNT}/Keys/**`, `${ACCOUNT}/SigningKeys/**`, `${ACCOUNT}/Tokens/**`], note: "mints or revokes API and signing keys, and network traversal tokens" },
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
  fields: {
    username: { label: "Account SID or API key SID", pattern: "^(AC|SK)[0-9a-f]{32}$" },
    password: { label: "Auth token or API key secret" },
  },
}

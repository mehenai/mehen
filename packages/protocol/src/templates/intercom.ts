import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER } from "./shared.ts"

// The hosts are Intercom's US, EU and Australian regions; an app works
// only in its own. Without a human: reads and searches of contacts,
// conversations, tickets and companies. Replying, messaging customers,
// creating conversations, news items and phone redirects are pinned to
// an approval, as is everything else.
// https://developers.intercom.com/docs/references/rest-api/api.intercom.io
export const intercom: Template = {
  id: "intercom",
  displayName: "Intercom access token",
  kind: "api-key",
  category: "customers",
  docsUrl: "https://app.intercom.com/a/apps/_/developer-hub",
  binding: { hosts: ["api.intercom.io", "api.eu.intercom.io", "api.au.intercom.io"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "allow", methods: ["POST"], paths: ["/contacts/search", "/conversations/search", "/tickets/search", "/companies/list"], note: "searches" },
      {
        action: "approve",
        methods: ["POST"],
        paths: ["/conversations/*/reply", "/tickets/*/reply", "/messages", "/conversations", "/news/news_items", "/phone_call_redirects"],
        note: "messages a customer",
      },
    ],
  },
  ceiling: "placeholder",
  fields: { key: { label: "Access token" } },
}

import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, WRITES } from "./shared.ts"

// A HubSpot private app's access token. Without a human: reads, CRM
// searches and batch reads. Creating or changing records and everything
// else need an approval; sending marketing or transactional email,
// sending a conversation message and enrolling contacts in sequences are
// pinned to one. Users, webhooks, SMTP tokens and OAuth tokens are
// refused. https://developers.hubspot.com/docs/api-reference/overview
export const hubspotPrivateApp: Template = {
  id: "hubspot-private-app",
  displayName: "HubSpot private app token",
  kind: "api-key",
  category: "customers",
  docsUrl: "https://developers.hubspot.com/docs/apps/legacy-apps/private-apps/overview",
  binding: { hosts: ["api.hubapi.com"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "allow",
        methods: ["POST"],
        paths: ["/crm/v3/objects/*/search", "/crm/v3/objects/*/batch/read", "/crm/objects/*/*/search", "/crm/objects/*/*/batch/read"],
        note: "CRM searches and batch reads",
      },
      {
        action: "approve",
        methods: ["POST"],
        paths: ["/marketing/**/send", "/marketing/**/single-send", "/conversations/*/conversations/threads/*/messages", "/automation/**/enrollments"],
        note: "sends email or a message, or enrols a contact in a sequence",
      },
      { action: "deny", methods: WRITES, paths: ["/settings/*/users/**", "/settings/users/**"], note: "adds, changes or removes users" },
      { action: "deny", methods: WRITES, paths: ["/webhooks/**", "/app-webhooks/**", "/webhooks-journal/**"], note: "webhooks" },
      { action: "deny", methods: WRITES, paths: ["/marketing/*/transactional/smtp-tokens/**"], note: "mints SMTP tokens" },
      { action: "deny", methods: WRITES, paths: ["/oauth/**"], note: "OAuth tokens" },
    ],
  },
  ceiling: "placeholder",
  fields: { key: { label: "Access token", pattern: "^pat-" } },
  prefixes: ["pat-na1-", "pat-eu1-"],
  setup: {
    title: "In HubSpot",
    steps: [
      { title: "Create a private app", body: "In HubSpot, Settings, then Integrations, then Private apps (Legacy apps in newer portals), then Create. The guide walks through it.", docs: true },
      { title: "Tick only the scopes it needs", body: "On Scopes, tick the read scopes for the objects the agent reads, for example crm.objects.contacts.read, and write scopes only where it is to change records.", field: "key" },
    ],
  },
}

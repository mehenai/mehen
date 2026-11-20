import { OAUTH_PROVIDERS, TEMPLATES } from "@mehen/protocol/templates"
import { z } from "zod"
import { redirectUri, templatesJson } from "../commands/templates.ts"
import { READS, outputSchema, plain, tool } from "./shared.ts"

// With no id, what an agent picks by: the title, category and hosts (an
// agent that knows only an API host finds its template), a template's kind,
// which vault_request needs beside it, and a provider's client template,
// which vault_connect asks for when no client exists. One id has the rest.
export function templatesSummary(): Record<string, unknown> {
  return {
    templates: Object.values(TEMPLATES).map((t) => ({ id: t.id, title: t.displayName, category: t.category, kind: t.kind, hosts: t.binding.hosts })),
    oauthProviders: Object.values(OAUTH_PROVIDERS).map((p) => ({ id: p.id, title: p.displayName, category: p.category, clientTemplate: p.clientTemplate, hosts: p.upstream.binding.hosts })),
  }
}

export const vaultTemplates = tool({
  name: "vault_templates",
  title: "Credential templates",
  description:
    "The credential templates and OAuth providers you may name as `provider` in vault_request (and vault_connect when served), one short entry each with its hosts. No network, creates nothing. " +
    "With `id`, one in full: scopes, what it allows without a human, holds for approval and refuses, its docs link and the redirect URI an OAuth client must list.",
  input: z.object({ id: z.string().optional().describe("a template or OAuth provider id, e.g. openai or google-gmail, for its full detail") }),
  annotations: READS,
  output: outputSchema({ templates: "array", oauthProviders: "array" }),
  async call(args, deps) {
    if (args.id === undefined) return plain(templatesSummary())
    return plain(templatesJson(await redirectUri(deps.env), args.id))
  },
})

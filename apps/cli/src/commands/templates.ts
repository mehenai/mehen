// mehen templates: everything an agent may name as a provider, from the
// protocol's TEMPLATES and OAUTH_PROVIDERS. No network: this works before
// enrolment and never creates anything.

import { EXIT, type Injection, type PolicyInput } from "@mehen/protocol/api"
import { type PolicySummary, summarisePolicy } from "@mehen/protocol/policy-summary"
import {
  OAUTH_PROVIDERS,
  type OAuthProviderTemplate,
  TEMPLATES,
  TEMPLATE_CATEGORIES,
  type Template,
  type TemplateCategory,
  connectionPolicy,
  getOAuthProvider,
  getTemplate,
} from "@mehen/protocol/templates"
import type { ParsedArgs } from "../args.ts"
import type { Command } from "../command.ts"
import { type Config, type Env, resolveVaultUrl } from "../config.ts"
import { selectSlot } from "../slots.ts"
import { CliError, usageError } from "../errors.ts"
import { NEW_FLAGS, NEW_USAGE, findRepoRoot, newTemplateInput, newTemplateLines, notInCheckout, writeNewTemplate } from "./templates-new.ts"
import { printJson, printLine, table } from "../output.ts"
import { type Text, visibleText } from "../tty.ts"

export const OAUTH_CALLBACK_PATH = "/oauth/callback"

// The redirect URI an OAuth client must list, derived from the vault this
// machine uses (MEHEN_VAULT_URL, then the selected slot's vault, then the
// default).
export async function redirectUri(env: Env): Promise<string> {
  let config: Config | null = null
  try {
    config = (await selectSlot(env, { manifest: null })).config
  } catch {
    config = null
  }
  return `${resolveVaultUrl(env, config)}${OAUTH_CALLBACK_PATH}`
}

export function shortScope(provider: OAuthProviderTemplate, scope: string): string {
  const prefix = provider.auth.scopes.shortPrefix
  return prefix && scope.startsWith(prefix) ? scope.slice(prefix.length) : scope
}

function docsHost(url: string | null): string {
  if (!url) return "-"
  return url.replace(/^https?:\/\//, "").replace(/#.*$/, "").replace(/\/$/, "")
}

// "api.cloudflare.com /client/v4/**", "api.linear.app POST /graphql",
// "oauth2.googleapis.com (token only)" for an OAuth client.
export function goesTo(template: Template): string {
  const hosts = template.binding.hosts.join(", ")
  if (template.kind === "oauth-client") return `${hosts} (token only)`
  const methods = template.binding.methods?.length ? ` ${template.binding.methods.join("/")}` : ""
  const paths = template.binding.paths?.length ? ` ${template.binding.paths.join(", ")}` : ""
  return `${hosts}${methods}${paths}`
}

export type PolicySummaryLines = { allowed: string; approve: string; deny: string }

// The three policy lines. "anything else" lands on the list the default
// sends unnamed requests to, so the summary never implies an allow the
// policy does not grant; an empty list reads "nothing", and a default with
// no named rules reads "anything".
export function policySummaryLines(summary: PolicySummary): PolicySummaryLines {
  const noRules = summary.allowed.length + summary.approve.length + summary.deny.length === 0
  const line = (list: string[], rest: boolean) => {
    if (rest && noRules) return "anything"
    const phrases = rest ? [...list, "anything else"] : list
    return phrases.length ? phrases.map(visibleText).join("; ") : "nothing"
  }
  return {
    allowed: line(summary.allowed, summary.rest === "allowed"),
    approve: line(summary.approve, summary.rest === "approve"),
    deny: line(summary.deny, summary.rest === "deny"),
  }
}

// Built-in templates were written and reviewed by a human, so their notes
// are shown; a policy from an item is summarised from its matchers unless
// the caller knows better.
export function templateSummary(policy: PolicyInput): PolicySummary {
  return summarisePolicy(policy, { notes: "trusted" })
}

// "Authorization: Bearer {key}", "query key={key}", "basic auth", "headers from {field}".
export function injectionText(injection: Injection): string {
  if (injection.in === "header") return `${injection.name}: ${injection.format}`
  if (injection.in === "query") return `query ${injection.name}={${injection.field}}`
  if (injection.in === "basic") return "basic auth"
  return `headers from field ${injection.field}`
}

const DETAIL_LABEL = 18

function detail(label: string, value: string): string {
  return `  ${`${label}:`.padEnd(DETAIL_LABEL)} ${value}`
}

function policyDetail(summary: PolicySummary): string[] {
  const lines = policySummaryLines(summary)
  return [detail("without a human", lines.allowed), detail("needs approval", lines.approve), detail("refused", lines.deny)]
}

function categoryTitle(category: TemplateCategory): string {
  return TEMPLATE_CATEGORIES.find((c) => c.id === category)?.title ?? category
}

function templateDetail(template: Template, callback: string): string[] {
  const lines = [`${template.id}: ${template.displayName} (${template.kind} template)`]
  lines.push(detail("category", categoryTitle(template.category)))
  if (template.docsUrl) lines.push(detail("docs", template.docsUrl))
  if (template.kind === "oauth-client") lines.push(detail("redirect URI", `${callback}   (the OAuth client at the provider must list this)`))
  lines.push(detail("goes to", goesTo(template)))
  if (template.injection) lines.push(detail("injection", injectionText(template.injection)))
  lines.push(detail("ceiling", template.ceiling))
  lines.push(...policyDetail(templateSummary(template.policy)))
  lines.push(detail("request", `mehen request ${template.kind} --name <slug> --provider ${template.id} --reason "<why>"`))
  return lines
}

function providerDetail(provider: OAuthProviderTemplate, callback: string): string[] {
  const { binding } = provider.upstream
  const paths = binding.paths?.length ? ` ${binding.paths.join(", ")}` : ""
  return [
    `${provider.id}: ${provider.displayName} (OAuth provider; client template ${provider.clientTemplate})`,
    detail("category", categoryTitle(provider.category)),
    detail("docs", provider.docsUrl),
    detail("redirect URI", `${callback}   (the OAuth client at the provider must list this)`),
    detail("default scopes", provider.auth.scopes.defaults.map((s) => shortScope(provider, s)).join(", ")),
    detail("allowed scopes", provider.auth.scopes.allowed.map((s) => shortScope(provider, s)).join(", ")),
    detail("goes to", `${binding.hosts.join(", ")}${paths}`),
    ...policyDetail(templateSummary(connectionPolicy(provider))),
    detail("connect", `mehen connect ${provider.id} --name <slug> --reason "<why>" [--expect <account>]`),
  ]
}

// One table, its columns aligned across every section, with each
// category's title above its rows, in the order of TEMPLATE_CATEGORIES.
function groupedTable(header: string[], rows: { category: TemplateCategory; cells: string[] }[]): Text[] {
  const sections = TEMPLATE_CATEGORIES.map((c) => ({ title: c.title, rows: rows.filter((r) => r.category === c.id) })).filter((s) => s.rows.length > 0)
  const [head, ...lines] = table([header, ...sections.flatMap((s) => s.rows.map((r) => r.cells))])
  const out: Text[] = head ? [head] : []
  for (const section of sections) out.push("", `${section.title}:`, ...lines.splice(0, section.rows.length))
  return out
}

function listLines(callback: string): Text[] {
  const templates = Object.values(TEMPLATES).map((t) => ({ category: t.category, cells: [t.id, t.kind, goesTo(t), docsHost(t.docsUrl)] }))
  const providers = Object.values(OAUTH_PROVIDERS).map((p) => ({
    category: p.category,
    cells: [p.id, p.displayName, p.clientTemplate, p.auth.scopes.defaults.map((s) => shortScope(p, s)).join(", "), p.upstream.binding.hosts.join(", ")],
  }))
  return [
    "CREDENTIAL TEMPLATES   mehen request <kind> --name <slug> --provider <id> --reason <why>",
    ...groupedTable(["ID", "KIND", "GOES TO", "DOCS"], templates),
    "",
    "OAUTH PROVIDERS   mehen connect <id> --name <slug> --reason <why> [--expect <account>]",
    ...groupedTable(["ID", "NAME", "CLIENT TEMPLATE", "DEFAULT SCOPES", "API"], providers),
    "",
    `OAuth clients must list the redirect URI ${callback}`,
    "mehen templates <id> shows what a template allows without a human, holds for approval and refuses.",
  ]
}

// The ids an unknown id may have meant: those it starts, or that have it
// as one of their hyphenated words (github: github-pat, github-oauth).
function similarIds(id: string): string[] {
  const wanted = id.toLowerCase()
  if (wanted === "") return []
  return [...Object.keys(TEMPLATES), ...Object.keys(OAUTH_PROVIDERS)].filter((candidate) => candidate.startsWith(wanted) || candidate.split("-").includes(wanted))
}

function orList(ids: string[]): string {
  return ids.length === 1 ? (ids[0] ?? "") : `${ids.slice(0, -1).join(", ")} or ${ids.at(-1)}`
}

// Where a templates answer goes: the mehen command line, or the MCP
// vault_templates tool, whose next steps name no mehen command.
export type TemplatesSurface = "cli" | "mcp"

// One template or OAuth provider by id; not_found names the ids it may have
// meant, else the way to list them.
function templateOrProvider(id: string, surface: TemplatesSurface): { template: Template } | { provider: OAuthProviderTemplate } {
  const template = getTemplate(id)
  if (template) return { template }
  const provider = getOAuthProvider(id)
  if (provider) return { provider }
  const message = `No template or OAuth provider is called ${JSON.stringify(id)}.`
  const similar = similarIds(id)
  if (similar.length === 0) throw new CliError("not_found", message, { command: "mehen templates", say: "List the templates and providers with `mehen templates` and use an id from there." })
  const say = `Did you mean ${orList(similar)}?`
  if (similar.length === 1 && surface === "cli") throw new CliError("not_found", message, { command: `mehen templates ${similar[0]} --json`, say })
  throw new CliError("not_found", message, { say })
}

// The --json body of mehen templates [<id>], shared with the MCP vault_templates
// tool: every template and provider with its category and policy summary,
// and the categories in order, or one of them with its redirect URI where
// an OAuth client needs it. vault_templates calls it without a surface.
export function templatesJson(callback: string, id: string | undefined, surface: TemplatesSurface = "mcp"): Record<string, unknown> {
  if (id === undefined) {
    return {
      categories: TEMPLATE_CATEGORIES,
      templates: Object.values(TEMPLATES).map((t) => ({ ...t, policySummary: templateSummary(t.policy) })),
      oauthProviders: Object.values(OAUTH_PROVIDERS).map((p) => ({ ...p, policy: connectionPolicy(p), policySummary: templateSummary(connectionPolicy(p)) })),
      redirectUri: callback,
    }
  }
  const found = templateOrProvider(id, surface)
  if ("template" in found) {
    const { template } = found
    return { type: "template", ...template, ...(template.kind === "oauth-client" ? { redirectUri: callback } : {}), policySummary: templateSummary(template.policy) }
  }
  const policy = connectionPolicy(found.provider)
  return { type: "oauth-provider", ...found.provider, policy, redirectUri: callback, policySummary: templateSummary(policy) }
}

// mehen templates new, inside a checkout of this repository: `start` is
// where the search for its root begins.
export function runTemplatesNew(args: ParsedArgs, json: boolean, start: string): number {
  const input = newTemplateInput(args.positionals[1], args)
  const root = findRepoRoot(start)
  if (root === null) throw notInCheckout(start)
  const result = writeNewTemplate(root, input)
  if (json) printJson({ ...result, root })
  else for (const line of newTemplateLines(result, input)) printLine(line)
  return EXIT.ok
}

export const templatesCommand: Command = {
  summary: "list the credential templates and OAuth providers an agent may name (no network), or write a new template in a checkout of the Mehen repository",
  spec: {
    usage: `mehen templates [<id>] | ${NEW_USAGE}`,
    flags: { host: { type: "list" }, path: { type: "list" }, header: { type: "string" }, format: { type: "string" }, docs: { type: "string" }, name: { type: "string" }, category: { type: "string" }, prefix: { type: "list" } },
    positionals: { min: 0, max: 2 },
  },
  examples: [
    ["templates"],
    ["templates", "google-gmail", "--json"],
    ["templates", "new", "acme", "--host", "api.acme.com", "--category", "productivity", "--docs", "https://acme.com/settings/api-keys"],
    ["templates", "new", "acme", "--host", "api.acme.com", "--path", "/v2/**", "--header", "X-Api-Key", "--format", "{key}", "--prefix", "acme_", "--category", "ai"],
  ],
  notes: [
    "new writes a template with the safe defaults (reads allowed, every other method held for approval, ceiling placeholder, kind api-key, exact hosts), its test, and its entry in the template index, then prints the files and the test command. It runs only inside a checkout of the Mehen repository, from any folder in it, and never touches the network or the vault.",
    "new refuses an id that exists or does not match ^[a-z][a-z0-9-]{1,40}$, a host that is not a plain lower-case DNS name, a docs URL that is not https, a reserved header and a format without {key}. The key goes in Authorization as Bearer {key} unless --header and --format say otherwise. A new --prefix is added to the placeholder prefixes too.",
  ],
  async run({ args, json, env }) {
    if (args.positionals[0] === "new") return runTemplatesNew(args, json, process.cwd())
    const stray = NEW_FLAGS.filter((f) => args.list(f).length > 0 || args.string(f) !== null)
    if (stray.length) throw usageError(`${stray.map((f) => `--${f}`).join(", ")} belong${stray.length === 1 ? "s" : ""} to mehen templates new.`, "mehen templates --help")
    if (args.positionals.length > 1) throw usageError("Usage: mehen templates [<id>]", "mehen templates --help")
    const callback = await redirectUri(env)
    const id = args.positionals[0]
    if (json) {
      printJson(templatesJson(callback, id, "cli"))
      return EXIT.ok
    }
    if (id === undefined) {
      for (const line of listLines(callback)) printLine(line)
      return EXIT.ok
    }
    const found = templateOrProvider(id, "cli")
    const lines = "template" in found ? templateDetail(found.template, callback) : providerDetail(found.provider, callback)
    for (const line of lines) printLine(line)
    return EXIT.ok
  },
}

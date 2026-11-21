// mehen run --item <slug>[=VAR]: items given to one command with no project.
//
// Design. Nothing new is asked of the vault. Each item is read with
// GET /v1/items/<slug>, the child gets a stand-in made by the protocol's
// placeholder generator from the item's well-known prefix (random per run,
// never derived from a secret), and the run's local relay intercepts exactly
// the hosts the vault returned for the item. A request to one of those hosts
// that carries the item's stand-in goes to the vault as an item-mode
// /v1/relay call ({ item, method, url, headers, body }), the body
// mehen fetch and vault_fetch send, so the vault authorises, fences, applies
// policy, asks, injects over the declared surface and audits it as a fetch.
// A request without the stand-in is refused locally, so no other call to the
// host is ever credentialed. No lease, no vault run, nothing to renew: the
// machine gets what vault_fetch already gives it, one request at a time.

import { isIP } from "node:net"
import { z } from "zod"
import { EXIT, EXIT_FOR_ERROR, InjectionSchema, Slug, VarName, type Injection } from "@mehen/protocol/api"
import { LEASE_ONLY_HOST, isLeaseOnly, hostMatches } from "@mehen/protocol/binding"
import { newPlaceholder } from "@mehen/protocol/placeholder"
import { getTemplate } from "@mehen/protocol/templates"
import { usageError } from "../errors.ts"
import { VaultApiError, type VaultApi } from "../vault-api.ts"
import { CommandError } from "./deps.ts"

export type AdHocSpec = { item: string; variable: string | null }

export type AdHocItem = {
  item: string
  variable: string
  // The hosts the vault returned for the item, each one a name constraint the run CA can carry.
  hosts: string[]
  standIn: string
}

const RUN_HELP = "mehen run --help"
const MANIFEST_NEXT = "Use it through a project instead: mehen init, then mehen env set <NAME> --env <env> --item <slug>, then mehen run."

// `<slug>` or `<slug>=<VAR>`, as typed after --item.
export function parseItemSpec(text: string): AdHocSpec {
  const at = text.indexOf("=")
  const item = at === -1 ? text : text.slice(0, at)
  const variable = at === -1 ? null : text.slice(at + 1)
  if (!Slug.safeParse(item).success) throw usageError(`--item ${JSON.stringify(text)}: ${JSON.stringify(item)} is not a credential name. Give --item <slug> or --item <slug>=<VAR>.`, RUN_HELP)
  if (variable !== null && !VarName.safeParse(variable).success) {
    throw usageError(`--item ${JSON.stringify(text)}: ${JSON.stringify(variable)} is not an environment variable name. Use letters, digits and underscores, not starting with a digit.`, RUN_HELP)
  }
  return { item, variable }
}

// The same item twice is refused: one item, one stand-in, one variable.
export function checkItemSpecs(specs: readonly AdHocSpec[]): void {
  const seen = new Set<string>()
  for (const spec of specs) {
    if (seen.has(spec.item)) throw usageError(`--item ${spec.item} is given twice. Give each credential once.`, RUN_HELP)
    seen.add(spec.item)
  }
}

const DNS_LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/

function dnsName(name: string): boolean {
  const labels = name.split(".")
  return name.length <= 253 && labels.every((label) => DNS_LABEL.test(label))
}

// Whether a binding host is something the run CA's name constraints express
// exactly: a lower-case DNS name, "*." over a name of at least two labels
// (".example.com" in the CA permits any depth below and never the apex, as
// hostMatches admits), or an IP address. Anything else, a wildcard over a
// whole top-level domain included, is refused rather than approximated.
export function constrainableHost(pattern: string): boolean {
  const bare = pattern.replace(/^\[(.*)\]$/, "$1")
  if (isIP(bare) !== 0) return true
  if (pattern !== pattern.toLowerCase()) return false
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(2)
    return suffix.includes(".") && dnsName(suffix)
  }
  return dnsName(pattern)
}

function covers(wildcard: string, other: string): boolean {
  if (!wildcard.startsWith("*.")) return false
  const bare = other.startsWith("*.") ? other.slice(2) : other
  if (bare === wildcard.slice(2)) return other.startsWith("*.")
  return hostMatches(wildcard, bare)
}

// Whether one host could be matched by both patterns.
export function hostsOverlap(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase() || covers(a, b) || covers(b, a)
}

// What the child may not receive twice: a variable from two places, or a
// host two routes would both claim, since the relay could not tell which
// credential a request to it is for.
export function checkAdHocConflicts(items: readonly AdHocItem[], manifestVars: readonly string[], runHosts: readonly string[]): void {
  const variables = new Map<string, string>()
  for (const item of items) {
    const other = variables.get(item.variable)
    if (other !== undefined) throw usageError(`--item ${other} and --item ${item.item} both set ${item.variable}. Give one of them another name with --item <slug>=<VAR>.`, RUN_HELP)
    variables.set(item.variable, item.item)
    if (manifestVars.includes(item.variable)) {
      throw usageError(`--item ${item.item} sets ${item.variable}, which this checkout's mehen.toml also declares. Name it differently with --item ${item.item}=<VAR>, or drop --item and use the project's value.`, RUN_HELP)
    }
  }
  for (const [i, item] of items.entries()) {
    for (const host of item.hosts) {
      const clash = items.slice(i + 1).find((other) => other.hosts.some((h) => hostsOverlap(h, host)))
      if (clash !== undefined) throw new CommandError(EXIT.usage, `--item ${item.item} and --item ${clash.item} are both bound to ${host}, so mehen could not tell which one a request is for`, { say: "Run them in separate commands, or call one of them with mehen fetch." })
      const runHost = runHosts.find((h) => hostsOverlap(h, host))
      if (runHost !== undefined) throw new CommandError(EXIT.usage, `--item ${item.item} is bound to ${host}, which this project's run already intercepts for one of its variables`, { say: "Drop --item and use the project's variable, or run the item in a separate command outside the project." })
    }
  }
}

// What an ad hoc run needs from GET /v1/items/<slug>. Read field by field,
// so a vault that leaves one out is named rather than guessed at.
const Description = z.object({
  slug: z.string(),
  provider: z.string().nullable(),
  status: z.string(),
  binding: z.object({ hosts: z.array(z.string()) }),
  injection: InjectionSchema.nullable(),
  secretFields: z.array(z.object({ name: z.string(), prefix: z.string() })),
})
type Description = z.infer<typeof Description>

// The secret field whose value the injection sends, for its well-known prefix.
function injectedField(injection: Injection, secretNames: readonly string[]): string | null {
  if (injection.in === "query") return injection.field
  if (injection.in === "basic") return injection.password
  if (injection.in === "header") return [...injection.format.matchAll(/\{([a-z][a-z0-9_]*)\}/g)].map((m) => m[1] ?? "").find((name) => secretNames.includes(name)) ?? null
  return null
}

function refused(slug: string, why: string, say: string, command?: string): CommandError {
  return new CommandError(EXIT.refused, `--item ${slug}: ${why}`, { say, ...(command !== undefined ? { command } : {}) })
}

async function describe(api: VaultApi, slug: string): Promise<Description> {
  let answer: unknown
  try {
    answer = await api.request<unknown>("GET", `/v1/items/${slug}`)
  } catch (error) {
    if (error instanceof VaultApiError && error.body.error === "not_found") {
      throw new CommandError(EXIT_FOR_ERROR.not_found, `--item ${slug}: the vault does not let this machine use ${slug} outside a project`, {
        say: "Check the name with mehen ls. A private credential needs a machine allowed your private credentials. A credential behind a protected environment is used only in an approved run of its project: mehen run --env <env> in a checkout with mehen.toml.",
        command: "mehen ls",
      })
    }
    if (error instanceof VaultApiError && (error.status === 404 || error.status === 405)) throw outdatedVault(slug, "it does not describe credentials")
    throw error
  }
  const parsed = Description.safeParse(answer)
  if (!parsed.success) throw outdatedVault(slug, `its description of ${slug} lacks ${parsed.error.issues.map((issue) => issue.path.join(".") || "a field").join(", ")}`)
  return parsed.data
}

function outdatedVault(slug: string, why: string): CommandError {
  return new CommandError(EXIT.error, `--item ${slug}: this vault cannot serve an ad hoc run: ${why}`, { say: `Update the vault, or use ${slug} through a project: mehen init, then mehen env set <NAME> --env <env> --item ${slug}, then mehen run.` })
}

// Each item read, checked and given its variable and stand-in, or the
// refusal for the first that cannot be used outside a project.
export async function resolveAdHocItems(api: VaultApi, specs: readonly AdHocSpec[]): Promise<AdHocItem[]> {
  const items: AdHocItem[] = []
  for (const spec of specs) {
    const described = await describe(api, spec.item)
    const slug = spec.item
    const hosts = described.binding.hosts
    if (isLeaseOnly({ hosts }) || hosts.includes(LEASE_ONLY_HOST)) {
      throw refused(slug, "it is a lease-only credential, which is delivered as its real value and only to a project's variable", MANIFEST_NEXT.replaceAll("<slug>", slug), "mehen init")
    }
    if (described.status === "disabled") throw refused(slug, "it is disabled", "Ask a human to enable it in the vault, or use another credential.")
    if (described.injection === null || described.injection.in === "headers") {
      throw refused(slug, "it is not sent as one key in a header or query parameter, so a program cannot hold a stand-in for it", `Call it with mehen fetch ${slug} <METHOD> <url> instead.`)
    }
    const unsafe = hosts.find((host) => !constrainableHost(host))
    if (unsafe !== undefined || hosts.length === 0) {
      throw refused(slug, hosts.length === 0 ? "it is bound to no host" : `its host ${JSON.stringify(unsafe)} cannot be held to exactly that host by the run's certificate authority`, `Call it with mehen fetch ${slug} <METHOD> <url> instead, or ask a human to bind it to exact hosts in the vault.`)
    }
    const variable = spec.variable ?? getTemplate(described.provider ?? "")?.defaultEnvVar ?? null
    if (variable === null) {
      throw usageError(`--item ${slug}: its template names no variable, so mehen cannot tell what to call it. Name it with --item ${slug}=<VAR>.`, RUN_HELP)
    }
    const field = injectedField(described.injection, described.secretFields.map((f) => f.name))
    const prefix = described.secretFields.find((f) => f.name === field)?.prefix ?? ""
    // A CONNECT names an IPv6 address without brackets, so the route does too.
    const routeHosts = hosts.map((host) => host.replace(/^\[(.*)\]$/, "$1"))
    items.push({ item: slug, variable, hosts: routeHosts, standIn: newPlaceholder(prefix) })
  }
  return items
}

// mehen request, mehen connect and mehen wait: ask a human for a credential or an
// OAuth connection, then wait for them (or for an approval, or for an
// enrolment this machine started) to act. Every link goes out as the ask
// block (ask.ts) and is recorded in the ledger, so it can be waited on and
// re-shown from any process on this machine.

import { EXIT, type ItemSummary, type NextStep } from "@mehen/protocol/api"
import { isLeaseOnly, leaseOnlyDelivery } from "@mehen/protocol/binding"
import { OAUTH_PROVIDERS, getOAuthProvider, getTemplate } from "@mehen/protocol/templates"
import { type Ask, type AskUrl, type AskVault, askNext, askUrl, askUrlFor, bundleAsk, clockText, connectAsk, intakeAsk, isWaitId, policyAsk, refusedLinkWarning, requestedBy, withContext } from "../ask.ts"
import type { Command } from "../command.ts"
import { type Env } from "../config.ts"
import { type Attempt, type Finished, followAttempt } from "./activate.ts"
import { CliError, exitCodeFor, toCliError, usageError } from "../errors.ts"
import { type LedgerEntry, type LedgerScope, addLedgerEntry, findLedgerEntry, readLedger, removeLedgerEntry } from "../ledger.ts"
import { type HumanWriter, errorJson, note, printAsk, printJson, printLine, reportError } from "../output.ts"
import {
  type ConnectInput,
  type IntakeInput,
  OAUTH_CALLBACK_PATH,
  type WaitKind,
  type WaitLedger,
  type WaitResult,
  chooseOauthClient,
  clientRequestReason,
  clockDown,
  connectCommandText,
  createConnect,
  durationText,
  knownOauthProvider,
  missingClientError,
  parseDurationSeconds,
  pickSummary,
  privateHomeUnavailable,
  pushBeingSent,
  pushWords,
  requestCommandText,
  requestIntake,
  resolveHome,
  waitFor,
  waitTarget,
  withPrivateHomeExplained,
} from "../operations.ts"
import { manifestWorkspace } from "../run/manifest.ts"
import { rememberedRule, ruleUntilText } from "../policy-operations.ts"
import { RuleRefSchema } from "../policy-responses.ts"
import { noHostText } from "./items.ts"
import { askFromServerEntry } from "./pending.ts"
import { selectSlot } from "../slots.ts"
import { committedEnrolment, openEnrolmentSession, openSession, pollIntervalMs, sessionLabel } from "../session.ts"
import { type Segment, type Styler, colourEnabled, isTty, segments, styler, terminalText } from "../tty.ts"

// The link and the id as they may be handed over: `url` is null when no
// link passed the check, `id` is null when the vault's id is not one mehen
// knows (so it never goes into a command or a line of text).
export type CheckedLink = { url: AskUrl | null; id: string | null; warning: string | null }

// The vault's link when askUrl accepts it against the vault this machine
// uses and its route id is the id the answer names; otherwise the link
// built from the id on that vault (an id that is not one gives no link),
// with the warning the human sees. A link from the answer that fails the
// check is never handed over. mehen request, mehen connect and the MCP tools all
// take their links through this.
// `url` is absent only from a managed workspace's answer (platform mode),
// which no person's machine reaches; it is then treated as a refused link.
export function checkedLink(url: string | undefined, kind: "intake" | "connect", id: string, vaultUrl: AskVault): CheckedLink {
  const validId = isWaitId(kind, id) ? id : null
  const given = url === undefined ? null : askUrl(url, vaultUrl)
  if (given && given.route && validId !== null && given.route.prefix === (kind === "intake" ? "i" : "c") && given.route.id === validId) {
    return { url: given.url, id: validId, warning: null }
  }
  return { url: validId === null ? null : (askUrlFor(vaultUrl, kind, validId)?.url ?? null), id: validId, warning: refusedLinkWarning(vaultUrl) }
}

// `url` and `id` are the checked ones (null when refused), the warning the
// sentence that stands in for them.
export function intakeNext(intake: string | null, url: AskUrl | null, warning: string | null = null): NextStep {
  const command = intake === null ? {} : { command: `mehen wait ${intake}` }
  if (!url) return { ...command, say: warning ?? "The vault returned no usable link." }
  const say = `Please open ${url} to provide this credential; it goes into the vault, never to the agent.`
  return { url, ...command, say: warning ? `${warning} ${say}` : say }
}

export function connectNext(connect: string | null, url: AskUrl | null, warning: string | null = null): NextStep {
  const command = connect === null ? {} : { command: `mehen wait ${connect}` }
  if (!url) return { ...command, say: warning ?? "The vault returned no usable link." }
  const say = `Please open ${url} and sign in to connect the account; the agent never sees the tokens.`
  return { url, ...command, say: warning ? `${warning} ${say}` : say }
}

// The `next` for a created ask: generated from the ask when there is one
// (the same words as the block), else the fallback with the warning.
export function nextFor(ask: Ask | null, link: CheckedLink, fallback: (id: string | null, url: AskUrl | null, warning: string | null) => NextStep, now: Date): NextStep {
  if (!ask) return fallback(link.id, link.url, link.warning)
  const next = askNext(ask, { now })
  return link.warning ? { ...next, say: `${link.warning} ${next.say}` } : next
}

function splitList(values: string[]): string[] {
  return values.flatMap((v) => v.split(",")).map((v) => v.trim()).filter(Boolean)
}

// --header NAME --format "Bearer {key}": the proposed header injection.
function headerInjection(name: string | null, format: string | null) {
  if (name === null && format === null) return null
  if (name === null || format === null) {
    throw usageError('A proposed injection needs both --header <name> and --format <format>, for example --header Authorization --format "Bearer {key}".', "mehen request --help")
  }
  return { in: "header" as const, name, format }
}

export const WAIT_DEFAULT_SECONDS = 600
export const WAIT_MAX_SECONDS = 86_400

// --timeout on wait, request and connect: 10 min unless given.
export function timeoutSeconds(text: string | null, help: string): number {
  return text === null ? WAIT_DEFAULT_SECONDS : parseDurationSeconds(text, { max: WAIT_MAX_SECONDS, flag: "--timeout", help })
}

// ---------------------------------------------------------------- the ledger around an ask

type Recorded = { entry: LedgerEntry; reissued: boolean }

// Records the ask, unless the vault handed back a link this machine already
// holds (the server reuses an open ask per device and slug): then the
// earlier entry stands, its createdAt included, so "already asked" is true
// and the expiry is never extended from here.
export async function recordAsk(dir: string, scope: LedgerScope, ask: Ask, slug: string, command: string, now: Date): Promise<Recorded> {
  const existing = findLedgerEntry(await readLedger(dir, scope, now), ask.id)
  if (existing && existing.ask.id === ask.id && existing.ask.url === ask.url) return { entry: existing, reissued: true }
  return { entry: await addLedgerEntry(dir, scope, { ask, slug, command, now }), reissued: false }
}

function sinceText(iso: string, now: Date): string {
  const ms = now.getTime() - Date.parse(iso)
  if (!Number.isFinite(ms) || ms < 60_000) return "under a minute ago"
  return `${durationText(ms / 1000)} ago`
}

function noteReissue(recorded: Recorded, now: Date): void {
  if (recorded.reissued) note(`mehen: already asked ${sinceText(recorded.entry.createdAt, now)}; same link`)
}

// ---------------------------------------------------------------- mehen request

export type RequestAskInput = { link: CheckedLink; input: IntakeInput; expiresAt: string; vaultUrl: string; env: Env; machineName: string | null }

export function requestAsk({ link, input, expiresAt, vaultUrl, env, machineName }: RequestAskInput): Ask | null {
  if (!link.url || link.id === null) return null
  return intakeAsk({
    id: link.id,
    url: link.url,
    name: input.name,
    kind: input.kind,
    provider: input.provider,
    reason: input.reason,
    hosts: input.hosts,
    redirectUri: input.kind === "oauth-client" ? `${vaultUrl}${OAUTH_CALLBACK_PATH}` : null,
    expiresAt,
    requestedBy: requestedBy(env, machineName),
  })
}

const THEN_OR_WAIT = (wait: string) => `${wait}   (or add --wait to this command)`
export const THEN_KEEPS_WAITING = (wait: string) => `mehen keeps waiting (Ctrl-C is safe: ${wait} resumes)`

export const requestCommand: Command = {
  summary: "ask a human for a credential (prints the link for them)",
  spec: {
    usage:
      'mehen request <kind> --name <slug> --reason <why> [--provider <template>] [--home private|project|workspace] [--project <prj_id>] [--tag <tag>]... [--host <host>]... [--path <glob>]... [--header <name> --format "Bearer {key}"] [--wait] [--new] [--timeout <duration>]',
    flags: {
      name: { type: "string" },
      home: { type: "string" },
      project: { type: "string" },
      provider: { type: "string" },
      reason: { type: "string" },
      tag: { type: "list" },
      host: { type: "list" },
      path: { type: "list" },
      header: { type: "string" },
      format: { type: "string" },
      wait: { type: "boolean" },
      new: { type: "boolean" },
      timeout: { type: "string" },
    },
    positionals: { min: 1, max: 1 },
  },
  examples: [
    ["request", "api-key", "--name", "openai-personal", "--provider", "openai", "--reason", "run the nightly evals against the OpenAI API", "--json"],
    ["request", "api-key", "--name", "snyk", "--host", "api.snyk.io", "--header", "Authorization", "--format", "token {key}", "--reason", "scan this repo's dependencies"],
    ["request", "api-key", "--name", "openai-team", "--provider", "openai", "--home", "project", "--project", "prj_3kQ9vXyZ7", "--reason", "run the evals for this project"],
  ],
  notes: [
    "Prints the ask block for the human; the value goes into the vault page, never through you. mehen templates lists the providers.",
    "Naming a credential this machine can already reach asks the human to rotate it instead: --home and --provider must match it, only its secret fields are replaced, and its binding and policy stay.",
    "Without --provider, the item holds every request for a human's approval unless the human lets reads through on the page.",
    "Without --provider, --host and --header, a generic, database-url, file or other kind the relay never sends is lease-only: it has no host, the vault never sends it anywhere, and only mehen run delivers it into a process. Use this for secrets such as JWT_SECRET or DATABASE_URL. An api-key, bearer-token, basic-auth, custom-headers or oauth-connection needs --host, and so does --header.",
    "A google-service-account or github-app is refused (bad_request): minting tokens from one is not built, so nothing could use it.",
    "--home says who the credential belongs to: private (only the owner, the default), project (needs --project or the checkout's mehen.toml) or workspace. The human may change it on the page.",
    "A machine accepted without private credentials (a team's machine, a guest's by default, or a member's whose tick was cleared; private: no in mehen status, scope.privateCredentials false in mehen status --json) cannot ask for a private one: it is refused forbidden (exit 5). Ask with --home project --project <prj_id> for a project the person can edit, or --home workspace if they are a workspace owner or admin, or ask the human to open this machine's page under Machines in the web app and allow it to use their private credentials.",
  ],
  async run({ args, json, env }) {
    const name = args.string("name")
    if (!name) throw usageError("Name the item to create with --name <slug>.", "mehen request --help")
    const injection = headerInjection(args.string("header"), args.string("format"))
    const wait = args.bool("wait")
    const timeout = timeoutSeconds(args.string("timeout"), "mehen request --help")
    const now = new Date()
    const { api, vaultUrl, configDir, ledger: scope, context, config } = await openSession(env)
    const home = resolveHome({ home: args.string("home"), project: args.string("project"), manifestProject: manifestWorkspace(process.cwd())?.project ?? null, help: "mehen request --help" })
    const input: IntakeInput = {
      kind: args.positionals[0] as string,
      name,
      home,
      provider: args.string("provider"),
      reason: args.string("reason"),
      tags: splitList(args.list("tag")),
      hosts: splitList(args.list("host")),
      paths: args.list("path"),
      injection,
      session: sessionLabel(env),
      fresh: args.bool("new"),
    }
    const created = await withPrivateHomeExplained(api, home, () => privateHomeUnavailable("cli", requestCommandText({ ...input, home: { home: "project" as const, project: "<prj_id>" } }), args.string("home") === null), () => requestIntake(api, input))
    const link = checkedLink(created.url, "intake", created.intake, scope)
    const ask = withContext(requestAsk({ link, input, expiresAt: created.expiresAt, vaultUrl, env, machineName: config.name ?? null }), context)
    const next = nextFor(ask, link, intakeNext, now)
    const recorded = ask ? await recordAsk(configDir, scope, ask, name, requestCommandText(input), now) : null
    if (json) {
      printJson({ ...created, url: link.url, kind: input.kind, name, provider: input.provider, ...(ask ? { ask } : {}), next, ...(link.warning ? { warning: link.warning } : {}) })
    } else {
      if (link.warning) note(`mehen: warning: ${link.warning}`)
      if (recorded) noteReissue(recorded, now)
      if (ask) printAsk(ask, { env, noQr: args.bool("no-qr"), now, then: ask.wait ? (wait ? THEN_KEEPS_WAITING(ask.wait) : THEN_OR_WAIT(ask.wait)) : null })
      else printLine(`The vault's intake id is not one mehen knows; run \`mehen pending\` to find it (expires ${created.expiresAt}).`)
    }
    if (!wait || !ask) return EXIT.ok
    return runWait(env, ask.id, { json, events: false, noQr: args.bool("no-qr"), timeoutSeconds: timeout, showAsk: false })
  },
}

// ---------------------------------------------------------------- mehen connect

export type ConnectAskInput = { link: CheckedLink; input: ConnectInput & { name: string }; expiresAt: string; env: Env; machineName: string | null }

export function connectAskFor({ link, input, expiresAt, env, machineName }: ConnectAskInput): Ask | null {
  if (!link.url || link.id === null) return null
  return connectAsk({ id: link.id, url: link.url, name: input.name, provider: input.provider, account: input.expect, reason: input.reason, expiresAt, requestedBy: requestedBy(env, machineName) })
}

// The lines under a client_missing error for a human: the one-command way
// through, what the human will need at the provider, and the docs.
export function missingClientLines(error: CliError, input: ConnectInput, s: Styler): Segment[][] {
  const lines: Segment[][] = []
  const chained = connectCommandText({ ...input, requestClient: true })
  lines.push(segments("  ", s.dim("or:  "), ` ${chained}   (asks for the client, waits for it, then continues)`))
  const setup = error.extras.setup
  if (setup) {
    const client = error.extras.request ? (getTemplate(error.extras.request.provider)?.displayName ?? "OAuth client") : "OAuth client"
    lines.push(segments(`  the human will need: a ${client} (web application) with redirect URI ${setup.redirectUri}`))
    if (setup.docsUrl) lines.push(segments("  ", s.dim("docs:"), ` ${setup.docsUrl}`))
  }
  return lines
}

export const connectCommand: Command = {
  summary: "ask a human to connect an OAuth account (prints the link for them)",
  spec: {
    usage: "mehen connect <provider> --name <slug> --reason <why> [--client <oauth-client-item>] [--home private|project|workspace] [--project <prj_id>] [--scopes a,b] [--expect <account>] [--request-client] [--client-tag <tag>]... [--wait] [--new] [--timeout <duration>]",
    flags: {
      client: { type: "string" },
      name: { type: "string" },
      home: { type: "string" },
      project: { type: "string" },
      scopes: { type: "list" },
      expect: { type: "string" },
      reason: { type: "string" },
      "request-client": { type: "boolean" },
      "client-tag": { type: "list" },
      wait: { type: "boolean" },
      new: { type: "boolean" },
      timeout: { type: "string" },
    },
    positionals: { min: 1, max: 1 },
  },
  examples: [
    ["connect", "google-gmail", "--name", "gmail-personal", "--expect", "you@example.com", "--reason", "read and draft replies in your inbox", "--request-client", "--json"],
    ["connect", "github-oauth", "--name", "github-personal", "--scopes", "read:user,repo", "--reason", "open pull requests for you"],
  ],
  notes: ["With no OAuth client in the vault it exits 4 (client_missing) with the mehen request to run; --request-client asks for the client first, in one chain.", "--name naming an existing connection of the same provider reconnects it, pinned to the account it holds. A reconnect keeps the connection's scopes; --scopes adds to them, and never drops one.", "--home as for mehen request: private by default, project with --project or the checkout's mehen.toml, or workspace. A machine without private credentials (private: no in mehen status, scope.privateCredentials false in mehen status --json) needs --home project or --home workspace."],
  async run({ args, json, env }) {
    const name = args.string("name")
    const reason = args.string("reason")
    if (!name) throw usageError("Name the connection item to create with --name.", "mehen connect --help")
    if (!reason) throw usageError("Say why you need it with --reason; the human sees it.", "mehen connect --help")
    const wait = args.bool("wait")
    const noQr = args.bool("no-qr")
    const timeout = timeoutSeconds(args.string("timeout"), "mehen connect --help")
    const provider = knownOauthProvider(args.positionals[0] as string)
    const now = new Date()
    const { api, vaultUrl, configDir, ledger: scope, context, config } = await openSession(env)
    const home = resolveHome({ home: args.string("home"), project: args.string("project"), manifestProject: manifestWorkspace(process.cwd())?.project ?? null, help: "mehen connect --help" })
    const input: ConnectInput & { name: string } = {
      provider: provider.id,
      client: args.string("client"),
      name,
      home,
      scopes: splitList(args.list("scopes")),
      expect: args.string("expect"),
      reason,
      session: sessionLabel(env),
      requestClient: args.bool("request-client"),
      clientTags: splitList(args.list("client-tag")),
      fresh: args.bool("new"),
    }
    if (!input.client) {
      const choice = await chooseOauthClient(api, provider)
      if (choice) {
        input.client = choice.client
        input.requestClient = false
        if (!json) note(`mehen: using OAuth client ${choice.client}`)
      } else if (!input.requestClient) {
        const missing = missingClientError({ provider, name, expect: input.expect, reason, vaultUrl, home })
        if (json) throw missing
        reportError(missing, false, { env, noQr, vaultUrl })
        for (const line of missingClientLines(missing, input, styler(colourEnabled(process.stderr, env)))) note(line)
        return exitCodeFor(missing.code)
      }
    }
    const created = await withPrivateHomeExplained(api, home, () => privateHomeUnavailable("cli", connectCommandText({ ...input, home: { home: "project" as const, project: "<prj_id>" } }), args.string("home") === null), () => createConnect(api, input))
    const link = checkedLink(created.url, "connect", created.connect, scope)
    const ask = withContext(connectAskFor({ link, input, expiresAt: created.expiresAt, env, machineName: config.name ?? null }), context)
    const next = nextFor(ask, link, connectNext, now)
    const command = connectCommandText(input)
    const recorded = ask ? await recordAsk(configDir, scope, ask, name, command, now) : null
    const waitOptions = { json, events: false, noQr, timeoutSeconds: timeout, showAsk: false }
    const clientSlug = input.client ?? provider.clientTemplate

    // The chained case (V-4): the vault made a client intake first; the
    // connect link only starts once that intake has saved the client.
    if (created.intake) {
      const clientLink = checkedLink(created.intake.url, "intake", created.intake.intake, scope)
      const clientInput: IntakeInput = { kind: "oauth-client", name: clientSlug, provider: provider.clientTemplate, reason: clientRequestReason({ provider, expect: input.expect, reason }), tags: input.clientTags ?? [], hosts: [], paths: [], injection: null, session: input.session, home }
      const clientAsk = withContext(requestAsk({ link: clientLink, input: clientInput, expiresAt: created.intake.expiresAt, vaultUrl, env, machineName: config.name ?? null }), context)
      const clientNext = nextFor(clientAsk, clientLink, intakeNext, now)
      if (clientAsk) await recordAsk(configDir, scope, clientAsk, clientSlug, command, now)
      if (json) {
        printJson({ step: "client", ...created.intake, url: clientLink.url, ...(clientAsk ? { ask: clientAsk } : {}), next: clientNext, ...(clientLink.warning ? { warning: clientLink.warning } : {}) })
      } else {
        if (clientLink.warning) note(`mehen: warning: ${clientLink.warning}`)
        if (recorded) noteReissue(recorded, now)
        if (clientAsk) printAsk(clientAsk, { env, noQr, now, then: clientAsk.wait ? THEN_KEEPS_WAITING(clientAsk.wait) : null, expiresNote: "the connection link follows once the client is saved" })
      }
      if (!clientAsk) return EXIT.ok
      const first = await runWait(env, clientAsk.id, { ...waitOptions, step: "client" })
      if (first !== EXIT.ok) return first
    }

    const step = created.intake ? { step: "connect" } : {}
    if (json) {
      printJson({ ...step, connect: created.connect, url: link.url, expiresAt: created.expiresAt, provider: provider.id, client: clientSlug, name, ...(input.expect ? { account: input.expect } : {}), ...(ask ? { ask } : {}), next, ...(link.warning ? { warning: link.warning } : {}) })
    } else {
      if (link.warning) note(`mehen: warning: ${link.warning}`)
      if (recorded && !created.intake) noteReissue(recorded, now)
      if (ask) printAsk(ask, { env, noQr, now, then: ask.wait ? (wait ? THEN_KEEPS_WAITING(ask.wait) : THEN_OR_WAIT(ask.wait)) : null })
      else printLine(`The vault's connection id is not one mehen knows; run \`mehen pending\` to find it (expires ${created.expiresAt}).`)
    }
    if (!wait || !ask) return EXIT.ok
    return runWait(env, ask.id, { ...waitOptions, ...(created.intake ? { step: "connect" } : {}) })
  },
}

// ---------------------------------------------------------------- mehen wait

// The item an intake or connection produced passes through pickSummary,
// as `mehen ls` and `mehen show` do, so unknown fields never pass unreviewed.
export function waitOutput(id: string, result: WaitResult, vault: AskVault | null = null): Record<string, unknown> {
  if (result.kind === "approval") {
    const { rule: _rule, ruleProposal: _proposal, ...status } = result.status
    return { id, kind: result.kind, ...status, ...rememberedRule(result.status, vault) }
  }
  const item = result.kind === "intake" || result.kind === "connect" ? result.status.item : undefined
  return { id, kind: result.kind, ...result.status, ...(item ? { item: pickSummary(item) } : {}) }
}

function itemDisplay(item: ItemSummary): string {
  const template = item.provider ? getTemplate(item.provider) : null
  const display = template?.displayName ?? (item.provider ? `${item.kind}, ${item.provider}` : item.kind)
  if (isLeaseOnly(item)) return `${display}, ${noHostText(item)}`
  return item.hosts.length ? `${display}, goes to ${item.hosts.join(", ")}` : display
}

// The first OAuth provider a client template serves, for the "then:" after
// an oauth-client intake.
function providerForClient(clientTemplate: string | null): string | null {
  return Object.values(OAUTH_PROVIDERS).find((p) => p.clientTemplate === clientTemplate)?.id ?? null
}

function tryCommand(item: ItemSummary): string {
  if (isLeaseOnly(item)) return leaseOnlyDelivery(item.kind, item.ceiling) === "run" ? `mehen env set <NAME> --env <env> --item ${item.slug}, then mehen run -- <command>` : `mehen show ${item.slug}`
  if (item.kind === "oauth-client") {
    const provider = providerForClient(item.provider)
    return provider ? `mehen connect ${provider} --client ${item.slug} --name <slug> --reason "<why>"` : `mehen connect <provider> --client ${item.slug} --name <slug> --reason "<why>"`
  }
  const provider = item.kind === "oauth-connection" && item.provider ? getOAuthProvider(item.provider) : null
  const base = provider ? `${provider.upstream.baseUrl}${(provider.upstream.binding.paths?.[0] ?? "/").replace(/\*\*$/, "")}` : `https://${item.hosts[0] ?? "<host>"}/`
  return `mehen fetch ${item.slug} GET ${base}...`
}

const THEN = "  then:    "

// The outcome as a sentence, with the next action on the same block.
export function outcomeLines(result: WaitResult, s: Styler, options: { now?: Date; vault?: AskVault | null } = {}): Segment[][] {
  const then = (text: string) => segments(s.dim(THEN), text)
  if (result.kind === "intake") {
    const item = result.status.item
    if (!item) return [segments(s.ok("Completed"), `: intake ${result.status.intake} is done.`)]
    return [segments(s.ok("Added"), ` ${item.slug} (${itemDisplay(item)}).`), then(tryCommand(item))]
  }
  if (result.kind === "policy") {
    const rule = RuleRefSchema.safeParse((result.status as { rule?: unknown }).rule)
    if (rule.success) return [segments(s.ok("Approved"), `: ${ruleUntilText(rule.data, options)}.`), then(`mehen policy ls --item ${result.status.item}`)]
    const { item, proposal } = result.status
    const outcome = "outcome" in result.status ? result.status.outcome : null
    const state = outcome ? outcome.active ? ` is active until ${outcome.effectiveUntil}` : ` has ended${outcome.endedReason ? ` (${outcome.endedReason})` : ""}; it was granted until ${outcome.effectiveUntil}` : ""
    return [segments(s.ok("Approved"), `: policy proposal ${proposal}${state}.`), then(`mehen policy show ${item}`)]
  }
  if (result.kind === "approval" && result.status.push?.state === "done") {
    const { summary, push } = result.status
    return [segments(s.ok("Pushed"), `: ${summary}: ${push.outcome ?? "set"} (version ${push.version}).`)]
  }
  if (result.kind === "approval") {
    const { status, grant, summary, approval, item, push } = result.status
    const word = status === "used" ? "Approved and used" : "Approved"
    // A push that ended in a state this mehen does not know: the item's
    // pushes say how it went; repeating a fetch or run would not.
    if (push) return [segments(s.ok(word), `: ${summary}. The push to ${pushWords(push.destination)} is ${push.state}.`), then(`mehen show ${item ?? "<item>"}`)]
    const grantText = grant ? `  Grant ${grant.id}: ${grant.uses === null ? "unlimited uses" : `${grant.uses} use${grant.uses === 1 ? "" : "s"}`}, until ${clockText(grant.expiresAt, options) ?? grant.expiresAt}.` : ""
    const { rule, ruleProposal } = rememberedRule(result.status, options.vault)
    const remembered = rule
      ? [segments(`  Allowed from now on by rule ${rule.id} until ${clockText(rule.endsAt, options) ?? rule.endsAt}.`)]
      : ruleProposal ? [segments(`  A manager must co-sign the standing rule; open ${ruleProposal.url}, code ${ruleProposal.bindingCode}. Once co-signed, the rule appears in mehen policy ls${item ? ` --item ${item}` : ""} and in mehen wait ${approval}.`)] : []
    return [segments(s.ok(word), `: ${summary}.${grantText}`), ...remembered, then(`repeat the same mehen fetch or mehen run (you may add --approval ${approval})`)]
  }
  if (result.kind === "bundle") {
    const { bundle, approvals } = result.status
    return [segments(s.ok("Approved"), `: all ${approvals.length} request${approvals.length === 1 ? "" : "s"} in ${bundle}.`), then("repeat each request with its --approval, as mehen plan submit printed")]
  }
  if (result.kind === "adoption") {
    const { adoption, created, refused } = result.status
    const made = created?.length ?? 0
    const lines = [segments(s.ok("Approved"), `: adoption ${adoption} stored ${made} credential${made === 1 ? "" : "s"}${refused?.length ? `; ${refused.length} refused` : ""}.`)]
    return [...lines, then("mehen adopt apply, then mehen adopt verify")]
  }
  if (result.kind === "enrol") {
    const { tenant, device } = result.status
    const workspace = (result.status as { workspace?: { slug?: unknown; name?: unknown } }).workspace
    const where = typeof workspace?.slug === "string" && typeof workspace.name === "string" ? `${workspace.name} (${workspace.slug})` : `workspace ${tenant}`
    return [segments(s.ok("Enrolled"), ` as ${device} in ${where}.`), then("mehen status, then mehen guide")]
  }
  const { item, account, grantedScopes } = result.status
  const provider = item?.provider ? getOAuthProvider(item.provider) : null
  const scopes = grantedScopes?.length ? `; scopes ${grantedScopes.map((scope) => (provider?.auth.scopes.shortPrefix && scope.startsWith(provider.auth.scopes.shortPrefix) ? scope.slice(provider.auth.scopes.shortPrefix.length) : scope)).join(", ")}` : ""
  const name = item?.slug ?? result.status.connect
  const detail = provider || scopes ? ` (${provider?.displayName ?? item?.provider ?? "OAuth"}${scopes})` : ""
  return [segments(s.ok("Connected"), ` ${name}${account ? ` as ${account}` : ""}${detail}.`), ...(item ? [then(tryCommand(item))] : [])]
}

// What the countdown line says: the link's remaining life when known, else
// what is left of this wait. Numbers and fixed words only; the id was
// checked by waitTarget.
export function countdownLine(input: { kind: WaitKind; id: string; expiresAt: string | null; deadline: number; now: number }, s: Styler): Segment[] {
  const lead = input.kind === "enrol" ? "Waiting for the owner..." : "Waiting..."
  const at = input.expiresAt ? Date.parse(input.expiresAt) : Number.NaN
  if (Number.isFinite(at)) {
    const left = at - input.now
    if (left <= 0) return segments(lead, "  ", s.danger("the link has expired"), "  (waiting for the vault to say so)")
    return segments(lead, "  ", s.bold(clockDown(left)), " until the link expires  ", s.dim("(Ctrl-C stops waiting; the link stays valid)"))
  }
  return segments(lead, "  ", s.bold(clockDown(input.deadline - input.now)), " left of this wait  ", s.dim(`(Ctrl-C stops waiting; mehen wait ${input.id} resumes)`))
}

export type WaitEvent =
  | { event: "waiting"; id: string; kind: WaitKind; ask?: Ask; remainingSeconds: number | null }
  | ({ event: "settled"; id: string; kind: WaitKind } & Record<string, unknown>)
  | ({ event: "error" } & Record<string, unknown>)

const EVENT_MIN_SPACING_MS = 30_000

// One ticker for the time a wait spends on a human: on a TTY it redraws the
// countdown line on stderr once a second; with --events it writes a
// `waiting` line whenever the remaining time crosses a minute, at most one
// per 30 s. Off a TTY and without --events it writes nothing at all.
export class WaitMonitor {
  private timer: ReturnType<typeof setInterval> | null = null
  private drawn = false
  private lastEventAt = 0
  private lastMinute: number | null = null
  private askSent = false
  expiresAt: string | null
  ask: Ask | null

  constructor(
    private readonly target: { kind: WaitKind; id: string },
    private readonly options: { stderr: HumanWriter; env: Env; events: boolean; deadline: number; expiresAt: string | null; ask: Ask | null; emit: (event: WaitEvent) => void },
  ) {
    this.expiresAt = options.expiresAt
    this.ask = options.ask
  }

  private remainingMs(now: number): number | null {
    const at = this.expiresAt ? Date.parse(this.expiresAt) : Number.NaN
    return Number.isFinite(at) ? Math.max(0, at - now) : null
  }

  // Ctrl-C while the countdown is drawn: clear the line, then leave as the
  // shell expects (130); the link stays valid and mehen wait <id> resumes.
  private readonly onInterrupt = () => {
    this.stop()
    process.exit(130)
  }

  start(): void {
    const now = Date.now()
    if (this.options.events) this.waiting(now, true)
    if (!isTty(this.options.stderr)) return
    this.draw(now)
    this.timer = setInterval(() => this.tick(), 1000)
    process.once("SIGINT", this.onInterrupt)
  }

  // A pending status from the vault: a later expiry and an ask built from
  // it when the ledger had none. True when that ask is new.
  pending(expiresAt: string | null, ask: Ask | null): boolean {
    if (expiresAt) this.expiresAt = expiresAt
    const newAsk = ask !== null && this.ask === null
    if (newAsk) this.ask = ask
    const now = Date.now()
    if (this.options.events && !this.askSent && this.ask) this.waiting(now, true)
    else if (this.options.events) this.tick()
    return newAsk
  }

  private tick(): void {
    const now = Date.now()
    if (this.timer) this.draw(now)
    if (!this.options.events) return
    const remaining = this.remainingMs(now)
    const minute = remaining === null ? null : Math.floor(remaining / 60_000)
    if (minute !== this.lastMinute && now - this.lastEventAt >= EVENT_MIN_SPACING_MS) this.waiting(now, false)
  }

  private waiting(now: number, withAsk: boolean): void {
    const remaining = this.remainingMs(now)
    this.lastEventAt = now
    this.lastMinute = remaining === null ? null : Math.floor(remaining / 60_000)
    const ask = withAsk && this.ask && !this.askSent ? { ask: this.ask } : {}
    if ("ask" in ask) this.askSent = true
    this.options.emit({ event: "waiting", id: this.target.id, kind: this.target.kind, ...ask, remainingSeconds: remaining === null ? null : Math.ceil(remaining / 1000) })
  }

  private draw(now: number): void {
    const s = styler(colourEnabled(this.options.stderr, this.options.env))
    const line = countdownLine({ kind: this.target.kind, id: this.target.id, expiresAt: this.expiresAt, deadline: this.options.deadline, now }, s)
    this.options.stderr.write(`\r${terminalText(line)}\u001b[K`)
    this.drawn = true
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer)
    this.timer = null
    process.off("SIGINT", this.onInterrupt)
    if (this.drawn) this.options.stderr.write("\r\u001b[K")
    this.drawn = false
  }
}

export type RunWaitOptions = {
  json: boolean
  events: boolean
  noQr: boolean
  timeoutSeconds: number
  // Print the ask block (stderr, on a TTY) before waiting: mehen wait does;
  // --wait on request and connect has just printed it as the result.
  showAsk: boolean
  // --request-client: which step of the chain this wait is, for --json.
  step?: "client" | "connect"
}

// The error codes that mean the vault has closed the ask for good.
// provider_refused: a push approval whose push the provider refused.
export const SETTLED_CODES: ReadonlySet<CliError["code"]> = new Set<CliError["code"]>(["expired", "cancelled", "denied", "stale", "superseded", "rejected", "failed", "provider_refused"])

// The ask the vault's pending status describes, when the ledger had none:
// the link is built from the id on this vault; check and expiry are what
// the status says.
function askFromPending(kind: WaitKind, id: string, value: unknown, vaultUrl: AskVault, by: Ask["requestedBy"]): Ask | null {
  if (kind === "enrol") return null
  const v = value as { summary?: unknown; bindingCode?: unknown; account?: unknown; expiresAt?: unknown }
  const text = (field: unknown) => (typeof field === "string" ? field : null)
  if (kind === "policy") {
    const link = askUrlFor(vaultUrl, "policy", id)
    return link ? policyAsk({ id, url: link.url, summary: text(v.summary) ?? "Allow from now on", bindingCode: text(v.bindingCode), expiresAt: text(v.expiresAt), requestedBy: by }) : null
  }
  if (kind === "bundle") {
    const link = askUrlFor(vaultUrl, "bundle", id)
    const approvals = (value as { approvals?: unknown }).approvals
    return link ? bundleAsk({ id, url: link.url, codes: null, asks: Array.isArray(approvals) ? approvals.length : 0, reason: null, expiresAt: null, requestedBy: by }) : null
  }
  if (kind === "adoption") {
    const machines = (value as { machines?: unknown }).machines
    const items = Array.isArray(machines) ? machines.reduce((sum: number, m: { items?: unknown }) => sum + (typeof m?.items === "number" && Number.isInteger(m.items) && m.items >= 0 ? m.items : 0), 0) : 0
    return askFromServerEntry({ kind, id, expiresAt: text(v.expiresAt), items }, vaultUrl, by, null).ask
  }
  return askFromServerEntry({ kind, id, expiresAt: text(v.expiresAt), title: text(v.summary), bindingCode: text(v.bindingCode), account: text(v.account) }, vaultUrl, by, null).ask
}

// The wait itself, shared by mehen wait and --wait on request and connect:
// the ask (when this machine made it), the countdown or event stream, the
// outcome as a sentence or JSON, and the ledger entry dropped once settled.
export async function runWait(env: Env, id: string, options: RunWaitOptions): Promise<number> {
  const target = waitTarget(id)
  if (target.kind === "enrol") return runEnrolmentWait(env, id, options)
  const now = new Date()
  // Selection adds the unique-ledger-hit stage for this id (15.6 rule 4).
  const session = await openSession(env, { waitId: id })
  const { api, vaultUrl, configDir, ledger: scope } = session
  const ledger = await readLedger(configDir, scope, now)
  const entry = findLedgerEntry(ledger, id)
  const known = entry && entry.ask.id === id ? entry : null
  const stderr: HumanWriter = process.stderr
  const emit = (event: WaitEvent) => printJson(options.step ? { step: options.step, ...event } : event)
  // The newer ask for the same slug, when this machine has one (the vault
  // says `superseded` on the old one; the ledger knows what replaced it).
  const newer = known?.slug ? ledger.slice(ledger.indexOf(known) + 1).filter((e) => e.slug === known.slug && e.ask.kind === known.ask.kind).at(-1) : undefined
  const waitLedger: WaitLedger = { reissueCommand: known?.command ?? null, replacedBy: newer?.ask.id ?? null }
  const monitor = new WaitMonitor(
    { kind: target.kind, id },
    { stderr, env, events: options.events, deadline: now.getTime() + options.timeoutSeconds * 1000, expiresAt: known?.ask.expiresAt ?? null, ask: known?.ask ?? null, emit },
  )
  const showBlock = options.showAsk && !options.json && isTty(stderr)
  if (showBlock && known) printAsk(known.ask, { stream: "stderr", env, noQr: options.noQr, now, then: null })
  let settledId: string | null = null
  let sendingShown = false
  try {
    monitor.start()
    const result = await waitFor(api, id, {
      timeoutMs: options.timeoutSeconds * 1000,
      intervalMs: pollIntervalMs(env),
      ledger: waitLedger,
      expiresAt: known?.ask.expiresAt ?? null,
      onPending: (pending) => {
        // Approved, and the push is being sent: one line instead of the
        // countdown, and no ask, since no human has anything left to do.
        const sending = pushBeingSent(target.kind, pending.value)
        if (sending !== null) {
          if (!sendingShown && isTty(stderr)) {
            monitor.stop()
            stderr.write(`Approved; the push to ${sending} is being sent.\n`)
          }
          sendingShown = true
          monitor.pending(pending.expiresAt, null)
          return
        }
        const newAsk = monitor.pending(pending.expiresAt, known ? null : withContext(askFromPending(target.kind, id, pending.value, scope, requestedBy(env, session.config.name ?? null)), session.context))
        if (newAsk && monitor.ask && showBlock) {
          monitor.stop()
          printAsk(monitor.ask, { stream: "stderr", env, noQr: options.noQr, then: null })
          monitor.start()
        }
      },
    })
    monitor.stop()
    settledId = id
    const output = waitOutput(id, result, scope)
    if (options.events) emit({ event: "settled", ...output } as WaitEvent)
    else if (options.json) printJson(options.step ? { step: options.step, ...output } : output)
    else for (const line of outcomeLines(result, styler(colourEnabled(process.stdout, env)), { now: new Date(), vault: scope })) printLine(line)
    return EXIT.ok
  } catch (error) {
    monitor.stop()
    const thrown = toCliError(error)
    // A link that is still live goes out again with the error, so the agent
    // can re-hand it; one the vault has settled is dropped from the ledger.
    const live = thrown.code === "timeout" || thrown.code === "mismatch"
    const failure = live && known && !thrown.extras.ask ? new CliError(thrown.code, thrown.message, thrown.next, { ...thrown.extras, ask: known.ask }) : thrown
    if (SETTLED_CODES.has(failure.code)) settledId = id
    if (!options.events) throw failure
    emit({ event: "error", id, kind: target.kind, ...(options.step ? { step: options.step } : {}), ...errorJson(failure, { env, noQr: options.noQr, vaultUrl }) })
    return exitCodeFor(failure.code)
  } finally {
    if (settledId) await removeLedgerEntry(configDir, scope, settledId).catch(() => undefined)
  }
}

// The enrolment result as a wait reports it: the vault's verified active
// answer, the same shape for mehen wait and vault_wait.
export function enrolmentResult(finished: Finished): WaitResult {
  return { kind: "enrol", status: finished.verified as Extract<WaitResult, { kind: "enrol" }>["status"] }
}

function printEnrolmentResult(env: Env, id: string, result: WaitResult, options: RunWaitOptions): number {
  const output = waitOutput(id, result)
  if (options.events) printJson(options.step ? { step: options.step, event: "settled", ...output } : { event: "settled", ...output })
  else if (options.json) printJson(options.step ? { step: options.step, ...output } : output)
  else for (const line of outcomeLines(result, styler(colourEnabled(process.stdout, env)), { now: new Date() })) printLine(line)
  return EXIT.ok
}

// mehen wait enr_...: the one slot in the allowed set whose record
// holds the id, followed with its own key from this process: renewed in
// place while it waits, finished on active (any process may finish it), the
// record removed only on a terminal answer. A timeout is exit 4 with the
// live ask; --events adds `renewed`.
async function runEnrolmentWait(env: Env, id: string, options: RunWaitOptions): Promise<number> {
  // Selection, then the attempt. A wait that starts after another observer
  // committed the attempt (or loses that race) finds the committed slot and
  // reports its success, never an error.
  let opened: Awaited<ReturnType<typeof openEnrolmentSession>> | null = null
  for (let look = 0; opened === null; look++) {
    const selected = await selectSlot(env, { waitId: id })
    if (selected.config) {
      const done = await committedEnrolment(env, id, selected)
      if (!done) throw new CliError("not_found", `No open enrolment ${id} is recorded on this machine for ${selected.config.vault}.`, { command: "mehen enrol --workspace <slug>", say: "Only the machine that started an enrolment can wait on it; run `mehen enrol --workspace <slug>` to start again." })
      return printEnrolmentResult(env, id, enrolmentResult(done), options)
    }
    try {
      opened = await openEnrolmentSession(env, id, { bound: { dir: selected.dir, config: null } })
    } catch (error) {
      if (look > 0 || !(error instanceof CliError && error.code === "not_found")) throw error
    }
  }
  const { attempt } = opened
  const stderr: HumanWriter = process.stderr
  const emit = (event: WaitEvent | { event: "renewed"; id: string; expiresAt: string; hardExpiresAt: string | null }) => printJson(options.step ? { step: options.step, ...event } : event)
  const now = Date.now()
  const deadline = now + options.timeoutSeconds * 1000
  const monitor = new WaitMonitor({ kind: "enrol", id }, { stderr, env, events: options.events, deadline, expiresAt: attempt.record.expiresAt, ask: opened.ask, emit })
  const showBlock = options.showAsk && !options.json && isTty(stderr)
  if (showBlock) printAsk(opened.ask, { stream: "stderr", env, noQr: options.noQr, then: null })
  const liveAsk = (a: Attempt): Ask => ({ ...opened.ask, expiresAt: a.record.expiresAt })
  try {
    monitor.start()
    const followed = await followAttempt(attempt, {
      deadline,
      intervalMs: pollIntervalMs(env),
      renew: true,
      onPending: (a) => monitor.pending(a.record.expiresAt, null),
      onRenewed: (a) => {
        if (options.events) emit({ event: "renewed", id, expiresAt: a.record.expiresAt, hardExpiresAt: a.record.hardExpiresAt })
      },
    })
    monitor.stop()
    if (followed.kind === "waiting") {
      throw new CliError("timeout", `Enrolment ${id} is still waiting for a human${options.timeoutSeconds > 0 ? ` after ${durationText(options.timeoutSeconds)}` : ""}; mehen keeps the link alive while it waits.`, {
        command: `mehen wait ${id}`,
        say: "A human has not accepted it yet; relay the link again and wait again.",
      }, { ask: liveAsk(attempt) })
    }
    return printEnrolmentResult(env, id, enrolmentResult(followed.finished), options)
  } catch (error) {
    monitor.stop()
    const failure = toCliError(error)
    if (!options.events) throw failure
    emit({ event: "error", id, kind: "enrol", ...(options.step ? { step: options.step } : {}), ...errorJson(failure, { env, noQr: options.noQr, vaultUrl: { vaultUrl: opened.vaultUrl, workspaceSlug: attempt.record.intent.workspace } }) })
    return exitCodeFor(failure.code)
  }
}

export const waitCommand: Command = {
  summary: "wait for an intake (int_), approval (apr_), connection (con_), enrolment (enr_), policy proposal (pol_) or bundle (bnd_)",
  spec: {
    usage: "mehen wait <id> [--timeout <duration>] [--json [--events]]",
    flags: { timeout: { type: "string" }, events: { type: "boolean" } },
    positionals: { min: 1, max: 1 },
  },
  examples: [["wait", "int_3kQ9vXyZ7", "--timeout", "10m"], ["wait", "apr_7Hq2", "--json", "--events"]],
  notes: [
    "A human who has not acted by the timeout is exit 4 (timeout) with the ask handed back: relay it again and wait again. Ctrl-C leaves the link valid.",
    "A bundle (bnd_, from mehen plan submit) ends once none of its requests waits: exit 0 when all were approved, 5 when any was denied, stopped or replaced (the approved ones stay usable, and next.say names them), 4 on timeout.",
  ],
  async run({ args, json, env }) {
    const id = args.positionals[0] as string
    const timeout = timeoutSeconds(args.string("timeout"), "mehen wait --help")
    const events = args.bool("events")
    if (events && !json) throw usageError("--events prints one JSON object per line, so it needs --json.", "mehen wait --help")
    return runWait(env, id, { json, events, noQr: args.bool("no-qr"), timeoutSeconds: timeout, showAsk: true })
  },
}

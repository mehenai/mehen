// mehen fill and vault_fill: one field of a credential typed into one field
// of the page the agent's browser shows (design 3, "Fill"). Every check of
// the browser, the page and the field runs before the vault is asked; the
// value comes back sealed to a key made for this fill alone, is opened in
// memory and goes only into the field, never into output, logs or errors.

import { FillRequestSchema, type FillResponse, FillResponseSchema, fillOrigin, fillSealContext } from "@mehen/protocol/fill"
import { type FillInput, KINDS, isSlug } from "@mehen/protocol/kinds"
import { generateSealKeyPair, openText } from "@mehen/protocol/seal"
import type { ItemUseContext } from "@mehen/protocol/workspace"
import { CliError, usageError } from "../errors.ts"
import type { VaultApi } from "../vault-api.ts"
import { CdpCallError, CdpConnection, type CdpEvent, type CdpSource, attachPage, cdpEndpoint, choosePage, pageUrl } from "./cdp.ts"
import { BEFORE_ENTER, CLEAR_FIELD, FIELD_PRESENT, type FieldCheck, type FrameInfo, type LocatedField, type PageVerdict, checkField, frameAncestors, locateField, onField, pageFrames } from "./page-check.ts"

// Every field fill may type, by name, with the kind of field it goes into.
// Names are unique across kinds, so the name alone says what to check for.
export const FILL_FIELDS: ReadonlyMap<string, FillInput> = new Map(Object.values(KINDS).flatMap((spec) => spec.fill.map((field) => [field.name, field.input] as const)))

export const SUBMIT_WAIT_MS = 10_000
// A one-time code with less than this left is fetched again, for the next step.
export const CODE_MARGIN_MS = 2_000

export type FillOptions = {
  item: string
  field: string
  selector: string
  submit: boolean
  source: CdpSource
  target: string | null
  context: ItemUseContext | null
  approval: string | null
  // Where a usage error points: `mehen fill --help` or the MCP tool.
  help: string
}

export type FillVault = { api: VaultApi; workspace: string }

export type FillDeps = {
  // Opened only once every local check has passed.
  vault(): Promise<FillVault>
  signal?: AbortSignal
  submitWaitMs?: number
  now?: () => number
  sleep?: (ms: number) => Promise<void>
}

export type FillResult = { typed: true; label: string; origin: string; page: string; submitted: boolean; navigatedTo: string | null; cleared: boolean }

const INPUT_WORDS: Record<FillInput, string> = { username: "username", password: "password", "one-time-code": "one-time code", secret: "secret" }
const MAX_SELECTOR = 2048

function checkArguments(options: FillOptions): FillInput {
  if (!isSlug(options.item)) throw usageError(`${JSON.stringify(options.item)} is not an item name.`, options.help)
  const input = FILL_FIELDS.get(options.field)
  if (!input) throw usageError(`No credential has a field ${JSON.stringify(options.field)} that can be typed into a web page. The fields are ${[...FILL_FIELDS.keys()].join(", ")}.`, options.help)
  if (options.selector.trim() === "" || options.selector.length > MAX_SELECTOR || options.selector.split(" >>> ").some((hop) => hop.trim() === "")) {
    throw usageError(`The selector must be a CSS selector of at most ${MAX_SELECTOR} characters; " >>> " steps into an open shadow root and needs a selector on each side.`, options.help)
  }
  if (options.approval !== null && !FillRequestSchema.shape.approval.safeParse(options.approval).success) throw usageError(`${JSON.stringify(options.approval)} is not an approval id (apr_...).`, options.help)
  return input
}

// The page's path for the request: no query, RFC 3986 path characters
// only, one leading slash and at most 512 characters.
export function pagePath(url: string): string {
  let path = "/"
  try {
    path = new URL(url).pathname || "/"
  } catch {
    path = "/"
  }
  path = `/${path.replace(/[^A-Za-z0-9\-._~!$&'()*+,;=:@%/]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0")}`).replace(/^\/+/, "")}`
  return path.length > 512 ? path.slice(0, 512).replace(/%[0-9A-Fa-f]?$/, "") : path
}

// Where a page went, without its query or fragment.
function placeOf(url: string): string {
  try {
    const parsed = new URL(url)
    return parsed.origin === "null" ? parsed.protocol : `${parsed.origin}${parsed.pathname}`
  } catch {
    return "an address mehen could not read"
  }
}

function pageRefusal(verdict: PageVerdict, options: FillOptions, input: FillInput, extras: { cleared?: boolean } = {}): CliError {
  const reason = verdict.reason ? `: ${verdict.reason}` : ""
  switch (verdict.code) {
    case "field_kind_mismatch":
      return new CliError("field_kind_mismatch", `${options.selector} is not a ${INPUT_WORDS[input]} field${reason}. Nothing was typed.`, { say: `Point the selector at the page's ${INPUT_WORDS[input]} field. Do not look for another way to type the value.` }, extras)
    case "field_hidden":
      return new CliError("field_hidden", `mehen will not type into ${options.selector}${reason}. Nothing was typed.`, { say: "Bring the field into view (close what covers it, open the step of the form it is on), then fill again." }, extras)
    case "frame_origin_mismatch":
      return new CliError("frame_origin_mismatch", `The field's frame is not on a page of its own origin alone${reason}. Nothing was typed.`, { say: "Open the sign-in page itself, not a page that embeds it, and fill there." }, extras)
    case "page_changed":
      return new CliError("page_changed", `The page changed under mehen${reason}.${extras.cleared === undefined ? " Nothing was typed." : ""}`, { say: "Look at the page as it is now, then run the fill again." }, extras)
    default:
      return new CliError("internal", "The check inside the page failed, so mehen typed nothing.", { command: "mehen doctor", say: "Retry once; if it fails again, tell the human which page it was." }, extras)
  }
}

function fieldRefusal(located: Awaited<ReturnType<typeof locateField>>, options: FillOptions): CliError | null {
  if ("invalid" in located) return usageError(`${options.selector} is not a valid CSS selector.`, options.help)
  if ("many" in located) return new CliError("field_ambiguous", `${options.selector} matches more than one element in the page's frames, so mehen will not guess which to type into.`, { say: "Make the selector match exactly one field." })
  if ("none" in located) {
    const closed = located.none.closed ? " A shadow hop reached an element with no open shadow root; a field in a closed shadow root cannot be filled." : ""
    return new CliError("field_not_found", `${options.selector} matches no element in any frame of the page.${closed}`, { say: "Check the selector against the page as it is now." })
  }
  return null
}

function originRefusal(code: "origin_mismatch" | "frame_origin_mismatch", message: string): CliError {
  return code === "origin_mismatch"
    ? new CliError("origin_mismatch", message, { say: "mehen types only into https pages with a host name. Do not retry on another page." })
    : new CliError("frame_origin_mismatch", message, { say: "Open the sign-in page itself, not a page that embeds it, and fill there." })
}

// The field's origin, held to the ruling for 0.3.18: the field's own frame
// is an https origin with a host name, and every ancestor and the page's
// top-level address have that same origin, as the browser reports them.
async function fieldOrigin(connection: CdpConnection, targetId: string, frames: Map<string, FrameInfo>, frame: FrameInfo): Promise<{ origin: string; ancestors: string[] }> {
  const origin = fillOrigin(frame.securityOrigin)
  if (origin === null || origin !== frame.securityOrigin) throw originRefusal("origin_mismatch", "The field's page is not an https page with a host name, so mehen will not type into it. Nothing was typed.")
  const ancestors = frameAncestors(frames, frame.id)
  if (ancestors === null) throw originRefusal("frame_origin_mismatch", "The browser did not report every ancestor of the field's frame. Nothing was typed.")
  if (ancestors.some((ancestor) => ancestor !== origin)) throw originRefusal("frame_origin_mismatch", `The field's frame (${origin}) is inside a page of another origin. mehen types only into a frame whose every ancestor has its own origin. Nothing was typed.`)
  if (fillOrigin(await pageUrl(connection, targetId)) !== origin) throw originRefusal("frame_origin_mismatch", `The page's address is not on ${origin}, the field's origin. Nothing was typed.`)
  return { origin, ancestors }
}

async function recipientOf(publicKey: CryptoKey): Promise<{ kty: "EC"; crv: "P-256"; x: string; y: string }> {
  const jwk = (await crypto.subtle.exportKey("jwk", publicKey)) as JsonWebKey
  return { kty: "EC", crv: "P-256", x: String(jwk.x), y: String(jwk.y) }
}

function answerRefused(what: string): CliError {
  return new CliError("internal", `The vault's answer to the fill ${what}, so mehen dropped it and typed nothing.`, { say: "Retry once; if it happens again, tell the human the time it happened." })
}

type Delivered = { answer: FillResponse; jti: string }

async function askVault(vault: FillVault, body: unknown, expect: { field: string; origin: string; input: FillInput }, signal: AbortSignal | undefined): Promise<Delivered> {
  let jti: string | null = null
  const raw = await vault.api.request<unknown>("POST", "/v1/fill", body, { onProof: (id) => (jti = id), ...(signal ? { signal } : {}) })
  const parsed = FillResponseSchema.safeParse(raw)
  if (!parsed.success) throw answerRefused("did not have the shape mehen expects")
  const answer = parsed.data
  if (answer.field !== expect.field || answer.origin !== expect.origin || answer.input !== expect.input) throw answerRefused("was for another field, page or kind of field than mehen asked for")
  if (jti === null) throw answerRefused("came back to no proof mehen signed")
  return { answer, jti }
}

export async function fill(options: FillOptions, deps: FillDeps): Promise<FillResult> {
  const input = checkArguments(options)
  const now = deps.now ?? Date.now
  const sleep = deps.sleep ?? Bun.sleep
  const connection = await CdpConnection.open(await cdpEndpoint(options.source))
  try {
    const page = await choosePage(connection, options.target)
    const pageSession = await attachPage(connection, page.targetId)
    const frames = await pageFrames(connection, pageSession)
    const located = await locateField(connection, frames, options.selector)
    const refused = fieldRefusal(located, options)
    if (refused || !("field" in located)) throw refused ?? answerRefused("found no field")
    const field = located.field
    const { origin, ancestors } = await fieldOrigin(connection, page.targetId, frames, field.frame)
    const path = pagePath(field.frame.url)
    const check: FieldCheck = { selector: options.selector, origin, ancestors, input }
    const pre = await checkField(connection, field, check, null)
    if (pre.code !== "ok") throw pageRefusal(pre, options, input)

    const vault = await deps.vault()
    const keys = await generateSealKeyPair()
    const body = FillRequestSchema.parse({ item: options.item, field: options.field, origin, page: path, ...(options.context ? { context: options.context } : {}), ...(options.approval ? { approval: options.approval } : {}), recipient: await recipientOf(keys.publicKey) })
    const expect = { field: options.field, origin, input }
    let delivered = await askVault(vault, body, expect, deps.signal)
    const until = delivered.answer.validUntil === undefined ? null : Date.parse(delivered.answer.validUntil)
    if (input === "one-time-code" && until !== null && until - now() < CODE_MARGIN_MS) {
      await sleep(Math.max(0, until - now()) + 250)
      delivered = await askVault(vault, body, expect, deps.signal)
    }
    const { answer, jti } = delivered
    let value: string | null
    try {
      value = await openText(keys.privateKey, answer.box, fillSealContext({ workspace: vault.workspace, item: answer.item, field: options.field, origin, jti }))
    } catch {
      throw answerRefused("did not open with the key and context mehen made for it")
    }
    let typed: PageVerdict
    try {
      typed = await checkField(connection, field, check, value)
    } finally {
      value = null
    }
    if (typed.code !== "typed") throw pageRefusal(typed, options, input)
    const result: FillResult = { typed: true, label: answer.label, origin, page: path, submitted: false, navigatedTo: null, cleared: false }
    if (!options.submit) return result
    return { ...result, ...(await submit(connection, { targetId: page.targetId, sessionId: pageSession }, frames, field, check, options, deps.submitWaitMs ?? SUBMIT_WAIT_MS)) }
  } finally {
    connection.close()
  }
}

// The browser refused a call (CdpCallError) or stopped answering.
function browserLost(error: unknown): boolean {
  return error instanceof CdpCallError || (error instanceof CliError && error.code === "cdp_unreachable")
}

// Why the Enter must not be pressed, or null: the browser's frame tree and
// the page's address are read again and held to fieldOrigin's rules, then
// BEFORE_ENTER checks the page's side against that fresh list of ancestors.
async function changedBeforeEnter(connection: CdpConnection, page: { targetId: string; sessionId: string }, field: LocatedField, check: FieldCheck): Promise<string | null> {
  const frames = await pageFrames(connection, page.sessionId)
  const frame = frames.get(field.frame.id)
  if (!frame) return "the field's frame went away"
  if (frame.securityOrigin !== check.origin) return "the browser now reports the field's frame on another origin"
  let ancestors: string[]
  try {
    ancestors = (await fieldOrigin(connection, page.targetId, frames, frame)).ancestors
  } catch (error) {
    if (error instanceof CliError && (error.code === "origin_mismatch" || error.code === "frame_origin_mismatch")) return "the browser now reports an ancestor of the field's frame, or the page's address, on another origin"
    throw error
  }
  const ready = await onField(connection, field, BEFORE_ENTER, [check.selector, check.origin, ancestors])
  return ready.code === "ok" ? null : (ready.reason ?? "the field's page changed")
}

// --submit: a trusted Enter in the field, then up to `waitMs` for a sign
// that the form went: a navigation of the page or the field's frame, a
// change of address within the document, or the field or its frame going
// away. Only signs that arrive after the Enter is sent count, and a
// navigation only requested is not one: it may still be cancelled (a 204, a
// download, a failed request). With none, the field is emptied and the fill
// is not_submitted. A browser that refuses a call or stops answering once
// the value is typed is page_changed before the Enter and not_submitted
// after it, with the field emptied where the browser still lets mehen.
async function submit(connection: CdpConnection, page: { targetId: string; sessionId: string }, frames: Map<string, FrameInfo>, field: LocatedField, check: FieldCheck, options: FillOptions, waitMs: number): Promise<{ submitted: true; navigatedTo: string | null }> {
  const pageSession = page.sessionId
  const main = [...frames.values()].find((frame) => frame.sessionId === pageSession && frame.parentId === null)?.id ?? null
  const watched = new Set([main, field.frame.id].filter((id): id is string => id !== null))
  let went: { navigatedTo: string | null } | null = null
  let entered = false
  let wake: (() => void) | null = null
  const stop = connection.onEvent((event: CdpEvent) => {
    if (!entered) return
    const params = event.params
    const frame = params.frame as { id?: unknown; url?: unknown } | undefined
    const frameId = typeof params.frameId === "string" ? params.frameId : typeof frame?.id === "string" ? frame.id : null
    const url = typeof params.url === "string" ? params.url : typeof frame?.url === "string" ? frame.url : null
    if ((event.method === "Page.frameNavigated" || event.method === "Page.navigatedWithinDocument") && frameId !== null && watched.has(frameId)) went ??= { navigatedTo: url === null ? null : placeOf(url) }
    else if (event.method === "Target.detachedFromTarget" && params.sessionId === field.sessionId) went ??= { navigatedTo: null }
    else return
    wake?.()
  })
  const clear = async (): Promise<boolean> => {
    try {
      return (await onField(connection, field, CLEAR_FIELD, [])).code === "ok"
    } catch (error) {
      if (browserLost(error)) return false
      throw error
    }
  }
  const notSubmitted = (what: string, cleared: boolean) =>
    new CliError("not_submitted", `mehen pressed Enter in ${options.selector}, but ${what}, so ${cleared ? "it emptied the field again" : "it tried to empty the field and could not"}.`, {
      say: "Submit the form the way the page expects, for example with its button, then check the result.",
    }, { cleared })
  try {
    let changed: string | null
    try {
      for (const sessionId of new Set([pageSession, field.sessionId])) await connection.send("Page.enable", {}, { sessionId })
      changed = await changedBeforeEnter(connection, page, field, check)
    } catch (error) {
      if (!browserLost(error)) throw error
      changed = "the browser refused a call or stopped answering"
    }
    if (changed !== null) {
      const cleared = await clear()
      throw pageRefusal({ code: "page_changed", reason: `${changed}, so mehen did not press Enter${cleared ? " and emptied the field" : " and could not empty the field"}` }, options, check.input, { cleared })
    }
    const enter = { key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13 }
    entered = true
    try {
      await connection.send("Input.dispatchKeyEvent", { type: "keyDown", ...enter, text: "\r", unmodifiedText: "\r" }, { sessionId: pageSession })
      await connection.send("Input.dispatchKeyEvent", { type: "keyUp", ...enter }, { sessionId: pageSession })
      const deadline = Date.now() + waitMs
      while (went === null && Date.now() < deadline) {
        await new Promise<void>((resolve) => {
          wake = resolve
          setTimeout(resolve, Math.min(250, Math.max(0, deadline - Date.now())))
        })
        wake = null
        if (went !== null) break
        const present = await onField(connection, field, FIELD_PRESENT, [])
        if (present.code !== "ok") went = { navigatedTo: null }
      }
    } catch (error) {
      if (!browserLost(error)) throw error
      if (went === null) throw notSubmitted("then the browser refused a call or stopped answering, so mehen cannot tell whether the form went", await clear())
    }
    if (went !== null) return { submitted: true, navigatedTo: (went as { navigatedTo: string | null }).navigatedTo }
    throw notSubmitted(`within ${Math.round(waitMs / 1000)} s the page did not navigate or remove the field`, await clear())
  } finally {
    stop()
  }
}

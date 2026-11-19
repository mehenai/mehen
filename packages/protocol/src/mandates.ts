// What a held request is to a mandate, and whether a mandate's terms cover
// it. The shapes are in mandate-terms.ts. Everything
// here is pure: which credentials, machines and signers a mandate reaches,
// its caps and its rate are the vault's.

import { evaluatePolicy, hostMatches, type Binding } from "./binding.ts"
import { graphqlMutationRootFields } from "./body-match.ts"
import { sha256B64 } from "./bytes.ts"
import { canonicalJson } from "./canonical-json.ts"
import { MANDATE_CLASSES, type MandateCandidateNever, type MandateClass, type MandateSchedule, type MandateState, type MandateTerms } from "./mandate-terms.ts"
import { catalogueFloorReason } from "./policy-catalogue.ts"
import { POLICY_RULE_MAX_NESTED_FIELDS, type PolicyRuleRefusal } from "./policy-mode.ts"
import { coveredBody, fieldFloorRefusals, holdsLiveKey, isJsonType, POLICY_DESTRUCTIVE_WORDS, queryNamesOf, ruleOnlyRefusals, type PolicyRuleAnchor } from "./policy-rules.ts"
import { classifyPolicyRequest, evaluatePolicyFloor, POLICY_FLOOR, policyCatalogueVerdict, policyPathFloorReasons } from "./policy-safety.ts"

// Facts that make a request never covered, whatever a mandate ticks.
export const MANDATE_NEVER_FACTS = ["method", "destination", "deny", "credential", "persistence", "sharing", "money", "generic", "unreadable", "live-key"] as const
export type MandateFact = (typeof MANDATE_NEVER_FACTS)[number] | "send" | "destructive" | "item-rule" | "act"

const WRITE_METHODS = ["POST", "PUT", "PATCH"]
const READ_METHODS = ["GET", "HEAD"]
const CLASS_METHODS = [...READ_METHODS, ...WRITE_METHODS, "DELETE"]
const DESTINATION_SAFETY = new Set(["safety.destination", "safety.encoding", "safety.destination-shape", "safety.method-override"])

// Each non-empty segment of a path, percent escapes decoded.
function pathSegments(path: string): string[] {
  let decoded = path
  try { decoded = decodeURIComponent(path) } catch { /* read as written */ }
  return decoded.split("/").map((segment) => segment.normalize("NFKC")).filter((segment) => segment !== "")
}
// The query parameters that name an RPC method, as Flickr's
// ?method=flickr.photos.delete does on a GET, by name in lower case.
const MANDATE_QUERY_METHOD_NAMES = new Set(["method", "action", "op", "cmd", "do", "operation"])
// Each value of such a parameter, decoded and split into parts at
// everything but a letter or a digit. Read only to find the class: never
// kept, audited or shown.
function queryMethodParts(search: string): string[][] {
  if (!search.startsWith("?")) return []
  const decoded = (text: string): string => { try { return decodeURIComponent(text.replace(/\+/g, " ")) } catch { return text } }
  return search.slice(1).split(/[&;]/).flatMap((part) => {
    const at = part.indexOf("=")
    if (at < 0 || !MANDATE_QUERY_METHOD_NAMES.has(decoded(part.slice(0, at)).toLowerCase())) return []
    return [decoded(part.slice(at + 1)).split(/[^A-Za-z0-9]+/).filter((p) => p !== "")]
  })
}
const segmentLetters = (segment: string): string => segment.toLowerCase().replace(/[^a-z]/g, "")
const holdsDigit = (segment: string): boolean => /[0-9]/.test(segment)
// A run of letters' camelCase words as sent, lowercased: "deleteMessage"
// holds "delete", "DELETEmessage" only "delet" and "emessage".
function camelTokens(run: string): string[] {
  return run.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2").split(" ").map((t) => t.toLowerCase())
}
// What may follow a word in a case-folded method name and still leave a
// collection or a state ("settings", "stopped", "editions"), not an act.
const MANDATE_PATH_INFLECTIONS = new Set(["s", "es", "d", "ed", "er", "ers", "ing", "ings", "ion", "ions", "ment", "ments", "al", "or", "ors", "ure"])
const MANDATE_PATH_PREFIX_STOPLIST = new Set(["address", "addresses", "addon", "addons", "addition", "additions", "settlement", "settlements", "copyright", "postcode", "postgres", "pinecone", "setups", "additional", "stopwords", "scheduledmessages"])
// Whether a lowercased token is a word and an inflection of it, a doubled
// last letter allowed: "posts", "settings", "stopped".
function inflectsWord(token: string, word: string): boolean {
  if (!token.startsWith(word)) return false
  const rest = token.slice(word.length)
  return MANDATE_PATH_INFLECTIONS.has(rest) || (rest[0] === word.at(-1) && MANDATE_PATH_INFLECTIONS.has(rest.slice(1)))
}
// Whether a lowercased run of letters, a case-folded method name such as
// Telegram's "deletemessage", starts with a word and goes on to more than an
// inflection of it.
function runStartsWithWord(run: string, word: string): boolean {
  if (!run.startsWith(word) || MANDATE_PATH_PREFIX_STOPLIST.has(run)) return false
  const rest = run.slice(word.length)
  return rest.length >= 3 && !inflectsWord(run, word)
}
// What may follow a word and an inflection of it and still leave a
// collection: "postslist", "settingspage". Only as all of the rest, so
// "for" never covers "forum".
const MANDATE_PATH_SPARED_TAILS = new Set(["by", "for", "page", "list", "count", "feed", "summary", "info"])
// Whether what follows a word at the start of a lowercased run leaves a
// collection: an inflection alone, or a non-empty one and then one listed
// tail. Decided on the lowercased run only, as the sender picks the case.
function sparedRest(word: string, rest: string): boolean {
  const inflection = (text: string): boolean => MANDATE_PATH_INFLECTIONS.has(text) || (text[0] === word.at(-1) && MANDATE_PATH_INFLECTIONS.has(text.slice(1)))
  if (inflection(rest)) return true
  for (let at = 1; at < rest.length; at++) if (inflection(rest.slice(0, at)) && MANDATE_PATH_SPARED_TAILS.has(rest.slice(at))) return true
  return false
}
// What a path may name that deletes beside the floor's own words:
// Discord's POST /guilds/{id}/prune, Mastodon's .../notifications/clear.
const MANDATE_PATH_DELETE_WORDS = [...POLICY_DESTRUCTIVE_WORDS, "prune", "clear"] as const
// Runs that hold a delete word inside another word and name no delete.
const MANDATE_PATH_DELETE_STOPLIST = new Set(["preset", "presets", "enforce", "enforcement", "salesforce", "workforce", "swipe", "swipes", "enforcements", "enforced", "workforces", "nuclear", "unclear", "clearance", "clearances", "cleared"])
// Whether a run of letters names a delete word, whatever letter case the
// sender chose: anywhere in the lowercased run ("bulkdelete",
// "postsdeleteall"), unless at its start with a spared rest ("archived") or
// the run is on the stoplist; or as one of its camelCase words as sent.
function runNamesDelete(run: string, word: string): boolean {
  if (camelTokens(run).includes(word)) return true
  const folded = run.toLowerCase()
  if (MANDATE_PATH_DELETE_STOPLIST.has(folded)) return false
  for (let at = folded.indexOf(word); at >= 0; at = folded.indexOf(word, at + 1)) {
    if (at > 0 || !sparedRest(word, folded.slice(word.length))) return true
  }
  return false
}
// What may come before an act word in one run of letters and leave it that
// act: "bulkupdate", "unpin", "bulkupdatemessages".
const MANDATE_PATH_ACT_PREFIXES = ["bulk", "batch", "mass", "multi", "un"] as const
// Whether a lowercased run starts with an act word and its rest is not
// spared: "editmessagetext", not "settingspage".
const startsWithAct = (folded: string, word: string): boolean => (folded === word || runStartsWithWord(folded, word)) && !sparedRest(word, folded.slice(word.length))
// Lowercased runs that read though a camelCase word in them is an act word:
// Telegram's getStickerSet. Only as the whole run, in any letter case.
const MANDATE_PATH_READ_RUNS = new Set(["getstickerset"])
// Whether a run of letters names an act word, whatever letter case the
// sender chose: never when the lowercased run is on the read list; else it
// starts with the word, or is a listed prefix and then the word and perhaps
// an inflection, or the word and more; or the word is one of its camelCase
// words as sent.
function runNamesAct(run: string, word: string): boolean {
  const folded = run.toLowerCase()
  if (MANDATE_PATH_READ_RUNS.has(folded)) return false
  if (camelTokens(run).includes(word)) return true
  if (MANDATE_PATH_ACT_PREFIXES.some((p) => folded.startsWith(p) && (inflectsWord(folded.slice(p.length), word) || startsWithAct(folded.slice(p.length), word)))) return true
  return startsWithAct(folded, word)
}
// Whether a segment names one of the words in any of its runs of letters:
// "bulk-delete", "deleteAll", "DELETEmessage" and "deletemessage.json" all
// name "delete".
function segmentNames(segment: string, words: readonly string[], names: (run: string, word: string) => boolean): boolean {
  const runs = segment.split(/[^A-Za-z]+/).filter((run) => run !== "")
  return runs.some((run) => words.some((w) => names(run, w)))
}
// A last segment that only says how much a delete before it takes.
const MANDATE_PATH_DELETE_SCOPES = new Set(["all", "bulk", "many"])
// The segments of a path that may name a delete: the last, and the one before a last that is a listed scope, or
// before up to two trailing IDs (each holding a digit), those IDs included.
function deleteSegments(parts: readonly string[]): string[] {
  if (MANDATE_PATH_DELETE_SCOPES.has((parts.at(-1) ?? "").toLowerCase())) return parts.slice(-2)
  let at = parts.length - 1
  while (at > 0 && at >= parts.length - 2 && holdsDigit(parts[at] ?? "")) at--
  return parts.slice(Math.max(at, 0))
}
// What a GET or HEAD may do when its path names it on a service nobody has
// reviewed (Telegram's GET /bot{token}/editMessageText), and of those, what
// also sends. Mandates' own, so the floor and the standing rules are as
// they were.
const MANDATE_PATH_ACT_WORDS = ["edit", "update", "set", "create", "add", "forward", "copy", "pin", "unpin", "leave", "close", "stop", "move", "rename", "approve", "decline", "post", "upload", "replace", "ban", "kick", "restrict", "promote", "logout", "verify", "reopen", "hide", "unhide", "schedule", "unban", "gift", "upgrade", "convert", "export", "save", "invite", "join", "disable", "uninstall"] as const
const MANDATE_PATH_SEND_WORDS = ["forward", "copy", "answer"] as const
// The start of a lowercased run that sends a message: Slack's
// chat.postMessage, chat.scheduleMessage, chat.meMessage and
// chat.postEphemeral, Telegram's sendMessage.
const MANDATE_PATH_SEND_STARTS = ["postmessage", "schedulemessage", "sendmessage", "memessage", "postephemeral"] as const
// A credential's name the floor's path words leave out.
const MANDATE_PATH_CREDENTIAL_WORDS = ["passwd"] as const
// What an operation selector may name that changes who has access, beside
// the act words: ?action=share_doc, ?op=grantRole.
const MANDATE_SELECTOR_SHARING_ACTS = ["share", "grant"] as const

// The facts an operation selector's value gives (?action=delete_item, as
// its parts). An API names one operation there, so a word in any part
// names it, not only one in the last part as on a path: delete_item,
// delete-item and deleteItem are deletes, edit_profile an act. One that
// acts and names access (set_acl, add_member, grant_access) is sharing, as
// it would be on a write, never a read.
function selectorFacts(parts: readonly string[], read: boolean, rpc: MandateRpcMethod | null): MandateFact[] {
  const facts: MandateFact[] = []
  const names = (words: readonly string[], test: (run: string, word: string) => boolean = runNamesAct): boolean => parts.some((part) => segmentNames(part, words, test))
  const deletes = names(MANDATE_PATH_DELETE_WORDS, runNamesDelete)
  const acts = names(MANDATE_PATH_ACT_WORDS) || names(MANDATE_SELECTOR_SHARING_ACTS)
  if (deletes) facts.push("destructive")
  if (read && rpc === null && acts) facts.push("act")
  if (read && (names(MANDATE_PATH_SEND_WORDS) || names(MANDATE_PATH_SEND_STARTS, (run, start) => run.toLowerCase().startsWith(start)))) facts.push("send")
  // The floor's words, read in each part and in each camelCase word of it,
  // so setAcl names acl as set_acl does.
  const words = parts.flatMap((part) => part.split(/[^A-Za-z]+/).filter((run) => run !== "").flatMap(camelTokens))
  const path = "/" + [...parts, ...words].join("/")
  facts.push(...policyPathFloorReasons(path, read))
  if ((acts || deletes) && policyPathFloorReasons(path).includes("sharing")) facts.push("sharing")
  return facts
}

// Telegram's Bot API and Slack's Web API name the method in the path and
// take every method on a GET, so no word list finds every act. There a
// method is an act on any HTTP method unless it has a read's shape, and a
// send when it starts with one of the service's send words. The rest of
// the word rules still add send and delete. A Telegram file download is a
// read.
type MandateRpcMethod = { service: "telegram" | "slack"; method: string } | { service: "telegram-file" }
// Which of the two a destination is, by the host and path the relay
// fetches: api.telegram.org's /bot<token>/<method> or
// /file/bot<token>/..., or /api/<method> on slack.com or a subdomain of it.
// The method is lowercased.
function mandateRpcMethod(host: string, segments: readonly string[]): MandateRpcMethod | null {
  const first = (segments[0] ?? "").toLowerCase()
  if (host === "api.telegram.org") {
    if (segments.length >= 3 && segments[0] === "file" && segments[1]?.startsWith("bot")) return { service: "telegram-file" }
    if (segments.length >= 2 && first.startsWith("bot")) return { service: "telegram", method: (segments.at(-1) ?? "").toLowerCase() }
  }
  if ((host === "slack.com" || host.endsWith(".slack.com")) && segments.length === 2 && first === "api") return { service: "slack", method: (segments[1] ?? "").toLowerCase() }
  return null
}
// The starts of a Telegram method that delivers content to a user or chat,
// or alters what a chat sees: sendMessage, answerCallbackQuery,
// editMessageText, postStory, approveSuggestedPost, giftPremiumSubscription,
// stopPoll, setMessageReaction and the rest.
const MANDATE_TELEGRAM_SEND_STARTS = ["send", "forward", "copy", "answer", "edit", "post", "approvesuggestedpost", "savepreparedinlinemessage", "gift", "upgradegift", "transfergift", "stoppoll", "stopmessagelivelocation", "repoststory", "setgamescore", "setmessagereaction", "pinchatmessage"] as const
// The starts of the part of a Slack method after its last dot that read:
// conversations.history, users.info, chat.getPermalink.
const MANDATE_SLACK_READ_STARTS = ["list", "info", "history", "replies", "get", "lookup", "search", "members", "profile", "test", "count", "bots"] as const
// The starts of that part that send: chat.postMessage, conversations.invite.
const MANDATE_SLACK_SEND_STARTS = ["postmessage", "postephemeral", "memessage", "schedulemessage", "share", "invite"] as const
// Whole Slack methods that alter what a conversation already sees, or put
// something new in front of it, with no send word to find: an edit, an
// unfurl, a streamed message, a file shared on upload, a reaction, a pin
// (which Slack announces) and a topic or purpose (posted as a message).
const MANDATE_SLACK_SEND_METHODS: ReadonlySet<string> = new Set(["chat.update", "chat.unfurl", "chat.startstream", "chat.appendstream", "chat.stopstream", "files.upload", "files.completeuploadexternal", "reactions.add", "reactions.remove", "pins.add", "conversations.settopic", "conversations.setpurpose"])
// The facts a Telegram or Slack method gives on any HTTP method: an act
// unless it reads (Telegram's get methods; a Slack method whose family is
// search, or whose part after the last dot is letters starting with a read
// word), and a send when it starts with a send word or, on Slack, is one
// of the whole methods that send.
function rpcMethodFacts(rpc: MandateRpcMethod): MandateFact[] {
  if (rpc.service === "telegram-file") return []
  const facts: MandateFact[] = []
  if (rpc.service === "telegram") {
    if (!/^get[a-z]*$/.test(rpc.method)) facts.push("act")
    if (MANDATE_TELEGRAM_SEND_STARTS.some((s) => rpc.method.startsWith(s))) facts.push("send")
    return facts
  }
  const last = rpc.method.split(".").at(-1) ?? ""
  const reads = rpc.method.split(".")[0] === "search" || (/^[a-z]+$/.test(last) && MANDATE_SLACK_READ_STARTS.some((s) => last.startsWith(s)))
  if (!reads) facts.push("act")
  if (MANDATE_SLACK_SEND_STARTS.some((s) => last.startsWith(s)) || MANDATE_SLACK_SEND_METHODS.has(rpc.method)) facts.push("send")
  return facts
}

// The fact a floor refusal word gives: rule.credential is credential, and
// so on; rule.destructive is destructive and rule.generic generic.
function refusalFact(refusal: PolicyRuleRefusal): MandateFact {
  switch (refusal) {
    case "rule.credential": return "credential"
    case "rule.persistence": return "persistence"
    case "rule.sharing": return "sharing"
    case "rule.money": return "money"
    case "rule.send": return "send"
    case "rule.destructive": return "destructive"
    case "rule.generic": return "generic"
    default: return "unreadable"
  }
}

// Every fact about a request, from the same pieces the standing rules'
// floor test reads, without its early return on a DELETE, which is still
// read for everything else it does. A method other than the six a class
// names (OPTIONS included) is the method fact. policyFloorRefusal is
// untouched by this.
export function mandateRequestFacts(request: PolicyRuleAnchor): ReadonlySet<MandateFact> {
  const d = request.destination
  const facts = new Set<MandateFact>()
  const input = { destination: d, body: request.body, contentType: request.contentType, contentEncoding: request.contentEncoding }
  if (d.scheme !== "https" || d.port !== 443) facts.add("destination")
  if (!CLASS_METHODS.includes(d.method)) facts.add("method")
  if (d.method === "DELETE") facts.add("destructive")
  let graphql = d.path.split("/").some((s) => s.toLowerCase() === "graphql")
  const base = evaluatePolicy(request.policy, d, request.body)
  if (base.action === "deny") facts.add("deny")
  for (const rule of base.matched) {
    if (rule.action !== "approve") continue
    if (rule.body === "graphql-mutation") graphql = true
    else facts.add("item-rule")
  }
  const floor = evaluatePolicyFloor(input)
  if (floor.action === "deny") facts.add("deny")
  for (const reason of floor.reasons) {
    const entry = POLICY_FLOOR.find((f) => f.id === reason)
    if (entry !== undefined) {
      if (entry.action === "deny") facts.add("deny")
      else if (entry.reason !== "opaque") facts.add(entry.reason)
      else if (entry.rule.body === "graphql-mutation") graphql = true
      else facts.add("unreadable")
      continue
    }
    const catalogued = catalogueFloorReason(reason)
    if (catalogued !== null) facts.add(catalogued === "opaque" ? "unreadable" : catalogued)
    else if (reason.startsWith("generic.")) facts.add("generic")
    else if (reason === "safety.graphql-proof") graphql = true
    else if (DESTINATION_SAFETY.has(reason)) facts.add("destination")
    else facts.add("unreadable")
  }
  const classification = classifyPolicyRequest(input)
  if (classification.effect === "destructive") facts.add("destructive")
  if (!facts.has("generic") && classification.routeId === null) {
    for (const reason of policyPathFloorReasons(d.path, READ_METHODS.includes(d.method))) facts.add(reason)
  }
  // A route nobody has reviewed whose path names a delete is one, whatever
  // its method, as a GraphQL mutation named so is. The delete is named in
  // the last segments deleteSegments gives: POST /v1/tasks/7/delete,
  // POST /v1/delete/7/8 and GET /v1/delete/all. An act is named
  // only in a last segment with no digit, where an RPC method name sits;
  // earlier segments are resources and slugs. A query parameter that names
  // the method is read by selectorFacts, every part of its value. On
  // Telegram and Slack, rpcMethodFacts alone decides the act.
  if (classification.routeId === null) {
    const segments = pathSegments(d.path)
    const read = READ_METHODS.includes(d.method)
    const rpc = mandateRpcMethod(d.host, segments)
    if (rpc !== null) for (const fact of rpcMethodFacts(rpc)) facts.add(fact)
    for (const parts of queryMethodParts(d.search)) for (const fact of selectorFacts(parts, read, rpc)) facts.add(fact)
    if (rpc?.service !== "telegram-file") {
      const last = segments.at(-1) ?? ""
      const namesAct = (words: readonly string[], names = runNamesAct): boolean => read && !holdsDigit(last) && segmentNames(last, words, names)
      if (deleteSegments(segments).some((s) => segmentNames(s, MANDATE_PATH_DELETE_WORDS, runNamesDelete))) facts.add("destructive")
      if (rpc === null && namesAct(MANDATE_PATH_ACT_WORDS)) facts.add("act")
      if (namesAct(MANDATE_PATH_SEND_WORDS) || namesAct(MANDATE_PATH_SEND_STARTS, (run, start) => run.toLowerCase().startsWith(start))) facts.add("send")
    }
    // Reading a credential, which the floor's path words name for a write
    // only: a password, a connection URI, an env.
    if ((READ_METHODS.includes(d.method) && policyPathFloorReasons(d.path).includes("credential")) || segments.some((s) => MANDATE_PATH_CREDENTIAL_WORDS.some((w) => segmentLetters(s).includes(w)))) facts.add("credential")
  }
  for (const refusal of ruleOnlyRefusals(d)) facts.add(refusalFact(refusal))
  if (graphql) {
    const proof = graphqlMutationRootFields(request.body)
    const nested = proof.ok ? new Set(proof.nestedFields).size : 0
    if (!proof.ok || d.search !== "" || !(request.body === null || isJsonType(request.contentType)) || nested > POLICY_RULE_MAX_NESTED_FIELDS) facts.add("unreadable")
    else for (const field of [...proof.fields, ...proof.nestedFields]) for (const refusal of fieldFloorRefusals(field)) facts.add(refusalFact(refusal))
  }
  if (queryNamesOf(d.search) === null) facts.add("unreadable")
  if (!graphql && request.body !== null && !isJsonType(request.contentType)) {
    const { entry } = policyCatalogueVerdict(input)
    if (entry === null || !coveredBody(entry, request)) facts.add("unreadable")
  }
  if (holdsLiveKey(request)) facts.add("live-key")
  return facts
}

// The classes a request is in, sorted, or never: send for a send,
// delete for anything destructive, change for a write, a request the
// item's own rules ask for or a GET or HEAD whose path names an act, and
// read for a GET or HEAD in no other class.
export function mandateClassesOf(facts: ReadonlySet<MandateFact>, method: string): MandateClass[] | "never" {
  if (MANDATE_NEVER_FACTS.some((f) => facts.has(f))) return "never"
  const classes = new Set<MandateClass>()
  if (facts.has("send")) classes.add("send")
  if (facts.has("destructive")) classes.add("delete")
  if (WRITE_METHODS.includes(method) || facts.has("item-rule") || facts.has("act")) classes.add("change")
  if (READ_METHODS.includes(method) && classes.size === 0) classes.add("read")
  return classes.size === 0 ? "never" : MANDATE_CLASSES.filter((c) => classes.has(c))
}

// A mandate reaches a destination only on a host the credential's binding
// names exactly: a wildcard host may admit a subdomain someone else holds.
export function mandateHostNamed(binding: Binding, host: string): boolean {
  return binding.hosts.some((h) => !h.includes("*") && hostMatches(h, host))
}
// Whether a forwarded header names the operation, which the classes never
// read: AWS's X-Amz-Target (DynamoDB_20120810.DeleteTable), SOAP's
// SOAPAction, or a Google-style X-Goog-...-Method. No mandate covers such a
// request; it asks, as an unreadable one does.
export function mandateHeadersNameOperation(names: readonly string[]): boolean {
  return names.some((n) => {
    const name = n.toLowerCase()
    return name === "x-amz-target" || name === "soapaction" || /^x-goog-.*-method$/.test(name)
  })
}
// Why no request on a credential could ever be covered, or null.
export function mandateCredentialNever(binding: Binding, secretPrefixes: readonly string[]): MandateCandidateNever | null {
  if (holdsLiveKey({ secretPrefixes: [...secretPrefixes] })) return "live-key"
  return binding.hosts.every((h) => h.includes("*")) ? "wildcard-host" : null
}

const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
// The weekday (0 Sunday) and minutes past midnight of a moment in a zone.
function localTime(now: number, tz: string): { day: number; minutes: number } {
  const parts = new Intl.DateTimeFormat("en-GB", { timeZone: tz, weekday: "short", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).formatToParts(new Date(now))
  const part = (type: string): string => parts.find((p) => p.type === type)?.value ?? ""
  return { day: WEEKDAYS.indexOf(part("weekday")), minutes: Number(part("hour")) * 60 + Number(part("minute")) }
}
const minutesOf = (clock: string): number => Number(clock.slice(0, 2)) * 60 + Number(clock.slice(3, 5))

// Whether a moment is inside one of the schedule's windows; always, with none.
export function mandateScheduleOpen(schedule: MandateSchedule | null, now: number): boolean {
  if (schedule === null) return true
  const { day, minutes } = localTime(now, schedule.tz)
  if (day < 0) return false
  const before = (day + 6) % 7
  return schedule.windows.some((w) => {
    const from = minutesOf(w.from), to = minutesOf(w.to)
    if (from < to) return w.days.includes(day) && minutes >= from && minutes < to
    return (w.days.includes(day) && minutes >= from) || (w.days.includes(before) && minutes < to)
  })
}

// The state the vault keeps beside the terms, as covering reads it.
export type MandateCoverView = { state: MandateState; expiresAt: number }
// Whether the terms let these classes through now: active, not expired,
// inside the schedule, and every class ticked. Caps, the credentials, the
// machine, the signer and the binding are the vault's.
export function mandateCovers(terms: Pick<MandateTerms, "classes" | "schedule">, view: MandateCoverView, classes: readonly MandateClass[], now: number): boolean {
  if (view.state !== "active" || now >= view.expiresAt || classes.length === 0) return false
  return mandateScheduleOpen(terms.schedule, now) && classes.every((c) => terms.classes.includes(c))
}

// What a passkey signs to make a mandate (mandate.sign, and mandate.resume
// beside the revision it resumes): the terms, the workspace and the signer.
export function mandateDigest(input: { terms: MandateTerms; workspace: string; signer: string }): Promise<string> {
  return sha256B64(canonicalJson({ domain: "mehen-mandate/v1", terms: input.terms, workspace: input.workspace, signer: input.signer }))
}

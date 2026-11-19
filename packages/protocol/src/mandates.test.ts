import { describe, expect, test } from "bun:test"
import { parseDestination, type Binding, type Policy } from "./binding.ts"
import { MANDATE_CAP_DEFAULTS, MandateProposedTermsSchema, MandateTermsSchema, mandateCapsFit, parseMandateReceiptsCursor, mandateReceiptsCursor, type MandateClass, type MandateSchedule, type MandateTerms } from "./mandate-terms.ts"
import { mandateClassesOf, mandateCovers, mandateCredentialNever, mandateDigest, mandateHeadersNameOperation, mandateHostNamed, mandateRequestFacts, mandateScheduleOpen } from "./mandates.ts"
import { POLICY_RULE_METHODS } from "./policy-mode.ts"
import { policyFloorRefusal, type PolicyRuleAnchor } from "./policy-rules.ts"
import { TEMPLATES } from "./templates.ts"

const encoded = (value: unknown): Uint8Array => new TextEncoder().encode(typeof value === "string" ? value : JSON.stringify(value))

// A held request on a template's policy and binding, or on a credential
// with no template (everything asks), as the relay holds it.
function held(template: string | null, method: string, url: string, body: unknown = null, overrides: Partial<PolicyRuleAnchor> = {}): PolicyRuleAnchor {
  const t = template === null ? null : TEMPLATES[template]
  if (template !== null && !t) throw new Error(`No template ${template}`)
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`Invalid test destination ${url}`)
  return {
    item: "work-key", itemId: "itm_work0001", asker: { device: "dev_alexmbp", workload: null }, destination: parsed.destination,
    body: body === null ? null : encoded(body), contentType: body === null ? null : "application/json", contentEncoding: null,
    policy: (t?.policy ?? { default: "approve", rules: [] }) as Policy, binding: (t?.binding ?? { hosts: [new URL(url).hostname] }) as Binding, secretPrefixes: [], ...overrides,
  }
}
const classesOf = (request: PolicyRuleAnchor) => mandateClassesOf(mandateRequestFacts(request), request.destination.method)

describe("mandateRequestFacts and mandateClassesOf on real routes", () => {
  test.each([
    ["a GitHub issue comment", held("github-pat", "POST", "https://api.github.com/repos/alex/vault/issues/42/comments", { body: "Looks right." }), ["change"]],
    ["Slack chat.postMessage, after the split", held("slack-bot", "POST", "https://slack.com/api/chat.postMessage", { channel: "C1", text: "hi" }), ["change", "send"]],
    ["DELETE /repos/x/y", held("github-pat", "DELETE", "https://api.github.com/repos/x/y"), ["delete"]],
    ["a custom DELETE", held(null, "DELETE", "https://api.example.com/v1/tasks/7"), ["delete"]],
    ["a plain GET", held(null, "GET", "https://api.example.com/v1/tasks"), ["read"]],
    ["Telegram GET /bot.../sendMessage", held(null, "GET", "https://api.telegram.org/bot123456:TEST/sendMessage?chat_id=1&text=hi"), ["change", "send"]],
    ["a proven Linear commentCreate", held("linear", "POST", "https://api.linear.app/graphql", { query: "mutation { commentCreate(input: {}) { success } }" }), ["change"]],
    ["a custom POST", held(null, "POST", "https://api.example.com/v1/tasks", { task: "a" }), ["change"]],
    ["two GraphQL mutations without aliases", held(null, "POST", "https://api.example.com/graphql", { query: "mutation { commentCreate(input: {}) { success } issueUpdate(input: {}) { success } }" }), ["change"]],
  ] as [string, PolicyRuleAnchor, MandateClass[]][])("%s gives its classes", (_, request, classes) => {
    expect(classesOf(request)).toEqual(classes)
  })

  test.each([
    ["Slack conversations.invite", held("slack-bot", "POST", "https://slack.com/api/conversations.invite", { channel: "C1", users: "U1" }), "sharing"],
    ["Slack chat.delete, its own opaque rule", held("slack-bot", "POST", "https://slack.com/api/chat.delete", { channel: "C1", ts: "1" }), "unreadable"],
    ["OPTIONS", held(null, "OPTIONS", "https://api.example.com/v1/tasks"), "method"],
    ["TRACE", held(null, "TRACE", "https://api.example.com/v1/tasks"), "method"],
    ["a DELETE of a token", held(null, "DELETE", "https://api.example.com/v1/tokens/7"), "generic"],
    ["a DELETE of a credential path", held(null, "DELETE", "https://api.example.com/v1/connection_uri/7"), "credential"],
    ["a DELETE of forwarding", held(null, "DELETE", "https://api.example.com/v1/settings/forwarding"), "persistence"],
    ["a DELETE of a member", held(null, "DELETE", "https://api.example.com/v1/teams/7/members/3"), "generic"],
    ["a DELETE of an access-control entry", held(null, "DELETE", "https://api.example.com/v1/acl/7"), "sharing"],
    ["a DELETE with an opaque body", held(null, "DELETE", "https://api.example.com/v1/tasks/7", "remove it", { contentType: "text/plain" }), "unreadable"],
    ["a DELETE the item's policy denies", held(null, "DELETE", "https://api.example.com/v1/tasks/7", null, { policy: { default: "approve", rules: [{ action: "deny", methods: ["DELETE"] }] } }), "deny"],
    ["Stripe POST /v1/refunds", held("stripe", "POST", "https://api.stripe.com/v1/refunds", { charge: "ch_1" }, { secretPrefixes: ["sk_test_"] }), "money"],
    ["any sk_live_ key", held(null, "POST", "https://api.example.com/v1/tasks", { task: "a" }, { secretPrefixes: ["sk_live_"] }), "live-key"],
    ["GitHub POST /repos/x/y/hooks", held("github-pat", "POST", "https://api.github.com/repos/x/y/hooks", { name: "web" }), "deny"],
    ["a custom /rpc body naming createApiKey as JSON-RPC", held(null, "POST", "https://api.example.com/rpc", { jsonrpc: "2.0", method: "createApiKey" }), "unreadable"],
    ["a custom /rpc body naming createApiKey as its method", held(null, "POST", "https://api.example.com/rpc", { method: "createApiKey", params: {} }), "unreadable"],
    ["a GraphQL query selecting apiKeys", held(null, "POST", "https://api.example.com/graphql", { query: "query { apiKeys { id secret } }" }), "unreadable"],
    ["aliased GraphQL mutations", held(null, "POST", "https://api.example.com/graphql", { query: "mutation { a: commentCreate(input: {}) { success } b: commentCreate(input: {}) { success } }" }), "unreadable"],
    ["aliased GraphQL fields", held(null, "POST", "https://api.example.com/graphql", { query: "query { a: viewer { id } b: viewer { name } }" }), "unreadable"],
    ["a GraphQL fragment", held(null, "POST", "https://api.example.com/graphql", { query: "mutation { commentCreate(input: {}) { ...F } } fragment F on X { id }" }), "unreadable"],
    ["a persisted GraphQL query", held(null, "POST", "https://api.example.com/graphql", { extensions: { persistedQuery: { version: 1, sha256Hash: "abc" } } }), "unreadable"],
    ["a GraphQL batch", held(null, "POST", "https://api.example.com/graphql", [{ query: "mutation { commentCreate(input: {}) { success } }" }]), "unreadable"],
    ["a JSON batch", held(null, "POST", "https://api.example.com/v1/tasks", [{ task: "a" }, { task: "b" }]), "unreadable"],
    ["a proven GraphQL mutation naming a webhook", held("linear", "POST", "https://api.linear.app/graphql", { query: "mutation { webhookCreate(input: {}) { success } }" }), "persistence"],
    ["a proven GraphQL mutation sent with a query string", held("linear", "POST", "https://api.linear.app/graphql?x=1", { query: "mutation { commentCreate(input: {}) { success } }" }), "unreadable"],
    ["a form body", held(null, "POST", "https://api.example.com/v1/tasks", "task=a", { contentType: "application/x-www-form-urlencoded" }), "unreadable"],
    ["a repeated query name", held(null, "GET", "https://api.example.com/v1/tasks?a=1&a=2"), "unreadable"],
    ["a GET of a password", held(null, "GET", "https://api.unreviewed.example/v1/passwords/1"), "credential"],
    ["a GET of a passwd", held(null, "GET", "https://api.unreviewed.example/v1/passwd"), "credential"],
    ["a GET of a connection URI", held(null, "GET", "https://api.unreviewed.example/v1/databases/7/connection_uri"), "credential"],
    ["a GET of an env", held(null, "GET", "https://api.unreviewed.example/v1/projects/x/env/"), "credential"],
    ["a HEAD of a password", held(null, "HEAD", "https://api.unreviewed.example/v1/passwords/1"), "credential"],
    ["plain HTTP", held(null, "GET", "http://api.example.com/v1/tasks"), "destination"],
    ["another port", held(null, "GET", "https://api.example.com:8443/v1/tasks"), "destination"],
  ] as [string, PolicyRuleAnchor, string][])("%s is never", (_, request, fact) => {
    expect(mandateRequestFacts(request).has(fact as never)).toBe(true)
    expect(classesOf(request)).toBe("never")
  })

  // On a service nobody has reviewed, a write whose path names a delete is
  // one, as a GraphQL mutation named so is.
  test.each(["delete", "archive", "purge", "bulk-delete", "deleteAll"])("POST /v1/tasks/7/%s is a change and a delete, not covered without delete", (word) => {
    const request = held(null, "POST", `https://api.example.com/v1/tasks/7/${word}`, { confirm: true })
    expect(classesOf(request)).toEqual(["change", "delete"])
    expect(mandateCovers(terms({ classes: ["change", "read"], caps: { ...MANDATE_CAP_DEFAULTS, send: 0, delete: 0 } }), active, classesOf(request) as MandateClass[], at("2026-11-08T12:00:00Z"))).toBe(false)
  })

  // A GET that names an act on a service nobody has reviewed (Telegram's
  // Bot API takes every method on a GET) is in that act's class, never a read.
  const telegram = (method: string) => held(null, "GET", `https://api.telegram.org/bot123456:TEST/${method}?chat_id=1&message_id=2`)
  test.each([
    ["deleteMessage", ["change", "delete"]],
    ["deletemessage", ["change", "delete"]],
    ["deleteMyCommands", ["change", "delete"]],
    ["editMessageText", ["change", "send"]],
    ["pinChatMessage", ["change", "send"]],
    ["unpinAllChatMessages", ["change"]],
    ["setChatTitle", ["change"]],
    ["stopPoll", ["change", "send"]],
    ["leaveChat", ["change"]],
    ["forwardMessage", ["change", "send"]],
    ["copyMessage", ["change", "send"]],
    ["replaceStickerInSet", ["change"]],
    ["banChatSenderChat", ["change", "send"]],
    ["kickUser", ["change"]],
    ["restrictUser", ["change"]],
    ["promoteUser", ["change"]],
    ["logOut", ["change"]],
    ["verifyUser", ["change"]],
    ["reopenForumTopic", ["change"]],
    ["hideGeneralForumTopic", ["change"]],
    ["unhideGeneralForumTopic", ["change"]],
    ["sendMessage", ["change", "send"]],
  ] as [string, MandateClass[]][])("Telegram GET /bot.../%s gives %p", (method, classes) => {
    expect(classesOf(telegram(method))).toEqual(classes)
    expect(mandateCovers(terms({ classes: ["read"], caps: { ...MANDATE_CAP_DEFAULTS, change: 0, send: 0, delete: 0 } }), active, classes, at("2026-11-08T12:00:00Z"))).toBe(false)
  })

  // A word counts only as a whole token in its place: a collection, a state,
  // a slug or an ID that holds its letters is still a read.
  test.each([
    "https://api.telegram.org/bot123456:TEST/getUpdates",
    ...["posts", "settings", "addresses", "shipping", "mapping", "assets", "offset", "credits", "ping", "datasets", "presets", "enforcement", "postgres", "pinecone", "setups", "additional", "stopwords"].map((s) => `https://api.example.com/v1/${s}`),
    "https://api.example.com/v1/commits/0a1dd3f9c2b4e5d6a7b8c9d0e1f2a3b4c5d6e7f8",
    "https://api.example.com/repos/alex/postgres-tools/issues",
  ])("GET %s stays a read", (url) => {
    expect(classesOf(held(null, "GET", url))).toEqual(["read"])
  })

  test("a delete counts in the last segment, or the one before an ID; an act only in a last segment with no digit", () => {
    expect(classesOf(held(null, "POST", "https://api.example.com/v1/delete/7", { confirm: true }))).toEqual(["change", "delete"])
    expect(classesOf(held(null, "POST", "https://api.example.com/v1/delete/tasks", { confirm: true }))).toEqual(["change"])
    expect(classesOf(held(null, "GET", "https://api.example.com/v1/update/tasks"))).toEqual(["read"])
    expect(classesOf(held(null, "GET", "https://api.example.com/v1/tasks/update7"))).toEqual(["read"])
  })

  test.each(["deleted", "archived", "removed", "suspended", "updates", "updated", "pinned", "closed", "edits", "copies", "pins", "stops", "stopped", "editions", "movement", "setup"])("GET /v1/tasks/%s, a collection or a state, stays a read", (word) => {
    expect(classesOf(held(null, "GET", `https://api.example.com/v1/tasks/${word}`))).toEqual(["read"])
  })

  test.each([
    ["editmessagetext", ["change"]],
    ["setchattitle", ["change"]],
    ["pinchatmessage", ["change"]],
    ["stoppoll", ["change"]],
    ["leavechat", ["change"]],
    ["forwardmessage", ["change", "send"]],
    ["DELETEALL", ["delete"]],
  ] as [string, MandateClass[]][])("a case-folded method name, GET .../%s, gives %p", (method, classes) => {
    expect(classesOf(held(null, "GET", `https://api.example.com/v1/${method}`))).toEqual(classes)
  })

  // Telegram reads a method name in any letter case, so the capitals the
  // sender moves never hide a word, nor does a suffix after a separator.
  test.each([
    ["DELETEmessage", ["change", "delete"]],
    ["deLeteMessage", ["change", "delete"]],
    ["DeleteMESSAGE", ["change", "delete"]],
    ["FORWARDmessage", ["change", "send"]],
    ["forwardmessagE", ["change", "send"]],
    ["deletemessage.json", ["change", "delete"]],
    ["editmessage_text", ["change", "send"]],
  ] as [string, MandateClass[]][])("Telegram GET /bot.../%s, its capitals moved, gives %p", (method, classes) => {
    expect(classesOf(telegram(method))).toEqual(classes)
  })

  test("the segment before an ID names a delete in any letter case", () => {
    expect(classesOf(held(null, "POST", "https://api.example.com/v1/deleteall/7", { confirm: true }))).toEqual(["change", "delete"])
    expect(classesOf(held(null, "POST", "https://api.example.com/v1/tasks/7/DELETEall", { confirm: true }))).toEqual(["change", "delete"])
  })

  // Up to two trailing IDs, or a last segment of all, bulk or many, leave the
  // segment before them checked for a delete word; three IDs or another last
  // word do not.
  test.each([
    ["POST", "v1/delete/7/8", ["change", "delete"]],
    ["GET", "v1/delete/7/8", ["delete"]],
    ["GET", "v1/delete/all", ["delete"]],
    ["GET", "v1/messages/DELETE/Many", ["delete"]],
    ["POST", "v1/archive/bulk", ["change", "delete"]],
    ["GET", "api?do=a.delete.1.2", ["delete"]],
    ["GET", "api?method=photos.delete.all", ["delete"]],
    ["POST", "v1/delete/7/8/9", ["change"]],
    ["GET", "v1/delete/everything", ["read"]],
    ["POST", "v1/projects/delete/myproject", ["change"]],
  ] as [string, string, MandateClass[]][])("%s /%s gives %p", (method, path, classes) => {
    expect(classesOf(held(null, method, `https://api.example.com/${path}`, method === "POST" ? { confirm: true } : null))).toEqual(classes)
  })

  // A delete word counts anywhere in a run, so predelete is one; a run on the
  // stoplist, such as enforce, names none.
  test.each([
    ["GET", "tasks/bulkdelete", ["delete"]],
    ["POST", "x/softdelete", ["change", "delete"]],
    ["GET", "tasks/BULKdelete", ["delete"]],
    ["GET", "tasks/batchdeleted", ["delete"]],
    ["GET", "tasks/unarchive", ["delete"]],
    ["GET", "tasks/massremove", ["delete"]],
    ["GET", "tasks/multipurge", ["delete"]],
    ["GET", "tasks/harddestroy", ["delete"]],
    ["GET", "tasks/forcewipe", ["delete"]],
    ["GET", "tasks/enforce", ["read"]],
    ["GET", "tasks/predelete", ["delete"]],
  ] as [string, string, MandateClass[]][])("%s /v1/%s gives %p", (method, path, classes) => {
    expect(classesOf(held(null, method, `https://api.example.com/v1/${path}`, method === "POST" ? { confirm: true } : null))).toEqual(classes)
  })

  // A query parameter that names the method, as Flickr's ?method= does on a
  // GET, its name in any letter case, names an act or a delete in any part
  // of its value, not only in the last.
  test.each([
    ["GET", "services/rest?method=flickr.photos.delete&photo_id=1", ["delete"]],
    ["GET", "services/rest?Method=flickr.photos.DELETE", ["delete"]],
    ["GET", "api?action=editMessage", ["change"]],
    ["GET", "api?op=forwardMessage", ["change", "send"]],
    ["GET", "api?cmd=tasks%2Earchive", ["delete"]],
    ["GET", "api?do=tasks.delete.7", ["delete"]],
    ["GET", "api?OPERATION=bulkdelete", ["delete"]],
    ["POST", "api?method=photos.delete", ["change", "delete"]],
    ["GET", "services/rest?method=flickr.photos.getList", ["read"]],
    ["GET", "services/rest?method=flickr.delete.photos", ["delete"]],
    ["GET", "api?q=delete", ["read"]],
    ["GET", "http-api.php?action=sendsms&to=1&text=hi", ["send"]],
    ["GET", "api?method=sendMessage", ["send"]],
    ["GET", "api?op=broadcast", ["send"]],
    ["GET", "api?q=sendsms", ["read"]],
  ] as [string, string, MandateClass[]][])("%s /%s gives %p", (method, path, classes) => {
    expect(classesOf(held(null, method, `https://api.example.com/${path}`, method === "POST" ? { confirm: true } : null))).toEqual(classes)
  })

  // The review's selectors: split at an underscore or a hyphen, or written
  // in camelCase, the act or delete in the first part still counts, and one
  // that changes who has access is sharing, never a read.
  test.each([
    ["delete_item", ["delete"]],
    ["delete-item", ["delete"]],
    ["deleteItem", ["delete"]],
    ["edit_profile", ["change"]],
    ["edit-profile", ["change"]],
    ["editProfile", ["change"]],
    ["items.remove_all", ["delete"]],
    ["list_items", ["read"]],
    ["get_acl", ["read"]],
  ] as [string, MandateClass[]][])("GET /api?action=%s gives %p", (selector, classes) => {
    expect(classesOf(held(null, "GET", `https://api.example.com/api?action=${selector}`))).toEqual(classes)
    expect(classesOf(held(null, "GET", `https://api.example.com/api?op=${selector}&id=7`))).toEqual(classes)
  })

  test.each(["set_acl", "set-acl", "setAcl", "add_member", "grant_access", "share_doc", "update_permissions", "remove_collaborator"])("GET /api?action=%s changes who has access, so it is sharing and never", (selector) => {
    const request = held(null, "GET", `https://api.example.com/api?action=${selector}`)
    expect(mandateRequestFacts(request).has("sharing")).toBe(true)
    expect(classesOf(request)).toBe("never")
  })

  test.each(["delete_item", "delete-item", "deleteItem", "edit_profile", "set_acl"])("a reads-only mandate never covers GET /api?action=%s", (selector) => {
    const classes = classesOf(held(null, "GET", `https://api.example.com/api?action=${selector}`))
    const covered = classes !== "never" && mandateCovers(terms({ classes: ["read"], caps: { ...MANDATE_CAP_DEFAULTS, change: 0, send: 0, delete: 0 } }), active, classes, at("2026-11-08T12:00:00Z"))
    expect(covered).toBe(false)
  })

  test("a query parameter that names a money method on a GET is never", () => {
    const request = held(null, "GET", "https://api.example.com/api?action=refund&id=7")
    expect(mandateRequestFacts(request).has("money")).toBe(true)
    expect(classesOf(request)).toBe("never")
  })

  // The spare is decided on the lowercased run alone: a word at the start is
  // spared only when an inflection follows it, alone or then exactly one of
  // by, for, page, list, count, feed, summary or info. So settingsPage and
  // postsList read. postsByUser asks, an accepted cost:
  // "byuser" is not one listed tail. postsDelete and settingsdelete hold a
  // delete word after the start, and post and set are not spared there.
  test.each([
    ["settingsPage", ["read"]],
    ["postsList", ["read"]],
    ["archived", ["read"]],
    ["presets", ["read"]],
    ["postsByUser", ["change"]],
    ["postsDelete", ["change", "delete"]],
    ["settingsdelete", ["change", "delete"]],
    ["postsdeleteAll", ["change", "delete"]],
    ["bulkdeletemessages", ["delete"]],
    ["massdeleteall", ["delete"]],
    ["bulkupdate", ["change"]],
    ["BULKupdate", ["change"]],
    ["unpin", ["change"]],
    ["unset", ["change"]],
  ] as [string, MandateClass[]][])("GET /v1/%s gives %p", (segment, classes) => {
    expect(classesOf(held(null, "GET", `https://api.example.com/v1/${segment}`))).toEqual(classes)
  })

  // Letter case can only add a match, never take one away: Telegram reads
  // deletesTory as deleteStory, and postsTORY as postStory.
  test.each(["deletesTory", "deletesTICKERSET", "deletesTICKERFROMSET", "DELETESTORY", "deleteSTORY"])("%s, its capitals moved to make a plural, is a delete on an unreviewed GET, and on Telegram a change and a delete on GET and POST", (method) => {
    expect(classesOf(held(null, "GET", `https://api.example.com/v1/${method}`))).toEqual(["delete"])
    expect(classesOf(telegram(method))).toEqual(["change", "delete"])
    expect(classesOf(held(null, "POST", `https://api.telegram.org/bot123456:TEST/${method}`, { chat_id: 1 }))).toEqual(["change", "delete"])
  })

  test.each([
    ["postsTORY", ["change", "send"]],
    ["editsTORY", ["change", "send"]],
    ["addsTICKERTOSET", ["change"]],
    ["setsTICKERSETTITLE", ["change"]],
    ["setsTICKERSETTHUMBNAIL", ["change"]],
    ["uploadsTICKERFILE", ["change"]],
    ["approvesUGGESTEDPOST", ["change", "send"]],
  ] as [string, MandateClass[]][])("%s, its capitals moved to make a plural, is a change on an unreviewed GET, and on Telegram %p", (method, classes) => {
    expect(classesOf(held(null, "GET", `https://api.example.com/v1/${method}`))).toEqual(["change"])
    expect(classesOf(telegram(method))).toEqual(classes)
  })

  // A delete word inside a run asks even where it names a read: an accepted
  // cost of reading the run whatever its case.
  test.each(["getDeletedMessages", "deletedItems", "undelete"])("GET /v1/%s asks as a delete, a known cost", (segment) => {
    expect(classesOf(held(null, "GET", `https://api.example.com/v1/${segment}`))).toEqual(["delete"])
  })

  // A run on the delete stoplist holds a delete word inside another word.
  test.each(["preset", "presets", "enforce", "enforcement", "salesforce", "workforce", "swipe", "swipes", "enforcements", "enforced", "workforces"])("GET /v1/%s stays a read", (segment) => {
    expect(classesOf(held(null, "GET", `https://api.example.com/v1/${segment}`))).toEqual(["read"])
  })

  test.each(["forceDelete", "forcedelete", "forceRemove", "forceremove"])("GET /v1/%s is still a delete", (segment) => {
    expect(classesOf(held(null, "GET", `https://api.example.com/v1/${segment}`))).toEqual(["delete"])
  })

  // transfer plus s is spared, so the mandate rules name no delete; the
  // floor alone already makes GET /v1/transfers never, as transfer is one of
  // its GET verb words for sharing.
  // Slack's chat.postMessage and chat.scheduleMessage on a GET, off its
  // reviewed routes, send.
  test.each([
    ["https://slack.example.com/api/chat.postMessage", ["change", "send"]],
    ["https://slack.example.com/api/chat.scheduleMessage", ["change", "send"]],
    ["https://slack.example.com/api/chat.POSTMESSAGE", ["change", "send"]],
    ["https://api.example.com/v1/sendmessage", ["send"]],
  ] as [string, MandateClass[]][])("GET %s gives %p", (url, classes) => {
    expect(classesOf(held(null, "GET", url))).toEqual(classes)
  })

  // The new act words leave their collections and states reads. A word and
  // an inflection then "byuser" is not spared, so schedulesbyuser asks, as
  // postsByUser does: an accepted cost.
  test.each([
    ["schedules", ["read"]],
    ["scheduled", ["read"]],
    ["schedulesList", ["read"]],
    ["replacements", ["read"]],
    ["restrictions", ["read"]],
    ["banners", ["read"]],
    ["banks", ["read"]],
    ["verified", ["read"]],
    ["hidden", ["read"]],
    ["promoted", ["read"]],
    ["schedulesbyuser", ["change"]],
    ["schedule", ["change"]],
  ] as [string, MandateClass[]][])("GET /v1/%s gives %p", (segment, classes) => {
    expect(classesOf(held(null, "GET", `https://api.example.com/v1/${segment}`))).toEqual(classes)
  })

  test("GET /v1/transfers names no delete, and the floor makes it never", () => {
    const facts = mandateRequestFacts(held(null, "GET", "https://api.example.com/v1/transfers"))
    expect(facts.has("destructive")).toBe(false)
    expect([...facts]).toEqual(["sharing"])
  })

  // The trace tables of reviews 245-r2 and 245-r3, on a route nobody has
  // reviewed. /archive/2024 is a delete, a known cost: 2024 is an ID, and
  // archive in the segment before it is a delete word.
  test.each([
    ["GET", "https://api.telegram.org/bot123456:TEST/getUpdates", ["read"]],
    ["GET", "https://api.telegram.org/bot123456:TEST/deleteMessage", ["change", "delete"]],
    ["GET", "https://api.telegram.org/bot123456:TEST/deletemessage", ["change", "delete"]],
    ["GET", "https://api.telegram.org/bot123456:TEST/editMessageText", ["change", "send"]],
    ["GET", "https://api.telegram.org/bot123456:TEST/forwardMessage", ["change", "send"]],
    ["GET", "https://api.example.com/v1/posts", ["read"]],
    ["GET", "https://api.example.com/v1/settings", ["read"]],
    ["GET", "https://api.example.com/v1/addresses", ["read"]],
    ["GET", "https://api.example.com/v1/shipping", ["read"]],
    ["GET", "https://api.example.com/repos/alex/postgres-tools/issues", ["read"]],
    ["GET", "https://api.example.com/commits/a1dd5f", ["read"]],
    ["POST", "https://api.example.com/v1/tasks/7/delete", ["change", "delete"]],
    ["POST", "https://api.example.com/v1/delete/7", ["change", "delete"]],
    ["POST", "https://api.example.com/v1/tasks/7/archive", ["change", "delete"]],
    ["GET", "https://api.example.com/v1/setup", ["read"]],
    ["GET", "https://api.example.com/v1/reset", ["delete"]],
    ["GET", "https://api.example.com/v1/presets", ["read"]],
    ["GET", "https://api.example.com/api/v1/users/42/remove", ["delete"]],
    ["HEAD", "https://api.example.com/v1/stop", ["change"]],
    ["GET", "https://api.example.com/v1/stopped", ["read"]],
    ["GET", "https://api.example.com/v1/deleteAll", ["delete"]],
    ["GET", "https://api.example.com/v1/bulk-delete", ["delete"]],
    ["GET", "https://api.example.com/v1/DELETEMESSAGE", ["delete"]],
    ["POST", "https://api.example.com/v1/addressesdelete", ["change", "delete"]],
    ["POST", "https://api.example.com/v1/addressesDelete", ["change", "delete"]],
    ["POST", "https://api.example.com/v1/postgres-delete", ["change", "delete"]],
    ["POST", "https://api.example.com/v1/addresses.delete", ["change", "delete"]],
    ["POST", "https://api.example.com/v1/projects/delete/myproject", ["change"]],
    ["GET", "https://api.example.com/v1/delete2", ["delete"]],
    ["GET", "https://api.example.com/v1/v2delete", ["delete"]],
    ...["users/me", "search", "messages", "updates", "history", "events", "stream", "status", "ping", "health", "addresses", "settings/notifications", "presets/7", "posts/42/comments", "getMe", "getChat", "getFile", "conversations.history"].map((path) => ["GET", `https://api.example.com/v1/${path}`, ["read"]]),
    ["GET", "https://api.example.com/v1/archive/2024", ["delete"]],
  ] as [string, string, MandateClass[]][])("%s %s gives %p", (method, url, classes) => {
    expect(classesOf(held(null, method, url, method === "POST" ? { confirm: true } : null))).toEqual(classes)
  })

  // unban is an act word, and a listed prefix may come before a run that
  // starts with an act word and goes on past a spared rest.
  test.each([
    ["unbanChatUser", ["change"]],
    ["unbanchatuser", ["change"]],
    ["UNBANCHATUSER", ["change"]],
    ["bulkupdatemessages", ["change"]],
    ["BULKUPDATEMESSAGES", ["change"]],
    ["bulkupdates", ["change"]],
  ] as [string, MandateClass[]][])("GET /v1/%s gives %p", (segment, classes) => {
    expect(classesOf(held(null, "GET", `https://api.example.com/v1/${segment}`))).toEqual(classes)
  })

  // answer sends, and gift, upgrade, convert, export and save are acts; their
  // plurals and past tenses stay reads. export is also one of the floor's
  // generic words, so a path holding it is never.
  test.each([
    ["answerInlineQuery", ["send"]],
    ["answerWebAppQuery", ["send"]],
    ["answerPreCheckoutQuery", ["send"]],
    ["giftStars", ["change"]],
    ["upgradeGift", ["change"]],
    ["convertGiftToStars", ["change"]],
    ["savePreparedInlineMessage", ["change"]],
    ["answers", ["read"]],
    ["gifts", ["read"]],
    ["upgrades", ["read"]],
    ["converted", ["read"]],
    ["saved", ["read"]],
  ] as [string, MandateClass[]][])("GET /v1/%s gives %p", (segment, classes) => {
    expect(classesOf(held(null, "GET", `https://api.example.com/v1/${segment}`))).toEqual(classes)
  })

  // Slack's chat.meMessage and chat.postEphemeral send, and join, disable
  // and uninstall are acts, off its reviewed routes. invite is an act word
  // too, though the floor's generic words already make it never.
  test.each([
    ["chat.meMessage", ["send"]],
    ["chat.MEMESSAGE", ["send"]],
    ["chat.postEphemeral", ["change", "send"]],
    ["conversations.join", ["change"]],
    ["usergroups.disable", ["change"]],
    ["apps.uninstall", ["change"]],
    ["joined", ["read"]],
    ["disabled", ["read"]],
    ["uninstalls", ["read"]],
  ] as [string, MandateClass[]][])("GET https://slack.example.com/api/%s gives %p", (method, classes) => {
    expect(classesOf(held(null, "GET", `https://slack.example.com/api/${method}`))).toEqual(classes)
  })

  // prune and clear are delete words beside the floor's, and the words that
  // hold clear stay reads. GET /guilds/1/prune, which only counts, asks: an
  // accepted cost.
  test.each([
    ["POST", "guilds/1/prune", ["change", "delete"]],
    ["POST", "api/v1/notifications/clear", ["change", "delete"]],
    ["GET", "v1/cache/CLEAR", ["delete"]],
    ["GET", "guilds/1/prune", ["delete"]],
    ...["nuclear", "unclear", "clearance", "clearances", "cleared", "clears", "pruned"].map((segment) => ["GET", `v1/${segment}`, ["read"]]),
  ] as [string, string, MandateClass[]][])("%s /%s gives %p", (method, path, classes) => {
    expect(classesOf(held(null, method, `https://api.example.com/${path}`, method === "POST" ? { confirm: true } : null))).toEqual(classes)
  })

  // A run on the exact read list names no act, in any letter case, though a
  // camelCase word in it is one; runs that only start or end alike still do.
  test.each([
    ["getStickerSet", ["read"]],
    ["GETSTICKERSET", ["read"]],
    ["setStickerSetTitle", ["change"]],
    ["createNewStickerSet", ["change"]],
    ["deleteStickerSet", ["change", "delete"]],
    ["getStickerSetTitle", ["change"]],
  ] as [string, MandateClass[]][])("GET /v1/%s gives %p", (segment, classes) => {
    expect(classesOf(held(null, "GET", `https://api.example.com/v1/${segment}`))).toEqual(classes)
  })

  // scheduledmessages is on the stoplist as a whole run only.
  test.each([
    ["chat.scheduledMessages.list", ["read"]],
    ["chat.scheduledMessages", ["read"]],
    ["chat.scheduleMessage", ["change", "send"]],
    ["chat.deleteScheduledMessage", ["delete"]],
  ] as [string, MandateClass[]][])("GET https://slack.example.com/api/%s gives %p", (method, classes) => {
    expect(classesOf(held(null, "GET", `https://slack.example.com/api/${method}`))).toEqual(classes)
  })

  // On Telegram's Bot API a GET or HEAD reads only for a get method; any
  // other is an act on every HTTP method, and the send words add send.
  const TELEGRAM_GET_METHODS = ["getMe", "getUpdates", "getChat", "getFile", "getStickerSet", "getUserProfilePhotos", "getUserProfileAudios", "getChatAdministrators", "getForumTopicIconStickers", "getUserChatBoosts", "getBusinessConnection", "getMyCommands", "getMyName", "getMyDescription", "getMyShortDescription", "getChatMenuButton", "getMyDefaultAdministratorRights", "getAvailableGifts", "getCustomEmojiStickers", "getStarTransactions", "getGameHighScores", "getMyStarBalance", "getBusinessAccountGifts", "getBusinessAccountStarBalance", "getUserGifts", "getChatGifts"]
  const TELEGRAM_METHODS: [string, MandateClass[]][] = [
    ...TELEGRAM_GET_METHODS.map((method): [string, MandateClass[]] => [method, ["read"]]),
    ["setMyCommands", ["change"]],
    ["logOut", ["change"]],
    ["close", ["change"]],
    ["answerWebAppQuery", ["change", "send"]],
    ["sendMessage", ["change", "send"]],
    ["answerCallbackQuery", ["change", "send"]],
    ["postStory", ["change", "send"]],
    ["upgradeGift", ["change", "send"]],
    ["savePreparedInlineMessage", ["change", "send"]],
    ["setMessageReaction", ["change", "send"]],
    ["deleteMessage", ["change", "delete"]],
    ["getMe.json", ["change"]],
  ]
  test.each(TELEGRAM_METHODS.flatMap(([method, classes]) => [method, method.toLowerCase(), method.toUpperCase()].map((m): [string, MandateClass[]] => [m, classes])))("Telegram GET /bot.../%s gives %p", (method, classes) => {
    expect(classesOf(held(null, "GET", `https://api.telegram.org/bot123456:TEST/${method}`))).toEqual(classes)
  })

  test.each(["getChatMember", "getChatMemberCount", "getWebhookInfo"])("Telegram GET /bot.../%s is never through the floor's generic words alone, a cost the floor sets", (method) => {
    const request = held(null, "GET", `https://api.telegram.org/bot123456:TEST/${method}`)
    expect([...mandateRequestFacts(request)]).toEqual(["generic"])
    expect(classesOf(request)).toBe("never")
  })

  test.each(["unbanChatMember", "exportChatInviteLink"])("Telegram GET /bot.../%s is an act, and never already through the floor's generic words", (method) => {
    const facts = mandateRequestFacts(held(null, "GET", `https://api.telegram.org/bot123456:TEST/${method}`))
    expect(facts.has("act")).toBe(true)
    expect(facts.has("generic")).toBe(true)
  })

  test.each([
    ["answerCallbackQuery", ["change", "send"]],
    ["editMessageText", ["change", "send"]],
    ["stopPoll", ["change", "send"]],
    ["setMyCommands", ["change"]],
    ["getMe", ["change"]],
  ] as [string, MandateClass[]][])("Telegram POST /bot.../%s gives %p", (method, classes) => {
    expect(classesOf(held(null, "POST", `https://api.telegram.org/bot123456:TEST/${method}`, { chat_id: 1 }))).toEqual(classes)
  })

  test("a Telegram file download is a read, whatever its path names", () => {
    expect(classesOf(held(null, "GET", "https://api.telegram.org/file/bot123456:TEST/documents/file_1.pdf"))).toEqual(["read"])
    expect(classesOf(held(null, "GET", "https://api.telegram.org/file/bot123456:TEST/photos/deleteMessage.jpg"))).toEqual(["read"])
  })

  test("another host's /bot1/... path is read by the general rules", () => {
    expect(classesOf(held(null, "GET", "https://api.example.com/bot1/getMe"))).toEqual(["read"])
    expect(classesOf(held(null, "GET", "https://api.example.com/bot1/readBusinessMessage"))).toEqual(["read"])
    expect(classesOf(held(null, "GET", "https://api.telegram.org/bot1/readBusinessMessage"))).toEqual(["change"])
    expect(classesOf(held(null, "GET", "https://api.example.com/bot1/answerCallbackQuery"))).toEqual(["send"])
  })

  // On Slack's Web API a GET or HEAD reads only when the part after the last
  // dot starts with a read word, or the family is search; any other method
  // is an act on every HTTP method.
  test.each([
    ["conversations.history", ["read"]],
    ["users.info", ["read"]],
    ["chat.getPermalink", ["read"]],
    ["users.lookupByEmail", ["read"]],
    ["search.messages", ["read"]],
    ["search.all", ["read"]],
    ["conversations.replies", ["read"]],
    ["auth.test", ["read"]],
    ["users.profile.get", ["read"]],
    ["chat.scheduledMessages.list", ["read"]],
    ["conversations.join", ["change"]],
    ["usergroups.disable", ["change"]],
    ["apps.uninstall", ["change"]],
    ["users.profile.set", ["change"]],
    ["rtm.connect", ["change"]],
    ["chat.postMessage", ["change", "send"]],
    ["chat.meMessage", ["change", "send"]],
    ["CHAT.MEMESSAGE", ["change", "send"]],
  ] as [string, MandateClass[]][])("Slack GET /api/%s gives %p", (method, classes) => {
    expect(classesOf(held(null, "GET", `https://slack.com/api/${method}`))).toEqual(classes)
    expect(classesOf(held(null, "GET", `https://acme.slack.com/api/${method}`))).toEqual(classes)
  })

  test("Slack's chat.delete is never on slack.com, where the template's floor reads it as opaque, and a delete on a workspace host", () => {
    expect(classesOf(held(null, "GET", "https://slack.com/api/chat.delete"))).toBe("never")
    expect(classesOf(held(null, "GET", "https://acme.slack.com/api/chat.delete"))).toEqual(["change", "delete"])
  })

  // A Slack method that alters a message the conversation already sees,
  // or puts one in front of it, is a send on every host and method: the
  // template's floor covers slack.com alone, never a workspace subdomain.
  test.each([
    ["chat.update", ["change", "send"]],
    ["CHAT.UPDATE", ["change", "send"]],
    ["chat.unfurl", ["change", "send"]],
    ["chat.startStream", ["change", "send"]],
    ["chat.appendStream", ["change", "send"]],
    ["chat.stopStream", ["change", "send"]],
    ["files.upload", ["change", "send"]],
    ["files.completeUploadExternal", ["change", "send"]],
    ["reactions.add", ["change", "send"]],
    ["reactions.remove", ["change", "delete", "send"]],
    ["pins.add", ["change", "send"]],
    ["conversations.setTopic", ["change", "send"]],
    ["conversations.setPurpose", ["change", "send"]],
    ["chat.delete", ["change", "delete"]],
    ["chat.scheduleMessage", ["change", "send"]],
    ["chat.updateX", ["change"]],
    ["views.update", ["change"]],
    ["files.remote.update", ["change"]],
    ["bookmarks.edit", ["change"]],
    ["reactions.get", ["read"]],
  ] as [string, MandateClass[]][])("Slack %s on a workspace host gives %p, on a GET and a POST alike", (method, classes) => {
    expect(classesOf(held(null, "GET", `https://acme.slack.com/api/${method}`))).toEqual(classes)
    if (!classes.includes("read")) expect(classesOf(held(null, "POST", `https://acme.slack.com/api/${method}`, { channel: "C1", ts: "1", text: "hi" }))).toEqual(classes)
  })

  test("Slack's chat.update is a send on slack.com too, through the template and without it", () => {
    expect(classesOf(held(null, "GET", "https://slack.com/api/chat.update"))).toEqual(["change", "send"])
    expect(classesOf(held("slack-bot", "POST", "https://slack.com/api/chat.update", { channel: "C1", ts: "1", text: "hi" }))).toEqual(["change", "send"])
  })

  // Telegram's: an edit of a message is a send, a delete a delete, and a
  // pin, which tells the chat's members by default, a send.
  test.each([
    ["editMessageText", ["change", "send"]],
    ["editMessageCaption", ["change", "send"]],
    ["editMessageMedia", ["change", "send"]],
    ["editMessageReplyMarkup", ["change", "send"]],
    ["deleteMessage", ["change", "delete"]],
    ["deleteMessages", ["change", "delete"]],
    ["pinChatMessage", ["change", "send"]],
    ["unpinChatMessage", ["change"]],
  ] as [string, MandateClass[]][])("Telegram GET %s gives %p", (method, classes) => {
    expect(classesOf(held(null, "GET", `https://api.telegram.org/bot123456:TEST/${method}?chat_id=1&message_id=2`))).toEqual(classes)
  })

  test("Slack's send words add send on a POST too", () => {
    expect(classesOf(held(null, "POST", "https://acme.slack.com/api/chat.meMessage", { channel: "C1", text: "hi" }))).toEqual(["change", "send"])
    expect(classesOf(held(null, "POST", "https://acme.slack.com/api/chat.postEphemeral", { channel: "C1", text: "hi" }))).toEqual(["change", "send"])
    expect(classesOf(held(null, "POST", "https://acme.slack.com/api/usergroups.disable", { usergroup: "S1" }))).toEqual(["change"])
  })

  test("a HEAD that names an act is in its class too, and a GET that names none stays a read", () => {
    expect(classesOf(held(null, "HEAD", "https://api.example.com/v1/tasks/7/update"))).toEqual(["change"])
    expect(classesOf(held(null, "GET", "https://api.example.com/v1/tasks"))).toEqual(["read"])
    expect(classesOf(held(null, "GET", "https://api.example.com/v1/tasks/7"))).toEqual(["read"])
  })

  test("a POST whose path names no delete stays a change, and a reviewed route keeps its own class", () => {
    expect(classesOf(held(null, "POST", "https://api.example.com/v1/tasks", { task: "a" }))).toEqual(["change"])
    expect(classesOf(held("github-pat", "POST", "https://api.github.com/repos/alex/vault/issues/42/comments", { body: "Looks right." }))).toEqual(["change"])
  })

  test("a DELETE is destructive and still read for everything else it does", () => {
    expect([...mandateRequestFacts(held(null, "DELETE", "https://api.example.com/v1/settings/forwarding"))].sort()).toEqual(["destructive", "persistence"])
  })

  test("an item rule that asks makes a read a change", () => {
    const request = held(null, "GET", "https://api.example.com/v1/tasks", null, { policy: { default: "allow", rules: [{ action: "approve", methods: ["GET"], paths: ["/v1/tasks"] }] } })
    expect(classesOf(request)).toEqual(["change"])
  })

  test("a result that is not never always has a class", () => {
    for (const method of ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]) {
      const classes = mandateClassesOf(new Set(), method)
      expect(classes === "never" || classes.length > 0, method).toBe(true)
    }
    expect(mandateClassesOf(new Set(), "OPTIONS")).toBe("never")
  })
})

// Analytics Engine takes its SQL as the raw body, which the collector reads
// as a task grant or posture does (the entry's reader proved it), and the
// AI Gateway create names its own id, which is no GraphQL.
describe("Cloudflare's Analytics Engine SQL and AI Gateway create", () => {
  const A = "https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef"
  const sql = (url: string, body: unknown, contentType: string | null) => held("cloudflare-api-token", "POST", url, body, { contentType })

  test.each([null, "text/plain", "text/plain;charset=UTF-8", "application/x-www-form-urlencoded"])("SQL on the SQL path, typed %s, is a change", (contentType) => {
    const request = sql(`${A}/analytics_engine/sql`, "SELECT blob1, count() AS n FROM contoso_events GROUP BY blob1", contentType)
    expect([...mandateRequestFacts(request)]).toEqual([])
    expect(classesOf(request)).toEqual(["change"])
  })

  test.each([
    ["SQL text to the telemetry query", sql(`${A}/workers/observability/telemetry/query`, "SELECT 1", "text/plain"), "unreadable"],
    ["SQL text below the SQL path", sql(`${A}/analytics_engine/sql/extra`, "SELECT 1", null), "unreadable"],
    ["SQL text to a custom host", held(null, "POST", "https://api.example.com/analytics_engine/sql", "SELECT 1", { contentType: "text/plain" }), "unreadable"],
    ["two statements on the SQL path", sql(`${A}/analytics_engine/sql`, "SELECT 1; SELECT 2", null), "unreadable"],
    ["an untyped JSON body on the SQL path", sql(`${A}/analytics_engine/sql`, { sql: "SELECT 1" }, null), "unreadable"],
    ["a JSON query the GraphQL check cannot prove on the SQL path", sql(`${A}/analytics_engine/sql`, { query: "SELECT 1" }, "application/json"), "unreadable"],
  ] as [string, PolicyRuleAnchor, string][])("%s is never, as before", (_, request, fact) => {
    expect(mandateRequestFacts(request).has(fact as never)).toBe(true)
    expect(classesOf(request)).toBe("never")
  })

  test("another JSON body on the SQL path is a change, as before", () => {
    expect(classesOf(sql(`${A}/analytics_engine/sql`, { sql: "SELECT 1" }, "application/json"))).toEqual(["change"])
  })

  test("the AI Gateway create, naming its own id, is a change", () => {
    const request = held("cloudflare-api-token", "POST", `${A}/ai-gateway/gateways`, { id: "contoso", collect_logs: false, cache_ttl: 0, cache_invalidate_on_update: false, rate_limiting_interval: 0, rate_limiting_limit: 0, rate_limiting_technique: "fixed" })
    expect([...mandateRequestFacts(request)]).toEqual([])
    expect(classesOf(request)).toEqual(["change"])
  })
})

// The standing rules' floor test is not the collector: its early return on
// a DELETE and its methods stay as they were.
describe("the floor test the standing rules share is unchanged", () => {
  test("a DELETE still refuses as destructive and a method no rule takes as rule.method", () => {
    expect(policyFloorRefusal(held(null, "DELETE", "https://api.example.com/v1/settings/forwarding"))).toBe("rule.destructive")
    expect(policyFloorRefusal(held(null, "OPTIONS", "https://api.example.com/v1/tasks"))).toBe("rule.method")
    expect(POLICY_RULE_METHODS).toEqual(["GET", "HEAD", "POST", "PUT", "PATCH"])
  })

  test("a request the collector reads as a change still passes it", () => {
    expect(policyFloorRefusal(held("github-pat", "POST", "https://api.github.com/repos/alex/vault/issues/42/comments", { body: "x" }))).toBeNull()
    expect(policyFloorRefusal(held(null, "GET", "https://api.telegram.org/bot123456:TEST/sendMessage?chat_id=1&text=hi"))).toBe("rule.send")
  })
})

describe("mandateHostNamed", () => {
  test("only a host the binding names exactly, never one a wildcard admits", () => {
    const binding: Binding = { hosts: ["api.example.com", "*.example.com"] }
    expect(mandateHostNamed(binding, "api.example.com")).toBe(true)
    expect(mandateHostNamed(binding, "attacker.example.com")).toBe(false)
    expect(mandateHostNamed({ hosts: ["*.example.com"] }, "api.example.com")).toBe(false)
  })
})

describe("mandateHeadersNameOperation", () => {
  test("a header that names the operation, in any case, never one that does not", () => {
    for (const name of ["X-Amz-Target", "x-amz-target", "SOAPAction", "X-Goog-Upload-Method"]) expect(mandateHeadersNameOperation(["content-type", name]), name).toBe(true)
    expect(mandateHeadersNameOperation(["content-type", "x-amz-date", "x-goog-api-client", "accept"])).toBe(false)
  })
})

describe("mandateCredentialNever", () => {
  test("a live key, or a binding with no host named exactly, is one no mandate covers", () => {
    expect(mandateCredentialNever({ hosts: ["api.stripe.com"] }, ["sk_live_"])).toBe("live-key")
    expect(mandateCredentialNever({ hosts: ["api.stripe.com"] }, ["rk_live_"])).toBe("live-key")
    expect(mandateCredentialNever({ hosts: ["*.example.com"] }, [])).toBe("wildcard-host")
    expect(mandateCredentialNever({ hosts: ["*.example.com", "api.example.com"] }, [])).toBeNull()
    expect(mandateCredentialNever({ hosts: ["api.stripe.com"] }, ["sk_test_"])).toBeNull()
  })
})

const at = (iso: string): number => Date.parse(iso)
const terms = (overrides: Partial<MandateTerms> = {}): MandateTerms => ({
  device: "dev_alexmbp", items: "all", classes: ["change", "delete", "read", "send"], caps: { ...MANDATE_CAP_DEFAULTS }, ttlDays: 30, schedule: null, note: "Sam's own work", ...overrides,
})
const active = { state: "active" as const, expiresAt: at("2026-12-08T12:00:00Z") }

describe("mandateCovers", () => {
  const now = at("2026-11-08T12:00:00Z")

  test("an active, unexpired mandate covers the classes it ticks, and no other", () => {
    expect(mandateCovers(terms(), active, ["change", "send"], now)).toBe(true)
    expect(mandateCovers(terms({ classes: ["change", "read"], caps: { ...MANDATE_CAP_DEFAULTS, send: 0, delete: 0 } }), active, ["change", "send"], now)).toBe(false)
    expect(mandateCovers(terms(), active, [], now)).toBe(false)
  })

  test.each(["paused", "tripped", "stopped", "expired"] as const)("a %s mandate covers nothing", (state) => {
    expect(mandateCovers(terms(), { ...active, state }, ["read"], now)).toBe(false)
  })

  test("a mandate covers nothing from its expiry on", () => {
    expect(mandateCovers(terms(), active, ["read"], active.expiresAt - 1)).toBe(true)
    expect(mandateCovers(terms(), active, ["read"], active.expiresAt)).toBe(false)
  })

  test("outside its schedule, nothing", () => {
    const schedule: MandateSchedule = { tz: "Europe/London", windows: [{ days: [1, 2, 3, 4, 5], from: "09:00", to: "17:00" }] }
    expect(mandateCovers(terms({ schedule }), active, ["read"], at("2026-11-09T10:00:00Z"))).toBe(true)
    expect(mandateCovers(terms({ schedule }), active, ["read"], at("2026-11-08T10:00:00Z"))).toBe(false)
  })
})

describe("mandateScheduleOpen", () => {
  test("no schedule is always", () => {
    expect(mandateScheduleOpen(null, at("2026-11-08T03:00:00Z"))).toBe(true)
  })

  test("a window starts inclusive and ends exclusive", () => {
    const schedule: MandateSchedule = { tz: "UTC", windows: [{ days: [1], from: "09:00", to: "17:00" }] }
    expect(mandateScheduleOpen(schedule, at("2026-11-09T08:59:59Z"))).toBe(false)
    expect(mandateScheduleOpen(schedule, at("2026-11-09T09:00:00Z"))).toBe(true)
    expect(mandateScheduleOpen(schedule, at("2026-11-09T16:59:59Z"))).toBe(true)
    expect(mandateScheduleOpen(schedule, at("2026-11-09T17:00:00Z"))).toBe(false)
  })

  test("a window crossing midnight counts on the day it started", () => {
    // Friday 6 November 2026, 22:00, to Saturday 02:00.
    const schedule: MandateSchedule = { tz: "UTC", windows: [{ days: [5], from: "22:00", to: "02:00" }] }
    expect(mandateScheduleOpen(schedule, at("2026-11-06T22:00:00Z"))).toBe(true)
    expect(mandateScheduleOpen(schedule, at("2026-11-07T01:59:00Z"))).toBe(true)
    expect(mandateScheduleOpen(schedule, at("2026-11-07T02:00:00Z"))).toBe(false)
    expect(mandateScheduleOpen(schedule, at("2026-11-07T22:30:00Z"))).toBe(false)
    expect(mandateScheduleOpen(schedule, at("2026-11-06T01:00:00Z"))).toBe(false)
    expect(mandateScheduleOpen({ tz: "UTC", windows: [{ days: [6], from: "22:00", to: "02:00" }] }, at("2026-11-08T01:00:00Z"))).toBe(true)
  })

  test("the same moment reads as each zone's own wall clock", () => {
    const window = { days: [1], from: "09:00", to: "17:00" }
    const moment = at("2026-11-09T15:00:00Z")
    expect(mandateScheduleOpen({ tz: "Europe/London", windows: [window] }, moment)).toBe(true)
    expect(mandateScheduleOpen({ tz: "America/New_York", windows: [window] }, moment)).toBe(true)
    expect(mandateScheduleOpen({ tz: "Asia/Tokyo", windows: [window] }, moment)).toBe(false)
    expect(mandateScheduleOpen({ tz: "America/New_York", windows: [window] }, at("2026-11-09T13:59:00Z"))).toBe(false)
  })

  test("in Europe/Paris, a local time the spring change skips never occurs", () => {
    // Sunday 29 March 2026: 02:00 CET becomes 03:00 CEST at 01:00 UTC.
    const skipped: MandateSchedule = { tz: "Europe/Paris", windows: [{ days: [0], from: "02:00", to: "03:00" }] }
    for (const iso of ["2026-03-29T00:30:00Z", "2026-03-29T00:59:59Z", "2026-03-29T01:00:00Z", "2026-03-29T01:30:00Z"]) expect(mandateScheduleOpen(skipped, at(iso)), iso).toBe(false)
    const straddling: MandateSchedule = { tz: "Europe/Paris", windows: [{ days: [0], from: "01:30", to: "03:30" }] }
    expect(mandateScheduleOpen(straddling, at("2026-03-29T00:45:00Z"))).toBe(true)
    expect(mandateScheduleOpen(straddling, at("2026-03-29T01:15:00Z"))).toBe(true)
    expect(mandateScheduleOpen(straddling, at("2026-03-29T01:30:00Z"))).toBe(false)
  })

  test("in Europe/Paris, an hour the autumn change repeats is inside or outside both times", () => {
    // Sunday 25 October 2026: 03:00 CEST becomes 02:00 CET at 01:00 UTC, so
    // 02:30 local is both 00:30 and 01:30 UTC.
    const inside: MandateSchedule = { tz: "Europe/Paris", windows: [{ days: [0], from: "02:00", to: "03:00" }] }
    expect(mandateScheduleOpen(inside, at("2026-10-25T00:30:00Z"))).toBe(true)
    expect(mandateScheduleOpen(inside, at("2026-10-25T01:30:00Z"))).toBe(true)
    const outside: MandateSchedule = { tz: "Europe/Paris", windows: [{ days: [0], from: "03:00", to: "04:00" }] }
    expect(mandateScheduleOpen(outside, at("2026-10-25T00:30:00Z"))).toBe(false)
    expect(mandateScheduleOpen(outside, at("2026-10-25T01:30:00Z"))).toBe(false)
    expect(mandateScheduleOpen(outside, at("2026-10-25T02:00:00Z"))).toBe(true)
  })
})

describe("mandate terms", () => {
  test("take only what a person could sign", () => {
    expect(MandateTermsSchema.safeParse(terms()).success).toBe(true)
    expect(MandateTermsSchema.safeParse(terms({ items: ["itm_b0000001", "itm_a0000001"] })).success).toBe(false)
    expect(MandateTermsSchema.safeParse(terms({ classes: ["change", "send"] })).success).toBe(false)
    expect(MandateTermsSchema.safeParse(terms({ caps: { ...MANDATE_CAP_DEFAULTS, send: 501 } })).success).toBe(false)
    expect(MandateTermsSchema.safeParse(terms({ classes: ["read"], caps: MANDATE_CAP_DEFAULTS })).success).toBe(false)
    expect(MandateTermsSchema.safeParse(terms({ ttlDays: 60 as 30 })).success).toBe(false)
    expect(MandateTermsSchema.safeParse(terms({ note: "" })).success).toBe(false)
    expect(MandateTermsSchema.safeParse(terms({ schedule: { tz: "Mars/Olympus", windows: [{ days: [1], from: "09:00", to: "17:00" }] } })).success).toBe(false)
    expect(MandateTermsSchema.safeParse(terms({ schedule: { tz: "UTC", windows: [{ days: [1], from: "09:00", to: "09:00" }] } })).success).toBe(false)
    expect(MandateTermsSchema.safeParse(terms({ schedule: { tz: "UTC", windows: [{ days: [1], from: "24:00", to: "09:00" }] } })).success).toBe(false)
  })

  test("a ticked class's cap is between 1 and its most, an unticked one's 0", () => {
    expect(mandateCapsFit(["read"], { read: 1, change: 0, send: 0, delete: 0 })).toBe(true)
    expect(mandateCapsFit(["read"], { read: 0, change: 0, send: 0, delete: 0 })).toBe(false)
    expect(mandateCapsFit(["delete", "read"], { read: 50_000, change: 0, send: 0, delete: 200 })).toBe(true)
  })

  test("a machine proposes terms without a device, naming credentials by slug", () => {
    const { device: _device, ...rest } = terms()
    expect(MandateProposedTermsSchema.safeParse({ ...rest, items: ["github-work", "slack-bot"] }).success).toBe(true)
    expect(MandateProposedTermsSchema.safeParse({ ...rest, device: "dev_alexmbp" }).success).toBe(false)
  })

  test("the digest binds the terms, the workspace and the signer", async () => {
    const base = { terms: terms(), workspace: "tn_Ex7mR4pLq9WzTnVc2Hdyk", signer: "mem_alex" }
    const digest = await mandateDigest(base)
    expect(digest).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(await mandateDigest(base)).toBe(digest)
    for (const changed of [{ ...base, terms: terms({ ttlDays: 7 }) }, { ...base, workspace: "tn_Nw4dQ2m8xPLsJyKb3Rtvz" }, { ...base, signer: "mem_kim" }]) expect(await mandateDigest(changed)).not.toBe(digest)
  })

  test("a receipts cursor reads back as the time and id it was made from", () => {
    expect(parseMandateReceiptsCursor(mandateReceiptsCursor(1_762_000_000_000, "mdu_abc123"))).toEqual({ at: 1_762_000_000_000, id: "mdu_abc123" })
    expect(parseMandateReceiptsCursor("1.mdt_abc")).toBeNull()
  })
})

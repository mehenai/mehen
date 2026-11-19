// The credential and machine pages with standing rules (routes/ui-projects.ts,
// routes/ui-people.ts, ui/policy-rules-list.ts): with POLICY_RULES off
// each page is byte for byte what it was before rules, rules or none; with
// it on and a rule made through the approval page's own routes, both pages
// list it and the compact line links between them, and switching it off
// again takes away exactly the card and the line.
import { env } from "cloudflare:workers"
import { runInDurableObject } from "cloudflare:test"
import { afterEach, expect, it, vi } from "vitest"
import type { WorkspaceRef, WorkspaceStepUpAction } from "@mehen/protocol"
import type { PolicyRuleOffer, PolicyRuleView } from "@mehen/protocol/policy-mode"
import { policyRuleTermsDigest } from "@mehen/protocol/policy-rules"
import { loadPolicyRules } from "../../src/ui/load.ts"
import { ruleTermsOf } from "../../src/ui/policy-rules-row.ts"
import type { RequestContext, WorkspaceRequest } from "../../src/routes/context.ts"
import { body, workJourney, type Machine } from "./workspace-journey.ts"

const WS = "northwind"
type Journey = Awaited<ReturnType<typeof workJourney>>

// POLICY_RULES for the Worker's routes and the workspace's vault alike.
async function switchRules(f: Journey, value: string) {
  f.env.POLICY_RULES = value
  await runInDurableObject(env.TENANT_VAULT.getByName(f.work.id), (instance) => { instance.context.env = { ...instance.context.env, POLICY_RULES: value } })
}

async function html(f: Journey, path: string): Promise<string> {
  const response = await f.request(path, f.alex, undefined, { accept: "text/html" })
  expect(response.status, path).toBe(200)
  return response.text()
}

// A request the credential's policy holds, approved with "allow this from
// now on" at the offer's own path and duration, as the approval page signs it.
async function rememberedRule(f: Journey, machine: Machine): Promise<PolicyRuleView> {
  const asked = await f.deviceCall(machine, "/v1/relay", { item: "openai-dev", method: "POST", url: "https://api.openai.com/v1/assistants", headers: [] })
  const { approval } = await body<{ approval: string }>(asked, 409)
  const view = await body<{ view: string; approval: { rememberOptions?: { rule?: PolicyRuleOffer } } }>(await f.request(`/api/w/${WS}/approvals/${approval}`, f.alex))
  const offer = view.approval.rememberOptions?.rule
  if (!offer?.terms) throw new Error(`No rule offered: ${offer?.refused}`)
  const input = { decision: "approve", remember: { kind: "rule", path: offer.terms.path, ttlSeconds: offer.terms.ttlSeconds, termsDigest: offer.termsDigest } }
  const action = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/approvals/${approval}/action`, f.alex, input))
  await body(await f.signed(`/api/w/${WS}/approvals/${approval}/decide`, f.alex, input, action, WS))
  const rules = await body<PolicyRuleView[]>(await f.request(`/api/w/${WS}/policy/rules?item=openai-dev`, f.alex))
  expect(rules).toHaveLength(1)
  return rules[0]!
}

// Workspaces a test drove with its clock faked into the past.
const pastClockWorkspaces: WorkspaceRef[] = []

// With Date faked into the real past, every run of the workspace's alarm
// finds nothing due by the test's clock and re-arms it in the past, so
// workerd fires it again at once; once the clock is real it delivers the
// queued notices after the test has ended, logging while vitest closes the
// worker. Runs what is due by the test's clock, then empties the schedule
// before deleting the alarm: a run workerd has already dispatched still
// arrives after the delete, and must find nothing to do or re-arm.
async function quietWorkspace(workspace: WorkspaceRef): Promise<void> {
  const stub = env.TENANT_VAULT.getByName(workspace.id)
  await runInDurableObject(stub, async (instance, state) => {
    await instance.alarm()
    instance.context.sql.exec("DELETE FROM schedule")
    await state.storage.deleteAlarm()
  })
}

afterEach(async () => {
  try {
    for (const workspace of pastClockWorkspaces.splice(0)) await quietWorkspace(workspace)
  } finally {
    vi.useRealTimers()
  }
})

it("with POLICY_RULES off the credential and machine pages are what they were, rules or none; on, both list the rule and link to each other", async () => {
  // One clock for the whole journey, so the machine page's "Last seen"
  // reads the same in every capture compared.
  vi.useFakeTimers({ toFake: ["Date"], now: Date.parse("2026-10-27T18:30:00Z") })
  const f = await workJourney()
  pastClockWorkspaces.push(f.work)
  await f.credential(f.alex, f.work, "openai-dev", { kind: "workspace" })
  const machine = await f.machine(f.alex, f.work)
  const itemPage = `/w/${WS}/items/openai-dev`, machinePage = `/w/${WS}/devices/${machine.device}`
  const before = { item: await html(f, itemPage), machine: await html(f, machinePage) }
  for (const page of Object.values(before)) {
    expect(page).not.toContain('data-region="policy-rules"')
    expect(page).not.toContain('data-region="policy-rules-line"')
  }
  // On, with no rule yet: nothing to show, so nothing changes but the
  // link to My rules.
  await switchRules(f, "on")
  const empty = { item: await html(f, itemPage), machine: await html(f, machinePage) }
  for (const page of Object.values(empty)) expect(page).toContain(`<a href="/w/${WS}/rules"><span>My rules</span></a>`)
  expect({ item: withoutMyRulesLink(empty.item), machine: withoutMyRulesLink(empty.machine) }).toEqual(before)

  const rule = await rememberedRule(f, machine)
  const item = await html(f, itemPage)
  expect(item).toContain(`data-rule="${rule.id}" data-rule-state="active" data-rule-own`)
  expect(item).toContain("<code>POST api.openai.com/v1/assistants</code>")
  expect(item).toContain("<dt>Who</dt><dd>integration-machine</dd>")
  expect(item).toContain("<dt>Context</dt><dd>outside any project</dd>")
  expect(item).toContain(`data-action="rule-extend" data-rule="${rule.id}"`)
  expect(item).toContain(`<a href="/w/${WS}/devices/${machine.device}" data-region="policy-rules-count">1 request allowed without asking</a>`)
  const onMachine = await html(f, machinePage)
  expect(onMachine).toContain(`data-rule="${rule.id}" data-rule-state="active" data-rule-own`)
  expect(onMachine).toContain(`<a href="/w/${WS}/items/openai-dev"><code>openai-dev</code></a>`)
  expect(onMachine).toContain(`<a href="/w/${WS}/items/openai-dev" data-region="policy-rules-count">1 request allowed without asking</a>`)

  // Off again, with the rule still standing: no read, no card, no line,
  // and nothing else differs.
  await switchRules(f, "off")
  const off = { item: await html(f, itemPage), machine: await html(f, machinePage) }
  for (const page of Object.values(off)) expect(page).not.toContain("allowed without asking")
  // How careful opens on Custom only while a live rule applies; with rules
  // off it reads as it did before the rule, on Ask.
  expect(howCareful(item)).toContain('value="custom" checked')
  expect(howCareful(off.item)).toEqual(howCareful(before.item))
  expect(howCareful(off.item)).toContain('value="ask" checked')
  expect({ ...off, item: withoutHowCareful(off.item) }).toEqual({ item: withoutHowCareful(withoutMyRulesLink(withoutRules(item))), machine: withoutMyRulesLink(withoutRules(onMachine)) })
  // A list of workspace ids: one that leaves this workspace out is "off"
  // here byte for byte; one that names it is "on".
  await switchRules(f, "tn_elsewhere0001,tn_elsewhere0002")
  expect({ item: await html(f, itemPage), machine: await html(f, machinePage) }).toEqual(off)
  await switchRules(f, `tn_elsewhere0001, ${f.work.id}`)
  expect({ item: await html(f, itemPage), machine: await html(f, machinePage) }).toEqual({ item, machine: onMachine })
}, 120_000)

it("My rules lists the person's live rule with Stop and Extend while POLICY_RULES is on, says there is none before it, and is not found with it off", async () => {
  vi.useFakeTimers({ toFake: ["Date"], now: Date.parse("2026-10-27T18:30:00Z") })
  const f = await workJourney()
  pastClockWorkspaces.push(f.work)
  await f.credential(f.alex, f.work, "openai-dev", { kind: "workspace" })
  const machine = await f.machine(f.alex, f.work)
  const notFound = async () => (await f.request(`/w/${WS}/no-such-page`, f.alex, undefined, { accept: "text/html" })).text()
  const mine = () => f.request(`/w/${WS}/rules`, f.alex, undefined, { accept: "text/html" })
  expect(await (await mine()).text()).toBe(await notFound())
  await switchRules(f, "on")
  const empty = await html(f, `/w/${WS}/rules`)
  expect(empty).toContain("<h1>My rules</h1>")
  expect(empty).toContain("<b>No rules</b>")
  expect(empty).toContain(`<a href="/w/${WS}/rules" aria-current="page"><span>My rules</span></a>`)
  const rule = await rememberedRule(f, machine)
  expect(await body<PolicyRuleView[]>(await f.request(`/api/w/${WS}/policy/rules`, f.alex))).toEqual([rule])
  const listed = await html(f, `/w/${WS}/rules`)
  expect(listed).toContain(`data-rule="${rule.id}" data-rule-state="active" data-rule-own`)
  expect(listed).toContain("<code>POST api.openai.com/v1/assistants</code>")
  expect(listed).toContain("<dt>Who</dt><dd>integration-machine</dd>")
  expect(listed).toContain(`<a href="/w/${WS}/items/openai-dev"><code>openai-dev</code></a>`)
  expect(listed).toContain(`data-action="rule-stop" data-rule="${rule.id}"`)
  expect(listed).toContain(`data-action="rule-extend" data-rule="${rule.id}"`)
  expect(listed).toContain("&quot;page&quot;:&quot;ws-my-rules&quot;")
  // Stopped through the card's own route, it leaves the list.
  await body(await f.request(`/api/w/${WS}/policy/rules/${rule.id}/revoke`, f.alex, {}))
  expect(await html(f, `/w/${WS}/rules`)).toContain("<b>No rules</b>")
  await switchRules(f, "off")
  expect(await (await mine()).text()).toBe(await notFound())
}, 120_000)

it("the vault's extend action is over the digest of the terms the rule's row shows, before an extension and after it", async () => {
  vi.useFakeTimers({ toFake: ["Date"], now: Date.parse("2026-10-27T18:30:00Z") })
  const f = await workJourney()
  pastClockWorkspaces.push(f.work)
  await f.credential(f.alex, f.work, "openai-dev", { kind: "workspace" })
  await switchRules(f, "on")
  const rule = await rememberedRule(f, await f.machine(f.alex, f.work))
  const base = `/api/w/${WS}/policy/rules/${rule.id}/extend`
  const first = await body<WorkspaceStepUpAction & { digest: string }>(await f.request(`${base}/action`, f.alex, { ttlSeconds: 86_400 }))
  expect(first.digest).toBe(await policyRuleTermsDigest(ruleTermsOf(rule)))
  await body(await f.signed(`${base}/decide`, f.alex, { ttlSeconds: 86_400 }, first, WS))
  const [extended] = await body<PolicyRuleView[]>(await f.request(`/api/w/${WS}/policy/rules?item=openai-dev`, f.alex))
  expect(extended!.ttlSeconds).toBe(86_400)
  const next = await body<{ digest: string }>(await f.request(`${base}/action`, f.alex, { ttlSeconds: 604_800 }))
  expect(next.digest).toBe(await policyRuleTermsDigest(ruleTermsOf(extended!)))
  expect(next.digest).not.toBe(first.digest)
}, 120_000)

it("an area remember for a service nobody reviewed is refused on the approval's action route, and an area effective on a rule proposal's action route", async () => {
  const f = await workJourney()
  await f.credential(f.alex, f.work, "openai-dev", { kind: "workspace" })
  const machine = await f.machine(f.alex, f.work)
  await switchRules(f, "on")
  const asked = await f.deviceCall(machine, "/v1/relay", { item: "openai-dev", method: "POST", url: "https://api.openai.com/v1/assistants", headers: [] })
  const { approval } = await body<{ approval: string }>(asked, 409)
  const answer = async (response: Response) => ({ status: response.status, body: await response.json() })
  const remember = { kind: "area", areas: ["issues"], ttlSeconds: 3600, maxUses: 50, termsDigest: "A".repeat(43) }
  expect(await answer(await f.request(`/api/w/${WS}/approvals/${approval}/action`, f.alex, { decision: "approve", remember }))).toEqual({ status: 403, body: { error: "forbidden", message: "Nobody has reviewed this service's routes, so this request cannot start a task grant.", areaRefused: "area.unreviewed" } })
  const { proposal } = await body<{ proposal: string }>(await f.deviceCall(machine, "/v1/policy/proposals", { from: { approval }, reason: "Make assistants" }), 201)
  expect(await answer(await f.request(`/api/w/${WS}/policy/proposals/${proposal}/action`, f.alex, { decision: "approve", effective: { areas: ["issues"], ttlSeconds: 3600, maxUses: 50 } }))).toEqual({ status: 400, body: expect.objectContaining({ error: "bad_request", message: "Approve names the path and duration; deny names neither." }) })
  // A task grant's proposal from a mehen that names no version reads as a
  // rule proposal with a key too many, as before task grants.
  const area = { from: { approval }, area: { item: "openai-dev", areas: ["issues"] }, reason: "Make assistants" }
  expect(await answer(await f.deviceCall(machine, "/v1/policy/proposals", area))).toEqual({ status: 400, body: { error: "bad_request", message: "Invalid request: body Unrecognized key: \"area\".", next: { command: "mehen policy propose --help", say: "Read the policy proposal options and try again." } } })
}, 120_000)

it("loadPolicyRules makes no read with POLICY_RULES off for the workspace: it touches nothing but the switch and the workspace's id", async () => {
  const untouchable = (name: string) => new Proxy({}, { get: (_, key) => { throw new Error(`read ${name}.${String(key)}`) } })
  const workspace = new Proxy({ workspace: { id: "tn_listed0000001" } }, { get: (target, key) => { if (key === "workspace") return target.workspace; throw new Error(`read workspace.${String(key)}`) } }) as unknown as WorkspaceRequest
  for (const value of [undefined, "off", "yes", "tn_elsewhere0001", "on,tn_listed0000001"]) {
    const rc = { env: { POLICY_RULES: value }, request: untouchable("request"), ctx: untouchable("ctx"), url: untouchable("url"), params: {} } as unknown as RequestContext
    for (const of of [{ item: "openai-dev" }, { device: "dev_x" }]) expect(await loadPolicyRules(rc, workspace, of)).toBeNull()
  }
})

// A page with My rules cut out of its rail, top bar, More sheet and boot.
function withoutMyRulesLink(page: string): string {
  const cut = page.replace(new RegExp(`<li><a href="/w/${WS}/rules">.*?</a></li>`, "g"), "").replace(new RegExp(`<a href="/w/${WS}/rules">.*?</a>`, "g"), "").replace(",&quot;rules&quot;", "")
  expect(cut).not.toContain("/rules\"")
  return cut
}

// The How careful card, from its section to the one that closes it.
function howCarefulAt(page: string): { start: number; end: number } {
  const start = page.indexOf('<section class="card" id="how-careful"')
  expect(start, "how-careful").toBeGreaterThan(-1)
  const tags = /<section\b|<\/section>/g
  tags.lastIndex = start
  for (let depth = 0, tag = tags.exec(page); tag !== null; tag = tags.exec(page)) {
    depth += tag[0] === "</section>" ? -1 : 1
    if (depth === 0) return { start, end: tag.index + tag[0].length }
  }
  throw new Error("the How careful card does not close")
}
const howCareful = (page: string) => { const at = howCarefulAt(page); return page.slice(at.start, at.end) }
const withoutHowCareful = (page: string) => { const at = howCarefulAt(page); return page.slice(0, at.start) + page.slice(at.end) }

// A page with its rules card and compact line cut out, exactly.
function withoutRules(page: string): string {
  const cut = (text: string, start: string) => {
    const at = text.indexOf(start)
    expect(at, start).toBeGreaterThan(-1)
    return text.slice(0, at) + text.slice(text.indexOf("</section>", at) + "</section>".length)
  }
  return cut(cut(page, '<section class="notice warn attention" data-region="policy-rules-line"'), '<section class="card" id="policy-rules"')
}

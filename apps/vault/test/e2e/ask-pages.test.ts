// The ask pages through the real Worker: what each viewer's
// page carries, from the vault's own answers. A four-eyes run for the
// machine's owner offers Decline only; a warned run approval leads with the
// warning card, Decline filled and Approve quiet; a stale run approval
// says it changed and offers no form and no bar; a machine's rule proposal
// renders its own page at /w/<slug>/p/<id>, whose decision, as its browser
// code signs it, makes the rule.
import { expect, it } from "vitest"
import { env } from "cloudflare:workers"
import { runInDurableObject } from "cloudflare:test"
import { CHANGED_SINCE_REQUESTED, FOUR_EYES_TITLE } from "../../src/ui/wording.ts"
import { type RuleProposalBoot, environmentChange, ruleProposalDecision, ruleProposalEffect, ruleProposalMatches, ruleProposalOutcomeWords, variableChange } from "../../src/ui/client/workspace-logic.ts"
import type { WorkspaceStepUpAction } from "@mehen/protocol"
import { body } from "./workspace-journey.ts"
import { WS, addCredential, page, projectSigned, setup } from "./ui-projects-journey.ts"

type Journey = Awaited<ReturnType<typeof setup>>

// A protected run on a machine Alex owns, using a workspace credential.
async function askedRun(f: Journey, argv: string[] = ["node", "deploy.js"]) {
  await addCredential(f, f.alex, f.work, "prod-key", { kind: "workspace" })
  await body(await projectSigned(f, f.alex, f.work, variableChange(f.platform.id, "prod", "TOKEN", null, { kind: "item", item: "prod-key", field: "key" })))
  const machine = await f.protectedMachine(f.alex, f.work)
  const approval = (await body<{ approval: string }>(await f.deviceCall(machine, "/v1/runs", { project: f.platform.id, env: "prod", envSource: "flag", remote: null, worktree: "/ask-pages", head: null, vars: ["TOKEN"], command: argv.join(" "), argv }), 409)).approval
  return { approval, machine }
}

function main(text: string): string {
  return text.slice(text.indexOf("<main"), text.indexOf("</main>")).replace(/data-boot="[^"]*"/, "")
}

function button(text: string, action: string): string {
  return new RegExp(`<button[^>]*data-action="${action}"[^>]*>`).exec(text)?.[0] ?? ""
}

it("a four-eyes run for the machine's owner: the request in full, Decline only, the second person named", async () => {
  const f = await setup()
  await body(await projectSigned(f, f.alex, f.work, environmentChange(f.platform.id, "prod", { protected: true, fences: [], fourEyes: false }, { protected: true, fences: [], fourEyes: true })))
  const { approval } = await askedRun(f)
  const shown = await page(f, `/w/${WS}/a/${approval}`, f.alex)
  expect(shown.status).toBe(200)
  const text = main(shown.text)
  expect(text).toContain('data-region="four-eyes"')
  expect(text).toContain(FOUR_EYES_TITLE)
  expect(text).toContain('data-region="cannot-approve"')
  expect(text).toContain('data-region="exact-request"')
  expect(button(text, "deny")).toContain('form="decide"')
  expect(text).not.toContain('data-action="approve"')
  expect(shown.text).toContain('<body class="focus has-bar"')
})

it("a warned run approval: the warning card before the decision card, Decline filled, Approve quiet and off, the marker shown", async () => {
  const f = await setup()
  const { approval } = await askedRun(f, ["node", "deploy\u202E.js"])
  const text = main((await page(f, `/w/${WS}/a/${approval}`, f.alex)).text)
  expect(text).toContain('data-region="warnings"')
  expect(text.indexOf('data-region="warnings"')).toBeLessThan(text.indexOf('data-region="decision"'))
  expect(text).toContain("[RLO U+202E]")
  expect(text).not.toContain("\u202E")
  expect(button(text, "deny")).toContain('class="btn danger"')
  expect(button(text, "approve")).toContain('class="btn quiet"')
  expect(button(text, "approve")).toContain("disabled")
})

it("a stale run approval says it changed and offers no form and no bar", async () => {
  const f = await setup()
  const { approval } = await askedRun(f)
  const change = { ceiling: "lease" }
  const action = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/items/prod-key/action`, f.alex, { action: "update", change }))
  await body(await f.signed(`/api/w/${WS}/items/prod-key/update`, f.alex, change, action, WS))
  const shown = await page(f, `/w/${WS}/a/${approval}`, f.alex)
  expect(shown.status).toBe(200)
  expect(shown.text).toContain('data-region="changed-since-requested"')
  expect(shown.text).toContain(CHANGED_SINCE_REQUESTED)
  expect(shown.text).not.toContain('data-form="decide"')
  expect(shown.text).not.toContain('data-region="bar"')
  expect(shown.text).not.toContain('data-action="approve"')
})

// No route stores a widening proposal, so /p/ names only rule proposals: any
// other id is not found, for a member and for a guest alike.
it("the policy page for a proposal the vault does not hold is not found", async () => {
  const f = await setup()
  const sam = await f.guest(f.alex, f.work, f.platform.id, "Sam")
  expect((await page(f, `/w/${WS}/p/pol_absent00001`, f.alex)).status).toBe(404)
  expect((await page(f, `/w/${WS}/p/pol_absent00001`, sam)).status).toBe(404)
})

// The page's boot as the browser reads it.
function bootOf(text: string): Record<string, unknown> {
  const raw = /data-boot="([^"]+)"/.exec(text)?.[1] ?? "{}"
  return JSON.parse(raw.replaceAll("&quot;", '"').replaceAll("&#39;", "'").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&amp;", "&")) as Record<string, unknown>
}

it("a machine's rule proposal: the page shows the agent's reason and code, and its own decision, as its browser code signs it, makes the rule the confirmation names", async () => {
  const f = await setup()
  const rules = async (value: "on" | "off") => {
    f.env.POLICY_RULES = value
    await runInDurableObject(env.TENANT_VAULT.getByName(f.work.id), (instance) => { instance.context.env = { ...instance.context.env, POLICY_RULES: value } })
  }
  await rules("on")
  await addCredential(f, f.alex, f.work, "shared-key", { kind: "workspace" })
  const machine = await f.machine(f.alex, f.work)
  const from = { item: "shared-key", method: "POST", url: "https://api.openai.com/v1/files/file-abc123/content", bodyBase64: btoa("{}"), contentType: "application/json" }
  const created = await body<{ proposal: string; bindingCode: string; url: string }>(await f.deviceCall(machine, "/v1/policy/proposals", { from, reason: "Upload each <build> log" }), 201)
  expect(created.url).toMatch(new RegExp(`/w/${WS}/p/${created.proposal}$`))
  const shown = await page(f, `/w/${WS}/p/${created.proposal}`, f.alex)
  expect(shown.status).toBe(200)
  const text = main(shown.text)
  expect(text).toContain('data-region="rule-reason">Upload each &lt;build&gt; log</blockquote>')
  expect(text).toContain(`The agent showed me the code <code class="code-inline">${created.bindingCode}</code>`)
  expect(text).toContain("Allow from now on: shared-key")
  const boot = bootOf(shown.text) as unknown as RuleProposalBoot & { page: string; coded: boolean }
  expect(boot).toMatchObject({ page: "ws-rule-proposal", coded: true, proposal: created.proposal, reason: "Upload each <build> log" })
  expect(await ruleProposalMatches(boot)).toBe(true)
  const built = await ruleProposalEffect(boot, boot.terms.anchorPath, "86400")
  if (!built.ok) throw new Error(built.problems.join(" "))
  const { body: decision, expected } = ruleProposalDecision(boot, "approve", built.value)
  const API = `/api/w/${WS}/policy/proposals/${created.proposal}`
  expect(await body(await f.request(`${API}/action`, f.alex, decision))).toEqual(expected)
  const answer = await body(await f.signed(`${API}/decide`, f.alex, decision, expected, WS))
  expect(ruleProposalOutcomeWords(answer, boot)).toMatch(/^Approved\. Allowed from now on until \d{1,2} [A-Z][a-z]{2} \d{4}, \d{2}:\d{2} UTC\.$/)
  // Settled, the page offers nothing to sign.
  const settled = main((await page(f, `/w/${WS}/p/${created.proposal}`, f.alex)).text)
  expect(settled).toContain('data-region="settled-words"')
  expect(settled).not.toContain('data-region="bar"')
  // With the switch off, the route serves the vault's refusal of the read,
  // not the proposal page.
  await rules("off")
  const off = await page(f, `/w/${WS}/p/${created.proposal}`, f.alex)
  expect(off.status).toBe(403)
  const refused = main(off.text)
  expect(refused).toContain('<section class="card error-card">\n    <h1>This page could not be shown</h1>\n    <p class="lead">Policy widening is not available yet.</p>')
  expect(refused).not.toContain('data-region="decision"')
  expect(off.text).not.toContain("ws-rule-proposal")
})

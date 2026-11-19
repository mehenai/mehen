// The push approval page as the vault serves it (design push-providers 4):
// the card a person opens from a machine's ask, and the pushed value's
// prefix and fingerprint, read as that person through their own items read,
// only for the pushed credential and only for the version the push names.
// Any refusal or error leaves the lines out, never a placeholder.
import { afterEach, expect, it } from "vitest"
import type { WorkspaceItemDescription } from "@mehen/protocol"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { pushAgainMatches } from "../src/ui/client/push-logic.ts"
import { body } from "./e2e/workspace-journey.ts"
import { VALUE, VIA_TOKEN, fakeGitHub, pushJourney, stored, to, type PushJourney } from "./push-journey.ts"

afterEach(() => setUpstreamFetch(null))

type Invoke = { op: string; input?: unknown; auth: { kind: string } }
type Answer = { ok: true; value: unknown } | { ok: false; error: { vaultError: { error: string; message: string } } }

// Every invocation the page makes, and a hook that may answer items.describe
// in its place.
function watchVault(f: PushJourney, describe: (real: () => Promise<Answer>) => Promise<Answer> = (real) => real()): Invoke[] {
  const seen: Invoke[] = []
  const vault = f.env.TENANT_VAULT
  f.env.TENANT_VAULT = new Proxy(vault, { get(target, key) {
    if (key !== "getByName") return Reflect.get(target, key)
    return (name: string) => {
      const stub = target.getByName(name)
      return new Proxy(stub, { get(object, prop) {
        if (prop !== "invoke") { const value = Reflect.get(object, prop) as unknown; return typeof value === "function" ? value.bind(object) : value }
        return async (input: Invoke) => {
          seen.push(input)
          const real = () => object.invoke(input as never) as Promise<Answer>
          return input.op === "items.describe" ? describe(real) : real()
        }
      } })
    }
  } })
  return seen
}

async function asked(f: PushJourney): Promise<string> {
  fakeGitHub()
  return (await body<{ approval: string }>(await f.deviceCall(f.machine, "/v1/push", { item: "openai-prod", to, reason: "deploys need it" }), 409)).approval
}

const page = async (f: PushJourney, approval: string) => (await f.request(`/w/${f.work.slug}/a/${approval}`, f.alex, undefined, { accept: "text/html" })).text()

it("shows the pushed field's prefix and fingerprint as the person may read them, for the pushed credential alone", async () => {
  const f = await pushJourney()
  const approval = await asked(f)
  const described = await body<WorkspaceItemDescription>(await f.request(`/api/w/${f.work.slug}/items/openai-prod`, f.alex))
  const key = described.secretFields.find((s) => s.name === "key")!
  const seen = watchVault(f)
  const html = await page(f, approval)
  expect(html).toContain('data-region="push-summary"')
  expect(html).toContain(`data-region="push-value-facts">${key.prefix !== "" ? `starts <code>${key.prefix}</code>, ` : ""}fingerprint <code>${key.fingerprint}</code></span>`)
  expect(html).toContain('<span class="pill danger">New destination</span>')
  // Read as this person, never the vault itself, and never the via.
  const reads = seen.filter((s) => s.op === "items.describe")
  expect(reads).toEqual([expect.objectContaining({ input: { slug: "openai-prod" }, auth: expect.objectContaining({ kind: "account", account: f.alex.account }) })])
  expect(html).not.toContain(VALUE)
  expect(html).not.toContain(VIA_TOKEN)
  expect(html).not.toMatch(/itm_[A-Za-z0-9]/)
})

it("leaves the prefix and fingerprint out when the read is refused or fails, and the card still shows", async () => {
  const f = await pushJourney()
  const approval = await asked(f)
  const refusals: Answer[] = [
    { ok: false, error: { vaultError: { error: "forbidden", message: "You are not allowed to do that." } } },
    { ok: false, error: { vaultError: { error: "not_found", message: "No such object." } } },
  ]
  for (const refusal of refusals) {
    watchVault(f, async () => refusal)
    const html = await page(f, approval)
    expect(html, refusal.ok ? "" : refusal.error.vaultError.error).toContain('data-region="push-summary"')
    for (const absent of ['data-region="push-value-facts"', "fingerprint <code>", "No such object.", "You are not allowed"]) expect(html, absent).not.toContain(absent)
  }
  watchVault(f, async () => { throw new Error("the object went away") })
  const failed = await page(f, approval)
  expect(failed).toContain('data-region="push-summary"')
  expect(failed).not.toContain('data-region="push-value-facts"')
})

it("leaves them out when the credential described is not the version the push names", async () => {
  const f = await pushJourney()
  const approval = await asked(f)
  watchVault(f, async (real) => {
    const answer = await real()
    return answer.ok ? { ok: true, value: { ...(answer.value as WorkspaceItemDescription), version: (answer.value as WorkspaceItemDescription).version + 1 } } : answer
  })
  const html = await page(f, approval)
  expect(html).toContain('data-region="push-summary"')
  expect(html).not.toContain('data-region="push-value-facts"')
})

it("the credential page shows the allowance and where it was pushed while pushing is on, and nothing about it once off", async () => {
  const f = await pushJourney()
  await f.decide(await asked(f))
  const credential = async () => (await f.request(`/w/${f.work.slug}/items/openai-prod`, f.alex, undefined, { accept: "text/html" })).text()
  const on = await credential()
  expect(on).toContain('data-input="pushable" checked>')
  expect(on).toContain('data-region="pushed-to"')
  expect(on).toContain("GitHub acme/api, Actions secret OPENAI_API_KEY")
  expect(on).toContain('data-region="push-delete"')
  expect(on).not.toContain(VALUE)
  const switched = f.env.PUSH
  f.env.PUSH = "off"
  const off = await credential()
  f.env.PUSH = switched
  for (const absent of ['data-region="push-allowance"', 'data-region="pushed-to"', 'data-region="push-delete"', "secret stores"]) expect(off, absent).not.toContain(absent)
})

it("leaves the prefix and fingerprint out once the credential holds another version than the push names, and the card still shows", async () => {
  const f = await pushJourney()
  const approval = await asked(f)
  // The person may read the credential, but not the version the push names.
  await stored(f, f.alex, f.work, "openai-prod", "openai", "sk-push-rotated-never-shown-0002")
  const rotated = await page(f, approval)
  expect(rotated).toContain('data-region="push-summary"')
  for (const absent of ['data-region="push-value-facts"', "fingerprint <code>"]) expect(rotated, absent).not.toContain(absent)
})

// The page's check of push again against the vault's real plan, so a change
// in the plan's shape fails here rather than making push again always
// refuse: the rows as the credential page shows them, each carrying
// credential read as the person, and push.action's answer from the route.
it("push again's check accepts the plan the vault's push.action route answers for the rows the page shows", async () => {
  const f = await pushJourney()
  await f.decide(await asked(f))
  await stored(f, f.alex, f.work, "openai-prod", "openai", "sk-push-rotated-never-shown-0002")
  const described = await body<WorkspaceItemDescription & { id: string }>(await f.request(`/api/w/${f.work.slug}/items/openai-prod`, f.alex))
  const rows = (described.pushes ?? []).filter((r) => r.state === "done" && !r.current)
  expect(rows).toHaveLength(1)
  const chosen = rows.map((r) => ({ record: r.push, destination: r.destination, field: r.field, via: r.via }))
  expect(chosen[0]!.via).toBe("gh-token")
  const via = await body<{ id: string; version: number }>(await f.request(`/api/w/${f.work.slug}/items/gh-token`, f.alex))
  const plan = await body<unknown>(await f.request(`/api/w/${f.work.slug}/items/openai-prod/push/action`, f.alex, { records: chosen.map((c) => c.record) }))
  const vias = new Map([["gh-token", { id: via.id, version: via.version }]])
  expect(pushAgainMatches({ id: described.id, version: described.version }, chosen, vias, plan)).toBe(true)
  expect(pushAgainMatches({ id: described.id, version: described.version }, chosen, new Map([["gh-token", { id: via.id, version: via.version + 1 }]]), plan)).toBe(false)
})

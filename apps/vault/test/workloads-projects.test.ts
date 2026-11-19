// A workload never creates workspace structure, and changes a project
// variable only when its scope covers both what the variable is bound to now
// and what it is being bound to. Out of cover answers as a device outside
// its scope does. A plain variable it sets, changes or unsets only in a
// project its scope names in projects.
import { expect, it } from "vitest"
import { body } from "./e2e/workspace-journey.ts"
import { workloadJourney } from "./workload-journey.ts"

const newProject = { slug: "task-project", remote: null, defaultEnv: "dev", environments: [{ name: "dev", protected: false }] }

async function variablesJourney() {
  const f = await workloadJourney()
  await f.credential(f.alex, f.work, "openai-main", { kind: "workspace" })
  await f.credential(f.alex, f.work, "openai-other", { kind: "workspace" })
  const setVar = (name: string) => `/v1/projects/${f.project.id}/vars/${name}`
  const bind = async (name: string, item: string) => body(await f.deviceCall(f.machine, setVar(name), { env: "dev", item, field: "key" }, undefined, undefined, "PUT"))
  const binding = async (name: string) => f.sql<{ item: string | null; plain: string | null }>(f.work, "SELECT item,plain FROM vars WHERE name=?", name)
  // A machine whose tags reach neither credential: the answer out of scope looks like.
  const outside = await f.enrolMachine(f.alex, f.work)
  await f.sql(f.work, "UPDATE devices SET scope=json_set(scope,'$.tags',json('[\"elsewhere\"]')) WHERE id=?", outside.device)
  const outsideAnswer = await f.deviceCall(outside, setVar("PROBE"), { env: "dev", item: "openai-other", field: "key" }, undefined, undefined, "PUT")
  expect(outsideAnswer.status).toBe(404)
  return { ...f, setVar, bind, binding, outsideRefusal: await outsideAnswer.json() }
}

it("no workload creates a project, whatever its scope, while its device's own key still can", async () => {
  const f = await workloadJourney()
  const refusal = { error: "forbidden", message: "A workload never creates a project, and a machine that acts only through workloads creates none.", next: { say: "A person creates the project on Mehen's site, or from a machine enrolled without --workloads-only." } }
  for (const scope of [{}, { items: ["openai-main"], modes: ["relay" as const] }]) {
    const task = await f.createWorkload(f.machine, scope, `task-${Object.keys(scope).length}`)
    expect(await body(await f.workloadCall(f.as(task), "/v1/projects", newProject), 403)).toEqual(refusal)
  }
  expect(await f.sql(f.work, "SELECT slug FROM projects WHERE slug=?", newProject.slug)).toEqual([])
  expect((await f.deviceCall(f.machine, "/v1/projects", newProject)).status).toBe(201)
  // A machine that acts only through workloads: its workload gets the same
  // answer, and its own key creates none either.
  const required = await f.enrolMachine(f.alex, f.work)
  await f.sql(f.work, "UPDATE devices SET scope=json_set(scope,'$.workloads','required') WHERE id=?", required.device)
  const task = await f.createWorkload(required, {}, "task-required")
  expect(await body(await f.workloadCall(f.as(task), "/v1/projects", { ...newProject, slug: "required-project" }), 403)).toEqual(refusal)
  expect(await body(await f.deviceCall(required, "/v1/projects", { ...newProject, slug: "required-project" }), 403)).toMatchObject({ error: "workload_required" })
})

it("a workload cannot rebind, or replace with a plain value, a variable bound to a credential outside its items", async () => {
  const f = await variablesJourney()
  await f.bind("OPENAI_KEY", "openai-other")
  const task = await f.createWorkload(f.machine, { items: ["openai-main"], modes: ["relay"] })
  for (const input of [{ env: "dev", item: "openai-main", field: "key" }, { env: "dev", plain: "https://evil.example" }]) {
    const refused = await f.workloadCall(f.as(task), f.setVar("OPENAI_KEY"), input, "PUT")
    expect(refused.status).toBe(404)
    expect(await refused.json()).toEqual(f.outsideRefusal)
  }
  expect(await f.binding("OPENAI_KEY")).toEqual([{ item: "openai-other", plain: null }])
})

it("a workload cannot bind a variable to a credential outside its items, even one bound to a credential it covers", async () => {
  const f = await variablesJourney()
  await f.bind("OPENAI_KEY", "openai-main")
  const task = await f.createWorkload(f.machine, { items: ["openai-main"] })
  for (const name of ["OPENAI_KEY", "UNBOUND"]) {
    const input = { env: "dev", item: "openai-other", field: "key" }
    const refused = await f.workloadCall(f.as(task), f.setVar(name), input, "PUT")
    expect(refused.status).toBe(404)
    expect(await refused.json()).toEqual(f.outsideRefusal)
  }
  expect(await f.binding("OPENAI_KEY")).toEqual([{ item: "openai-main", plain: null }])
})

it("a workload covering both the current and the new binding changes a variable", async () => {
  const f = await variablesJourney()
  await f.bind("OPENAI_KEY", "openai-main")
  const task = await f.createWorkload(f.machine, { items: ["openai-main", "openai-other"] })
  const rebind = { env: "dev", item: "openai-other", field: "key" }
  expect((await f.workloadCall(f.as(task), f.setVar("OPENAI_KEY"), rebind, "PUT")).status).toBe(200)
  expect(await f.binding("OPENAI_KEY")).toEqual([{ item: "openai-other", plain: null }])
  const fresh = { env: "dev", item: "openai-main", field: "key" }
  expect((await f.workloadCall(f.as(task), f.setVar("FRESH"), fresh, "PUT")).status).toBe(200)
  // Bound to plain needs both rules: the binding covered, and the project named.
  const plain = { env: "dev", plain: "https://api.example.test" }
  expect(await body(await f.workloadCall(f.as(task), f.setVar("OPENAI_KEY"), plain, "PUT"), 403)).toEqual(plainRefusal)
  expect(await f.binding("OPENAI_KEY")).toEqual([{ item: "openai-other", plain: null }])
  const named = await f.createWorkload(f.machine, { items: ["openai-main", "openai-other"], projects: [f.project.id] }, "task-named")
  expect((await f.workloadCall(f.as(named), f.setVar("OPENAI_KEY"), plain, "PUT")).status).toBe(200)
  expect(await f.binding("OPENAI_KEY")).toEqual([{ item: null, plain: "https://api.example.test" }])
})

const plainRefusal = { error: "forbidden", message: "A task's workload changes plain variables only in projects it names.", next: { say: "Create a workload whose scope names this project in projects." } }

it("a workload whose scope names no projects sets, changes, unsets and creates no plain variable", async () => {
  const f = await variablesJourney()
  const plain = (value: string) => ({ env: "dev", plain: value })
  expect((await f.deviceCall(f.machine, f.setVar("BASE_URL"), plain("https://api.openai.com/v1"), undefined, undefined, "PUT")).status).toBe(200)
  for (const [index, scope] of [{ items: ["openai-main"], modes: ["relay" as const] }, { tags: ["task"] }, {}].entries()) {
    const task = await f.createWorkload(f.machine, scope, `task-${index}`)
    for (const [name, input] of [["BASE_URL", plain("https://evil.example")], ["BASE_URL", { env: "dev" }], ["NEW_PLAIN", plain("x")]] as const) {
      expect(await body(await f.workloadCall(f.as(task), f.setVar(name), input, "PUT"), 403)).toEqual(plainRefusal)
    }
    // Plain to bound needs both rules: the binding covered, and the project named.
    if (index === 0) expect(await body(await f.workloadCall(f.as(task), f.setVar("BASE_URL"), { env: "dev", item: "openai-main", field: "key" }, "PUT"), 403)).toEqual(plainRefusal)
  }
  expect(await f.sql(f.work, "SELECT name,item,plain FROM vars ORDER BY name")).toEqual([{ name: "BASE_URL", item: null, plain: "https://api.openai.com/v1" }])
})

it("a workload whose scope names a project changes plain variables there and nowhere else; its device's own key is unchanged", async () => {
  const f = await variablesJourney()
  const other = await body<{ id: string }>(await f.deviceCall(f.machine, "/v1/projects", { ...newProject, slug: "other-project" }), 201)
  const plain = (value: string) => ({ env: "dev", plain: value })
  const task = await f.createWorkload(f.machine, { projects: [f.project.id] })
  expect((await f.workloadCall(f.as(task), f.setVar("NEW_PLAIN"), plain("one"), "PUT")).status).toBe(200)
  expect((await f.workloadCall(f.as(task), f.setVar("NEW_PLAIN"), plain("two"), "PUT")).status).toBe(200)
  expect(await f.binding("NEW_PLAIN")).toEqual([{ item: null, plain: "two" }])
  expect((await f.workloadCall(f.as(task), f.setVar("NEW_PLAIN"), { env: "dev" }, "PUT")).status).toBe(200)
  expect(await f.binding("NEW_PLAIN")).toEqual([{ item: null, plain: null }])
  expect((await f.workloadCall(f.as(task), f.setVar("BASE_URL"), plain("https://api.openai.com/v1"), "PUT")).status).toBe(200)
  expect((await f.workloadCall(f.as(task), f.setVar("BASE_URL"), { env: "dev", item: "openai-main", field: "key" }, "PUT")).status).toBe(200)
  expect(await f.binding("BASE_URL")).toEqual([{ item: expect.any(String), plain: null }])
  const elsewhere = await f.workloadCall(f.as(task), `/v1/projects/${other.id}/vars/NEW_PLAIN`, plain("x"), "PUT")
  expect(elsewhere.status).toBe(404)
  expect(await f.sql(f.work, "SELECT name FROM vars WHERE project=?", other.id)).toEqual([])
  for (const path of [f.setVar("DEVICE_PLAIN"), `/v1/projects/${other.id}/vars/DEVICE_PLAIN`]) expect((await f.deviceCall(f.machine, path, plain("ok"), undefined, undefined, "PUT")).status).toBe(200)
})

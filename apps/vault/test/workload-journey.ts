// A machine and its workloads through the real Worker and Durable Object:
// every call is worker.fetch with a real proof, signed by the device's own
// key or by a workload's.
import { createProof, webCryptoSigner, type WorkloadScope, type WorkloadView } from "@mehen/protocol"
import { expect } from "vitest"
import { ORIGIN } from "./helpers.ts"
import { newDeviceKey, publicJwk } from "./devices.ts"
import { body, workJourney, type Machine } from "./e2e/workspace-journey.ts"

export type Workload = { view: WorkloadView; keys: CryptoKeyPair; machine: Machine }

export async function workloadJourney() {
  const f = await workJourney()
  const machine = await f.machine(f.alex, f.work)
  // Signs as the workload: kid and wkl are the workload id, dev its device.
  async function workloadCall(workload: { id: string; keys: CryptoKeyPair; machine: Machine }, path: string, input?: unknown, method = input === undefined ? "GET" : "POST", tenant = workload.machine.workspace.id) {
    const encoded = input === undefined ? null : JSON.stringify(input), url = `${ORIGIN}${path}`
    const proof = await createProof(webCryptoSigner(workload.machine.device, workload.keys.privateKey, workload.id), { method, url, body: encoded }, { tenant })
    return f.request(path, undefined, input, { "Mehen-Proof": proof }, method)
  }
  async function createWorkload(owner: Machine, scope: WorkloadScope = {}, label = "task-1", ttlSeconds?: number): Promise<Workload> {
    const keys = await newDeviceKey()
    const view = await body<WorkloadView>(await f.deviceCall(owner, "/v1/workloads", { jwk: await publicJwk(keys), label, scope, ...(ttlSeconds ? { ttlSeconds } : {}) }), 201)
    expect(view).toMatchObject({ device: owner.device, label, scope, state: "active", revokedAt: null, revokedBy: null })
    return { view, keys, machine: owner }
  }
  const as = (workload: Workload) => ({ id: workload.view.workload, keys: workload.keys, machine: workload.machine })
  return { ...f, enrolMachine: f.machine, machine, workloadCall, createWorkload, as }
}

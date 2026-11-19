// Device proofs, asserted through the real workspace Worker and DO.
import { createProof, webCryptoSigner } from "@mehen/protocol"
import { expect, it } from "vitest"
import { ORIGIN } from "../helpers.ts"
import { body, workJourney } from "./workspace-journey.ts"

it("workspace device proofs reject replay, another workspace, URL/method/body tampering and both clock skews without spending a nonce or auditing",async () => {
  const f = await workJourney(),machine = await f.machine(f.alex,f.work)
  const signer = webCryptoSigner(machine.device,machine.keys.privateKey)
  const proof = (path = "/v1/me",method = "GET",input?: unknown,tenant = f.work.id,now = Date.now()) => createProof(signer,{ method,url: `${ORIGIN}${path}`,body: input === undefined ? null : JSON.stringify(input) },{ tenant,now })
  const send = (signature: string,path = "/v1/me",method = "GET",input?: unknown) => f.request(path,undefined,input,{ "Mehen-Proof": signature },method)
  const state = () => Promise.all([f.work,f.personal].map(async workspace => ({
    nonces: await f.sql(workspace,"SELECT * FROM device_nonces ORDER BY device,jti"),
    audit: await f.sql(workspace,"SELECT * FROM audit ORDER BY seq"),
  })))
  const fresh = await proof()
  expect(await body(await send(fresh))).toEqual(await f.expectedMachineStatus(f.alex,machine))
  for (const [name,signature,path,method,input,error] of [
    ["replay",fresh,"/v1/me","GET",undefined,"proof_invalid"],
    ["other workspace",await proof("/v1/me","GET",undefined,f.personal.id),"/v1/me","GET",undefined,"unauthenticated"],
    ["tampered URL",await proof("/v1/items"),"/v1/me","GET",undefined,"proof_invalid"],
    ["tampered method",await proof("/v1/me","POST"),"/v1/me","GET",undefined,"proof_invalid"],
    ["tampered body",await proof("/v1/devices/self/revoke","POST",{ a: 1 }),"/v1/devices/self/revoke","POST",{ a: 2 },"proof_invalid"],
    ["backward skew",await proof("/v1/me","GET",undefined,f.work.id,Date.now()-120_000),"/v1/me","GET",undefined,"proof_invalid"],
    ["forward skew",await proof("/v1/me","GET",undefined,f.work.id,Date.now()+120_000),"/v1/me","GET",undefined,"proof_invalid"],
  ] as const) {
    const before = await state(),response = await send(signature,path,method,input)
    expect(response.status,name).toBe(401)
    expect(await response.json(),name).toMatchObject({ error })
    expect(await state(),`${name}: nonces and audit must not change`).toEqual(before)
  }
})

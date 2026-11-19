import { expect, it } from "vitest"
import { refusal, workJourney } from "./workspace-journey.ts"

it("workspace intake refuses agent-proposed header maps and reserved headers before recording a request",async () => {
  const f = await workJourney(),machine = await f.machine(f.alex,f.work)
  const injections = [
    { in: "headers",field: "key" },
    ...["Host","hOsT","Cookie","X-Forwarded-Host","x-forwarded-for","Forwarded","Proxy-Anything","CF-Connecting-IP","Mehen-Item","X-Real-IP","True-Client-IP","X-Original-URL","Expect","Set-Cookie","X-HTTP-Method-Override","X_Original_URL","X_HTTP_Method_Override","x_forwarded_for","proxy_authorization"].map(name => ({ in: "header",name,format: "Bearer {key}" })),
  ]
  for (const injection of injections) {
    const before = await f.sql(f.work,"SELECT * FROM workspace_credential_requests ORDER BY id")
    const reason = injection.in === "headers" ? "is a header map, which an agent may not propose; propose one header, a query parameter or basic credentials" : `cannot use the header "${"name" in injection ? injection.name : ""}"`
    await refusal(await f.deviceCall(machine,"/v1/intakes",{ kind: "api-key",slug: "custom-injection",reason: "fixture",home: "private",binding: { hosts: ["api.example.com"] },injection }),400,{ error: "bad_request",message: `The proposed injection ${reason}. A API key has the secret field(s) key; use for example { "in": "header", "name": "Authorization", "format": "Bearer {key}" }.` })
    expect(await f.sql(f.work,"SELECT * FROM workspace_credential_requests ORDER BY id")).toEqual(before)
  }
})

it("workspace intake refuses a proposed injection on a kind the relay never puts into a request, as the legacy intake does",async () => {
  const f = await workJourney(),machine = await f.machine(f.alex,f.work)
  const proposals = [
    { kind: "hmac-key",label: "Signing secret (HMAC)",injection: { in: "header",name: "X-Signature",format: "{key}" } },
    { kind: "oauth-client",label: "OAuth client",injection: { in: "basic",username: "client_id",password: "client_secret" } },
    { kind: "generic",label: "Other",injection: { in: "query",name: "key",field: "value" } },
  ]
  for (const { kind,label,injection } of proposals) {
    const before = await f.sql(f.work,"SELECT * FROM workspace_credential_requests ORDER BY id")
    await refusal(await f.deviceCall(machine,"/v1/intakes",{ kind,slug: `custom-${kind}`,reason: "fixture",home: "private",binding: { hosts: ["api.example.com"] },injection }),400,{ error: "bad_request",message: `The relay never puts a ${label} into a request, so it takes no injection. Leave it out.` })
    expect(await f.sql(f.work,"SELECT * FROM workspace_credential_requests ORDER BY id")).toEqual(before)
  }
})

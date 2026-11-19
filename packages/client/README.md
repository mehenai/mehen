# @mehen/client

A small, typed client for Mehen's machine API and its platform API. It signs every request with a Mehen proof exactly as the `mehen` CLI does (a platform's with a platform proof), parses every answer, and tells a vault refusal apart from an upstream's own error. It runs anywhere with WebCrypto and `fetch`: Cloudflare Workers, Bun, Node 20 or later, Deno and browsers. It never stores a key.

## Status

Private and not yet published to npm (`"private": true`). It depends on `@mehen/protocol`, which is not published either, so publishing waits on that. Inside the Mehen repository it is the workspace package `packages/client`, used as `"@mehen/client": "workspace:*"`.

## Enrol a machine

A machine is a P-256 key. Generate one, start an enrolment and hand the link to a person, who opens it, types the fingerprint group the page hides and accepts with their passkey.

```ts
import { enrolmentStatus, exportPrivateKey, generateKey, startEnrolment } from "@mehen/client"

const key = await generateKey()
const pkcs8 = await exportPrivateKey(key.privateKey) // wrap and keep this yourself

const started = await startEnrolment({
  vaultUrl: "https://app.mehen.dev",
  workspace: "acme",
  owner: { kind: "self" },
  name: "build-runner",
  scope: { tags: ["ci"], workloads: "required" }, // optional: ask for less than usual
  key,
})
// Show the person started.url, started.fingerprint.groups and which group
// the page hides (started.hiddenGroup), so they can check the key.

const status = await enrolmentStatus({ vaultUrl: "https://app.mehen.dev", enrolment: started.enrolment, key })
if (status.status === "active") {
  // status.tenant and status.device are what createClient needs.
}
```

Poll with `enrolmentStatus` every few seconds, and keep the link alive with `renewEnrolment` while you wait: it answers `renewed`, `later` (try again after `retryAfter` seconds) or `settled`.

## Make requests

```ts
import { createClient, deviceSigner, importPrivateKey } from "@mehen/client"

const { privateKey } = await importPrivateKey(pkcs8, { extractable: false })
const mehen = createClient({ vaultUrl: "https://app.mehen.dev", tenant: status.tenant, signer: deviceSigner(status.device, privateKey) })

const me = await mehen.me()
const items = await mehen.items()
```

## Create a workload

A workload is a short-lived child key with a scope that only narrows the device's. Give each task its own: the vault keeps one task out of another's credentials, approvals and runs, names the task in the audit, and ends its reach the moment you revoke it.

```ts
import { createClient, generateKey, workloadSigner } from "@mehen/client"

const task = await generateKey()
const workload = await mehen.workloads.create({ jwk: task.jwk, label: "job:1842", ttlSeconds: 3600, scope: { items: ["openai"] } })

const forTask = createClient({ vaultUrl: "https://app.mehen.dev", tenant: status.tenant, signer: workloadSigner(status.device, workload.workload, task.privateKey) })
// ... later
await mehen.workloads.revoke(workload.workload)
```

Only the device's own key creates, renews, lists and revokes workloads; a workload that tries is refused with `forbidden`, and so is a workload calling `revokeSelf` or `freeze`. `forTask.me()` answers the device with a `workload` field, the workload's own view.

A workload scoped by `items` asks for an intake or a connection only for a slug in them. A connection also needs the provider's OAuth client there, for Gmail `{ items: ["gmail-task", "google-oauth-client"] }`, because the vault reads the client (or asks for it) as the workload; without it `connect` is refused with `forbidden`, naming the client to list. A workload scoped by `tags` or `projects` asks only for a credential it could then see: give the intake `tags` (a connection `clientTags`) that include one of the workload's, and a project home among its projects, or the ask is refused with `forbidden` before anything is created.

What a workload asks for is its own: only it polls, waits on, cancels or spends its approvals, intakes, connections and runs. The device's own key sees them in `pending()` but cannot cancel or spend one; revoking the workload ends every open ask it owns. A device enrolled with `workloads: "required"` may use its own key only for `me`, `items`, `item`, `pending`, the workload calls, `freeze` and `revokeSelf`; anything else is refused with `workload_required`. A request from a workload that has expired or been revoked, or whose device was revoked, is refused with `workload_ended`.

## Relay a request

```ts
const answer = await forTask.relay({ item: "openai", method: "POST", url: "https://api.openai.com/v1/responses", headers: [["content-type", "application/json"]], body: JSON.stringify({ input: "Hello" }) })
// answer.status, answer.headers and answer.body (bytes) are the upstream's,
// a 4xx or 5xx included.
```

Bodies are bytes both ways; a string body is sent as UTF-8.

`relayStream` takes the same input and answers `{ kind: "stream", status, headers, body, item }` with the upstream's body as an unread `ReadableStream`, for answers too long to buffer or that stream (server-sent events). It refuses exactly as `relay` does: `MehenRefusal` on the vault's own refusal, `MehenTransport` for an answer without `Mehen-Upstream`. Its timeout (`timeoutMs`, the client's by default) covers the whole exchange, the body included: a body that stalls past it errors with a `MehenTransport` timeout. Aborting `signal` rejects, or errors the body, with the signal's own reason. Read the body or cancel it.

```ts
const answer = await forTask.relayStream({ item: "openai", method: "POST", url: "https://api.openai.com/v1/responses", headers: [["content-type", "application/json"]], body: JSON.stringify({ input: "Hello", stream: true }) }, { timeoutMs: 300_000 })
const forwarded = new Response(answer.body, { status: answer.status, headers: answer.headers })
```

## Runs

A run gives a task a project environment's variables, as `mehen run` does: plain values as they are, secrets as placeholders only the vault swaps back, on run-mode relays. A task with no checkout uses a workload pinned to the project (its scope names it in `projects`, with `placeholder` in `modes`), which may start the run with `remote: null` even when the project binds remotes, outside protected environments.

```ts
const project = await forTask.project("prj_...")
const vars = project.vars.filter((v) => v.env === "dev").map((v) => v.name)
const run = await forTask.runs.create({ project: project.id, env: "dev", envSource: "flag", remote: null, worktree: "/workspace", head: null, vars, command: "job:1842" })
// run.vars: each { name, delivery }, with value for plain and placeholder, and hosts for a placeholder.
const key = run.vars.find((v) => v.name === "OPENAI_API_KEY")
if (key?.delivery === "placeholder") {
  const models = await forTask.relay({ run: run.run, method: "GET", url: "https://api.openai.com/v1/models", headers: [["authorization", `Bearer ${key.value}`]] })
}
await forTask.runs.renew(run.run) // every few minutes: a run lasts 15 minutes unless renewed, at most 12 hours unless it is a service run
await forTask.runs.end(run.run)
```

A relay names exactly one of `item` and `run`; both or neither is a `TypeError` before anything is sent. A relay through a run names only the run: the vault swaps the run's placeholders it finds where their items allow, and refuses one anywhere else with `surface_refused`. The session comes from the client's options, as for intakes.

A run's placeholders are a capability while the run lives: anything holding one can have the vault use the secret at its item's hosts through that run. Keep them inside the task, and end the run when the task ends. Only the workload that created a run may use, renew or end it; its device's own key gets `not_found`, and ends the run by revoking the workload, which ends all of the workload's runs.

## Handle an approval

A vault refusal throws `MehenRefusal`, with the protocol's error `code`. When a person must approve the request, the refusal carries what to show them:

```ts
import { MehenRefusal, MehenTransport } from "@mehen/client"

try {
  await forTask.relay(request)
} catch (error) {
  if (error instanceof MehenRefusal && error.code === "approval_required" && error.approval) {
    // Show error.link and error.bindingCode; the link stops working at error.expiresAt.
    const approval = await forTask.approval(error.approval, { wait: true })
    if (approval.status === "approved") await forTask.relay({ ...request, approval: approval.approval })
  }
  if (error instanceof MehenTransport) {
    // No usable answer. The upstream may or may not have received the
    // request: never retry a non-idempotent request blindly.
  }
}
```

A code this client does not know, from a newer vault, arrives as `code: "internal"` with the vault's own code in `rawCode`. `link` (and `next.url`) is always absolute and on the vault's origin, even when the vault sent a path such as `/account`.

`MehenTransport` covers everything that is not the vault's answer: a network failure, a timeout (`timeoutMs`, 60 seconds by default), an error page without `Mehen-Error`, an answer that does not parse, or a link off the vault's origin.

## Build a platform

A platform is a business that serves its own users through Mehen: one managed workspace per user, which the platform creates and acts in with its own key, and no Mehen page, account or passkey for anyone. The docs' [Build on Mehen](https://docs.mehen.dev/guides/build-on-mehen) guide explains the model; this is the client for it. Mehen's operator registers the platform with the public half of its P-256 key and gives it a platform id and a key id.

```ts
import { createPlatformClient, platformSigner } from "@mehen/client"

// platformId (plt_...) and keyId (pky_...) are the ids the operator gave you.
const privateKey = await crypto.subtle.importKey("jwk", JSON.parse(privateJwkText) as JsonWebKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])
const platform = createPlatformClient({ vaultUrl: "https://app.mehen.dev", signer: platformSigner(platformId, keyId, privateKey) })

const view = await platform.view() // status, limits, defaults, keys: if this answers, the key works
await platform.subjects.ensure("u_8c1f2e9a7b") // the user's managed workspace, made or found
const user = platform.subject("u_8c1f2e9a7b")
```

Every call is signed with a `Mehen-Platform-Proof` over its method, URL, body, time and a nonce; there is no bearer token. A subject is the platform's own opaque name for a user, 8 to 128 of `A-Z a-z 0-9 _ -`.

**A device per agent.** The platform registers the agent's public key; nobody accepts it. From then on the agent uses the machine client above, through workloads.

```ts
import { createClient, deviceSigner, generateKey } from "@mehen/client"

const agentKey = await generateKey()
const device = await user.devices.create({ name: "assistant", jwk: agentKey.jwk, modes: ["relay", "placeholder"] })
const asAgent = createClient({ vaultUrl: "https://app.mehen.dev", tenant: device.tenant, signer: deviceSigner(device.device, agentKey.privateKey) })
```

**A key from the user's page.** The platform opens an intake; the user's browser seals what they type ([below](#seal-in-a-browser)); the platform submits the boxes.

```ts
const intake = await user.intakes.create({ slug: "openai", service: { template: "openai" } })
// Hand intake.intake, intake.sealKey and intake.fields to the page; it hands back `sealed`.
const item = await user.intakes.submit(intake.intake, { sealed })
```

An intake a workload opened with no template needs the terms your user was shown: `intakes.submit(id, { sealed, terms: { binding, injection } })`.

**A decision.** When a workload's relay is refused with `approval_required`, the platform reads the held request, checks it against what the user agreed to, and decides with its digest. A decision serves one use, for at most 15 minutes.

```ts
// approvalId: the refusal's `approval`, which the agent passed to the platform.
const held = await user.approvals.get(approvalId)
await user.approvals.decide(held.approval, { decision: "approve", digest: held.digest, ref: "card:5521" })
```

**A project for computers, and leaving.**

```ts
const project = await user.projects.create({ slug: "computer", environments: [{ name: "default" }], defaultEnv: "default" })
await user.projects.setVar(project.id, "OPENAI_API_KEY", { env: "default", before: null, item: "openai" })
await platform.subjects.remove("u_8c1f2e9a7b") // every device and secret at once; the audit is kept for the platform's retention
```

Also on a subject: `devices.list` and `revoke`, `items.list` and `remove`, `intakes.cancel`, `connects` (start, finish, status, cancel), `approvals.list`, `projects.get` and `remove`, `audit`, `freeze` and `unfreeze`; on the platform, `defaults.get` and `put`, `subjects.get`, `list` and `removeAll`. Every answer is parsed with the protocol's schemas, and every refusal is a `MehenRefusal` as above, with no link: in a managed workspace the platform decides and reconnects.

## Seal in a browser

`@mehen/client/seal` is a separate entry for a platform's own web page. It imports nothing but Mehen's sealing code (no schema library, none of the client), so the page stays small, and the value the user types is sealed to the vault's key before it leaves their browser: the platform's server passes on a box it cannot open.

```ts
import { sealFields } from "@mehen/client/seal"

// intake.sealKey and intake.intake came from the platform's server, which opened the intake.
const sealed = await sealFields(intake.sealKey, intake.intake, { key: "sk-..." })
// POST sealed to the platform's server, then clear the field.
```

Each box is sealed under the context `intake/<intake>/<field>`, so it opens only for that field of that intake, and only once. An OAuth app's client secret is sealed the same way, as a field of its own intake.

## Also here

`project(id)` reads a project's remotes, environments and variables; `intake`, `intakeStatus` and `cancelIntake` ask a person for a credential; `connect`, `connectStatus` and `cancelConnect` for an OAuth connection; `pending` lists this machine's open asks (signed by a workload, only that workload's); `revokeSelf` (the device's own key only) and `freeze` (the device's own key only; a workload is refused with `forbidden`) are the panic buttons. `fingerprint(jwk)` gives the thumbprint, groups and words the CLI prints for a key. In a platform's managed workspace an intake's answer carries no `url`, `connect` is refused with `forbidden` because the platform starts every connection, and a refusal's `link` is absent: the platform, not a person on a Mehen page, settles it.

---
title: Build on Mehen
question: How do I use Mehen to keep my users' credentials, as a business?
section: guides
covers: cloud
order: 120
---

# Build on Mehen

Your product has users, and your agents need their credentials: API keys, Gmail, GitHub, an account at a service nobody else has heard of. Mehen keeps those credentials so that neither your servers nor your models ever hold them, and your users never see Mehen: no account, no passkey, no page, no link. This guide is for a business deciding whether to build on Mehen, and then for its engineers. [Platforms and managed workspaces](../concepts/platforms.md) explains the pieces; [Platform API](../reference/platform.md) has every route.

## What you get

**One umbrella.** Your platform sits on top: your key, your limits and your defaults. Under it, one managed workspace per user, each its own vault, so one user's keys, history and deletion never touch another's. Under each workspace, a device per agent you run; under each device, a workload per task; under a task that runs programs, a run with its environment. No other platform sees your workspaces; you see them listed by your users' subjects. Mehen's operator sees your platform, your subjects and your workspaces' status, and no operator command shows what is in them ([What Mehen's operator sees](#what-mehens-operator-sees)). Every audit row in them names your platform.

**In each workspace:** a device per agent you run; a short-lived workload per task, a key whose scope only narrows the device's; relayed requests, with the credential added on the way to the one host it may go to; projects whose settings and placeholders your sandboxes run with; each credential's policy from Mehen's catalogue, made stricter by your defaults where you choose; and a hash-chained audit of everything.

## What you hold, and what you never hold

You hold a **platform key** (P-256), your agents' **device keys** and your tasks' **workload keys**. Each signs requests; none of them is a credential of your users.

You never hold a user's secret. Your user types it into your page, your page seals it in their browser to Mehen's public seal key, and your server passes on a sealed box it cannot open and cannot reuse. Your agents never hold one either: they ask Mehen to make the call, or run with a placeholder that only Mehen turns back into the key, on its way to the key's own host.

You never hold an OAuth token. Each user brings their own OAuth app, guided by your page, and its client secret is sealed in their browser like any key. The code your callback receives is useless without that secret, which only Mehen holds ([Connecting an account](#connecting-an-account)).

## What Mehen's operator sees

Mehen's operator registers your platform and can suspend it, change its limits, rotate or revoke its keys, retire it, and remove it. Their platform commands and console show your platform's status, your keys' public halves, your limits and the revision of your defaults; your users' subjects, each with its workspace's status and dates; and, for the last day, how many devices were made, credentials added and deleted, decisions taken and calls refused. None of those commands or pages shows what is inside a workspace, and none acts in one. Each change they make is recorded with your platform's events, which you can read in Mehen's web app ([Your platform in Mehen's web app](#your-platform-in-mehens-web-app)). Beyond them, whoever runs Mehen sees what they see of any workspace: secrets only as ciphertext they cannot open without the root key, and the metadata in storage and the audit, such as which credentials exist and which hosts they were used on ([Threat model: the operator](../security/threat-model.md#the-operator)).

## Onboarding

Platforms run on Mehen Cloud, which is invite only for now, for platforms too: write to [hello@mehen.dev](mailto:hello@mehen.dev).

1. **Make a platform key** on a machine your agents cannot reach, and keep its private half in your server's secret store.
2. **Send the public half** to Mehen's operator, who registers your platform with your name and limits and gives you a platform id (`plt_...`) and a key id (`pky_...`).
3. **Set your defaults**, once ([below](#defaults-set-once)).

Your users never meet any of this. If you want to manage the platform from Mehen's web app as well, ask the operator to make your people its admins ([below](#your-platform-in-mehens-web-app)).

```ts
// Run once, on a machine no agent can reach.
const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey)
const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey)
// Put JSON.stringify(privateJwk) in your server's secret store.
// Send JSON.stringify({ kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y }) to Mehen's operator.
```

## The first call

Every call to `/v1/platform` carries `Mehen-Platform-Proof`, your signature over the method, the URL, the body, the time and a nonce. `@mehen/client`'s platform client makes it for you, and nothing you send is a bearer token, so nothing in a log can be replayed.

```ts
import { createPlatformClient, platformSigner } from "@mehen/client"

const privateKey = await crypto.subtle.importKey("jwk", JSON.parse(env.PLATFORM_PRIVATE_JWK) as JsonWebKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])
const platform = createPlatformClient({ vaultUrl: env.VAULT_URL, signer: platformSigner(env.PLATFORM_ID, env.PLATFORM_KEY_ID, privateKey) })

const view = await platform.view()
// view.platform.status is "active": your key works.
```

`view()` answers your platform as Mehen holds it: its status, limits, defaults and keys. If it answers, your key works.

A key pair made in Mehen's web app, by the operator for a platform they run themselves or by one of your admins, gives its private half as PKCS8 in base64url, not as a JWK: decode the base64url to bytes and import them with `crypto.subtle.importKey("pkcs8", bytes, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])` instead; the rest is the same.

## A workspace for each user

```ts
const user = platform.subject(subject)
await platform.subjects.ensure(subject)
```

`subjects.ensure` creates the user's managed workspace, or answers the one they already have; call it whenever you are not sure. While a user is still being deleted it answers `conflict`. A **subject** is your own name for the user: 8 to 128 of `A-Z a-z 0-9 _ -`. Choose one you will never reuse and that says nothing about the person, such as a random id you store, or a hash of your own user id with a fixed prefix. Mehen never interprets it, and another platform's subject with the same string is a different workspace.

Make workspaces when you first need one, on a user's first key or first connection, not for every sign-up: a user who never adds a credential costs nothing in Mehen.

## A device for each agent

Each agent you run gets a device: its own P-256 key, registered in the user's workspace by your platform, with no page for anyone to accept.

```ts
import { createClient, deviceSigner, generateKey } from "@mehen/client"

const agentKey = await generateKey()
const device = await user.devices.create({ name: "assistant", jwk: agentKey.jwk, modes: ["relay", "placeholder"], label: "agent:7f3c" })

const asAgent = createClient({ vaultUrl: env.VAULT_URL, tenant: device.tenant, signer: deviceSigner(device.device, agentKey.privateKey) })
```

A device may only relay and serve placeholders, and acts only through workloads: it never leases, mints, signs or reveals, so no value ever reaches it. Calling `devices.create` again with the same key answers the same device; a revoked device's key is never taken again (`conflict`). Keep the device key as you would any key (`exportPrivateKey` gives its bytes to wrap); if you lose it, revoke the device with `user.devices.revoke` and provision a new one.

From here the device is an ordinary Mehen machine using `@mehen/client`'s machine API: it creates a [workload per task](harnesses.md#one-workload-per-task), relays through it, and revokes it when the task ends. A held request, a failed relay and a refusal reach it exactly as they would anywhere else, except that nothing carries a link: in your workspaces, you decide.

## Adding a user's key

Your page asks for the key; Mehen never shows a page of its own.

1. When the user presses Add, your server calls `intakes.create`, which answers an intake, Mehen's seal key and the fields to draw.
2. Your page draws the fields and, when the user submits, seals each field marked `secret` in their browser with `@mehen/client/seal`. A field that is not secret, such as an OAuth app's client id, goes as it is, in `publicFields`.
3. Your page sends the sealed boxes to your server, which submits them.

```ts
// On your server: open the request.
const intake = await user.intakes.create({ slug: "openai", service: { template: "openai" }, reason: "Your assistant uses your OpenAI key." })
// Send intake.intake, intake.sealKey and intake.fields to the page.
```

```ts
// In the user's browser.
import { sealFields } from "@mehen/client/seal"

const sealed = await sealFields(intake.sealKey, intake.intake, { key: "sk-..." })
// POST sealed to your server, and clear the field.
```

```ts
// On your server again.
const item = await user.intakes.submit(intake.intake, { sealed })
// item.slug is "openai"; there is no value anywhere in it.
```

A sealed box opens only for that intake and that field, and only once, so a box your server keeps is worthless. For a service in Mehen's catalogue (`service: { template }`), the catalogue fixes where the key may go and how it is sent. For any other API, name its one host (`service: { host: "api.example.com" }`): the key goes there and nowhere else, and every request with it is held for your decision unless your defaults let reads through. An intake lives 10 minutes. Adding a key under a name the user already has, of the same kind and for the same service, replaces the secret and keeps where it may go.

An agent's workload can open an intake too (`POST /v1/intakes`), and you submit it the same way. When the workload chose a new key's host and how it is sent, with no template, the vault stores only terms you vouch for: send `terms`, the `binding` and `injection` you showed your user (`injection` is `null` for a kind Mehen never puts into a request), and the submit is refused with `bad_request` unless both equal what the workload asked for. With no proposed injection, the kind's usual one is the intake's, such as `Bearer {key}` in `Authorization` for an API key. When the workload proposed no host, for a kind Mehen never puts into a request, send `binding: { hosts: ["lease-only.mehen.invalid"] }` and `injection: null`. An intake your server opened, a template's and a replacement need no `terms`; terms you send for one are checked against its own in the same way.

`@mehen/client/seal` imports nothing but Mehen's sealing code, so your page needs no other part of the client, and your server never sees what the user typed.

## Connecting an account

Gmail, Google Calendar, GitHub, Microsoft 365, or any other OAuth 2 service: each user connects with **their own OAuth app**, which they make at the provider with your page's guidance. You need no app at Google, GitHub or Microsoft, no user's grants sit under an app of yours, and the consent screen shows the user's own app name. Apps owned by the platform, one of yours serving all of your users, are not offered yet.

It takes two steps the first time for a provider, and one after that.

**1. The user's own app.** Open an intake for the provider's app template, `google-oauth-client`, `github-oauth-client` or `microsoft-oauth-client`, named after the template so a connection finds it by default:

```ts
const appIntake = await user.intakes.create({ slug: "google-oauth-client", service: { template: "google-oauth-client" } })
// appIntake.setup: the steps to show; appIntake.fields: client_id (not secret) and client_secret (secret).
```

The answer carries the template's **set-up steps** (`setup`), each a short title, a sentence or two, and a link to the provider's console where there is one. Show them on your page beside the form, after replacing `{callback}` in each step with your own callback URL, exactly as you will send it below. Google's steps have the user create a project, enable the API, set up the consent screen, add themselves as a test user, publish the app to production (while it is in Testing, Google ends its sign-in after 7 days, and their own unverified app shows them Google's unverified app notice, which is expected), create a Web client with your callback as its redirect URI, and copy the id and secret into your form. Then the user's browser seals the secret, and your server submits it with the id:

```ts
const app = await user.intakes.submit(appIntake.intake, { sealed, publicFields: { client_id: "1234-abc.apps.googleusercontent.com" } })
```

The client secret was sealed in the user's browser, so your servers never see it, and only Mehen can use it.

**2. Connect.** Start the connection with your callback, and send the user to the provider in a new window:

```ts
const started = await user.connects.start({ provider: "google-gmail", slug: "gmail", redirectUri: "https://app.example.com/oauth/callback" })
// Open started.authorizeUrl for the user. It lives 15 minutes.
```

The provider's authorisation URL names the user's own app, your callback, Mehen's single-use `state`, the scopes, and a PKCE challenge wherever the provider supports one. Without `scopes`, a connection asks for your default scopes for the provider, else the catalogue's. A connection to the same provider with another name, Google Calendar after Gmail say, uses the same app: Connect is then the only step.

When the provider sends the user back to your callback, check that they are signed in to you as the user who started it, then pass on what arrived, naming that user:

```ts
// In your callback, for the user signed in to your app.
const state = callbackUrl.searchParams.get("state") ?? ""
const code = callbackUrl.searchParams.get("code")
const finished = await user.connects.finish(code === null ? { state, error: callbackUrl.searchParams.get("error") ?? "access_denied" } : { state, code })
// finished.status is "completed", with finished.item.account the provider's verified account, or "failed" with a reason.
```

Mehen exchanges the code itself, at the provider's token URL, with the user's client secret and, where it sent a challenge, its PKCE verifier. A code is useless without that secret, which only Mehen holds, so the code passing through your callback gives your servers nothing. The `state` is used once, and is found only in the named user's workspace: a state that is another user's is `not_found`, so a code from one person's browser cannot finish another's connection, and a state already used, or older than 15 minutes, is a `conflict`. A failed connection says why: `denied` (the user said no), `provider` (the provider refused the exchange), `mismatch` (a reconnect signed in as another account) or `wider` (the provider granted more than was asked). If the provider does not answer at all, the call is refused with `upstream_failed` and the connection must be started again.

**Reconnecting.** When a relay is refused with `needs_reauth`, start a connection again with the same `slug`: it is a reconnect, pinned to the same account at the provider.

**Any other provider.** For a service outside Mehen's catalogue, the user's app carries its own **provider definition**. Your page explains, in words, how to make an app at that provider; the form then takes the definition, the client id and the secret:

```ts
const customIntake = await user.intakes.create({
  slug: "acme-app",
  service: {
    customProvider: {
      name: "Acme",
      authorizeUrl: "https://auth.example.com/oauth/authorize",
      tokenUrl: "https://auth.example.com/oauth/token",
      scopes: ["read", "write"],
      pkce: "S256",
      clientAuth: "client_secret_post",
      hosts: ["api.example.com"],
    },
  },
})
// ... the user's browser seals client_secret; your server submits it with client_id, as above.
const acme = await user.connects.start({ client: "acme-app", slug: "acme", redirectUri: "https://app.example.com/oauth/callback" })
```

A definition says:

- **`authorizeUrl`, `tokenUrl`**: https only, on a public host name, with no user name, password or fragment. An IP address or a private name (such as `localhost` or `*.internal`) is refused. The check is by name: the vault's outbound requests cannot reach private networks at all, so a public name that resolves to a private address reaches nothing.
- **`scopes`**: every scope a connection may ask for; a connection asks for all of them unless it names fewer. `scopeSeparator` is a space unless the provider wants a comma.
- **`pkce`**: `S256` if the provider supports PKCE, else `none`.
- **`clientAuth`**: how the app authenticates at the token URL: `client_secret_post` (in the form body) or `client_secret_basic` (an HTTP Basic header). An app with no secret (a public app, `none`) is not supported yet: its intake is refused with `bad_request`.
- **`authorizeParams`**: up to 8 extra authorisation parameters, never one Mehen sets itself (`client_id`, `redirect_uri`, `state`, `scope`, the PKCE ones and so on).
- **`hosts`**: the API hosts the token may be sent to, at most 16; this is the connection's destination.
- **`injection`**: how the token is sent; a bearer `Authorization` header unless it says otherwise.

The definition is not secret, and it is fixed once the app is stored: to change it, add a new app. The app's client secret is bound to the definition's token URL, its host and its path, by `POST`: Mehen sends it there and nowhere else. The token request and every refresh go to that `tokenUrl`, and the audit names the provider's host, never a token. Mehen checks the definition again at every connection and refresh, so one that today's rules refuse is never used.

Because Mehen knows nothing about the service, a connection made with it fails closed, like a key with no template: every request is held for your decision unless your defaults let reads through (`customReads`), and only reads. Mehen cannot ask the service who signed in, so the connection names no verified account; a reconnect with the same `slug` must use the same app. In this release a custom provider is added through the platform API only; Mehen's own pages for its people do not offer it yet.

## Deciding what Mehen holds

A credential's policy may hold a request for a decision: sending mail, deleting, paying, anything the catalogue marks. In a person's own workspace, a person approves on Mehen's page with a passkey. In yours, you decide.

When an agent's relay is refused with `approval_required`, the refusal names the approval (`approval`, `apr_...`); your agent passes it to your server. Read it, check its exact request against what your user agreed to, and decide with its digest:

```ts
// approvalId: the refusal's approval, which your agent sent you.
const held = await user.approvals.get(approvalId)
// held.request: method, url, contentType, headersSha256, bodySha256. held.title and held.warnings say what it does.
const decided = await user.approvals.decide(held.approval, { decision: "approve", digest: held.digest, ref: "card:5521" })
// The agent's workload relays again, naming decided.approval.
```

A decision is bound to the request's digest, serves one use of that exact request by the workload that asked, and lasts at most 15 minutes (less if your limits say so). A digest that is no longer the request's is a `conflict`: the request changed, ask again. The audit records your platform, your key and your `ref`. If your user has not agreed to that exact request, ask them first, and deny what they refuse.

`approvals.list({ status: "pending" })` lists what is waiting in one user's workspace.

## Environments for computers

For a task that runs programs, a sandbox say, give the user's workspace a project with one environment, set its plain settings and bind its keys:

```ts
const project = await user.projects.create({ slug: "computer", environments: [{ name: "default" }], defaultEnv: "default" })
await user.projects.setVar(project.id, "REGION", { env: "default", before: null, plain: "eu-west-2" })
await user.projects.setVar(project.id, "OPENAI_API_KEY", { env: "default", before: null, item: "openai" })
```

A workload scoped to that project starts a run; the task gets the plain settings as they are and, for each key, a placeholder that only Mehen turns back into the key, for the key's own hosts ([A project's environment for a hosted task](harnesses.md#a-projects-environment-for-a-hosted-task)). Every environment of a managed project is unprotected, with no four-eyes rule and no remote. Calling `projects.create` again with the same slug, environments and default answers the same project, so a creation whose answer was lost can simply be repeated; another shape under that slug is a `conflict`. `before` is the value you last read, `null` for unset: a stale one is a `conflict`, so two writers never overwrite each other unseen. A plain value that looks like a secret is refused; bind it as a key instead.

## Defaults, set once

```ts
await platform.defaults.put({
  providers: ["google-gmail", "github-oauth"],
  scopes: {},
  tags: ["myproduct"],
  customReads: "approve",
  rules: { "github-oauth": [{ action: "approve", methods: ["GET"], paths: ["/repos/*/*/contents/**"], note: "reading a repository's files" }] },
})
```

Your defaults say, for every workspace you have and will have: which catalogue templates (`templates`) and OAuth providers (`providers`) your users may add, leaving either out for the whole catalogue (a `templates` list must name the app templates too, such as `google-oauth-client`, for users to add their own app); the OAuth scopes a connection asks for when it names none; tags for every new credential; whether a key with no template may be read (`GET`, `HEAD`, `OPTIONS`) without a hold (`customReads`); and extra rules on any template or provider. A rule may only hold (`approve`) or refuse (`deny`), never allow, so your defaults can only make Mehen's catalogue stricter.

Workspaces read your defaults live, within 30 seconds, and you never copy anything into each one. A change makes approvals given under the old defaults stale. `platform.defaults.get()` answers the current defaults and their revision, as `view()` does.

## Limits

Users, devices, credentials, projects, open requests, calls and decisions all have limits, set when you are registered: [Platform API](../reference/platform.md#limits) lists them with their defaults. Past one, Mehen answers `quota_exceeded` or `rate_limited` (with `retryAfter`). Ask Mehen's operator to change a limit; it needs no deploy on either side.

## The audit, and freezing

```ts
const page = await user.audit({ limit: 50 })
// page.events, a page of rows; page.head and page.verified say whether the chain checked out; page.next is the cursor for the next page.
await user.freeze()
```

Every row in a user's workspace names your platform, whoever caused it. Rows you caused name your key; a decision's row names the approval's digest and your `ref`. `freeze()` stops every use of the user's credentials at once, and any of your devices may freeze too; only your platform unfreezes.

## Your platform in Mehen's web app

Your platform has no page in Mehen for your users, but it can have admins: people at your business with their own Mehen account and passkey, whom Mehen's operator adds to your platform (and removes). An admin sees a Platforms area in Mehen's web app listing only the platforms they administer. For yours they see its status and limits, read only; your users counted by status (being made, live, being deleted, deleted, purged), never their credentials; the last day's usage in counts; its recent events, including every change the operator or an admin made; its keys; and its defaults.

With their passkey for each change, an admin can:

- **Edit your defaults** with the same rules as `platform.defaults.put` (only stricter than the catalogue), from the revision they read; a change made meanwhile is refused rather than overwritten, and the revision moves.
- **Add a key**, pasting its public JWK or making the pair in the browser, which shows the private key once, as the base64url PKCS8 text your server's signer takes; Mehen never receives it. Your other keys keep working for the overlap the admin chooses, so you can deploy the new one first. The admin types your platform's slug to confirm, and Mehen's operator and your other admins are told: whoever holds the new key's private half is your platform until the key is revoked.
- **Revoke a key**, typing your platform's slug to confirm, but never your last live one: add the new key first.
- **Delete one user**, by the subject your platform knows, typed in with the slug, exactly as `platform.subjects.remove` does.

An admin cannot suspend, resume, retire or remove your platform, change its limits, or add other admins: those are the operator's. Nobody can see or act inside your users' workspaces through Mehen's web app, the operator included; a key added there, though, is your platform, with all it can do in them, until it is revoked. Every admin change is recorded in your platform's events with the admin's account.

## When a user leaves

```ts
const gone = await platform.subjects.remove(subject)
// gone.status is "deleted"; the audit is kept until gone.purgeAfter.
```

Deleting a user ends every device and workload at once, deletes every secret, hands Google tokens back to Google, and keeps the audit (which holds no secrets) for your retention period, 30 days unless your limits say otherwise; then the whole workspace is erased. GitHub and Microsoft grants stay at the provider until the user removes their app there or its tokens lapse. Repeating the call answers the same. The same subject may be used again once it is deleted, and gets a new, empty workspace.

`platform.subjects.removeAll("<your platform's slug>")` does the same for every user you have, a batch at a time; your platform stays registered.

Mehen cannot hand a user's credentials to them or anywhere else: tell your users to add their keys wherever they go next.

## When you leave

Mehen's operator retires your platform with notice: no new users from that day (`subjects.ensure` answers `platform_suspended`), everything else working until the date; from the date your calls are refused with `platform_suspended`, then every workspace is deleted as above and your keys are revoked. If your platform must stop at once, the operator suspends it: your calls stop at once and your devices' calls within 30 seconds, and nothing is deleted until it is retired.

To start again from scratch, the operator **removes** your platform: it is retired at once, every user's workspace is deleted and purged, your keys are revoked, and then your slug is free to register again, with a new platform id and a new key (a key once registered is never taken again). Your platform's record stays with Mehen: its registration, its events and, for each user, only a hash of the subject and the last link of their audit chain.

Nothing you kept from before names anything afterwards. Once a user's workspace is purged, Mehen no longer knows its devices, so an agent still signing with an old device key is refused with `unauthenticated`, not `device_revoked`; the old workspace, device and project ids are gone with it. After registering again, treat every user as new: `subjects.ensure` gives the same subject a new, empty workspace, and each agent needs a new device and each computer a new project. Your users add their credentials again.

## If your platform is compromised

Whoever holds your platform key, or controls your servers, can do what your platform can: create devices, use your users' credentials within their destinations and policies, and approve what Mehen holds, within your limits, and in the audit under your key. They cannot read a stored credential: in a managed workspace a credential's destination never changes and nothing returns a value.

Your own page is where users type keys, so a hostile page, or a hostile server opening a request for a host it controls, can capture keys typed while it is hostile. Mehen cannot see your page; nothing that lets a person type into someone else's page can prevent that. [Threat model: a platform](../security/threat-model.md#a-platform) says so for your security reviewer.

If your key leaks, tell Mehen's operator: they revoke the key or suspend your platform at once, and register a new key. Rotate routinely the same way: the operator adds your new key, and your old one keeps working for a day while you deploy.

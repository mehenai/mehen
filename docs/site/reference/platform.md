---
title: Platform API
question: What does each platform route take and answer, and how is a call signed?
section: reference
covers: cloud
order: 65
generate: platform
---

# Platform API

A platform is a business that serves its own users through Mehen ([Platforms and managed workspaces](../concepts/platforms.md)). It calls the vault at `https://app.mehen.dev`, under `/v1/platform`, with JSON in and out. [Build on Mehen](../guides/build-on-mehen.md) walks through the calls in order; `@mehen/client`'s platform client makes every one of them for you. The tables on this page are generated from the route table in Mehen's protocol, so they say what the vault named in the footer accepts.

## Signing a call

Every call carries a `Mehen-Platform-Proof` header: a compact JWS, signed with the platform's own P-256 key, over that one request. There is no bearer token, so nothing on the platform's disk or in a log can be replayed.

```text
header  { "alg": "ES256", "typ": "mehen-platform+jwt", "kid": "pky_..." }
payload { "plt": "plt_...", "sub": "<subject>", "htm": "POST", "htu": "https://app.mehen.dev/v1/platform/...", "bh": "<base64url SHA-256 of the body>", "iat": 1793270400, "jti": "<random>" }
```

| Claim | What it is |
| --- | --- |
| `kid` | The platform key's id, `pky_...`, which Mehen's operator gave the platform when it registered the key. |
| `plt` | The platform's id, `plt_...`. It must be the key's own platform. |
| `sub` | The subject the path names, on every route under `/v1/platform/subjects/:subject`, and absent on every other route. It must equal the path's subject. |
| `htm`, `htu` | The method, and the full URL with its query. |
| `bh` | The base64url SHA-256 of the exact body bytes, or of nothing for a request with no body. |
| `iat` | When it was signed, in seconds. The vault accepts 60 seconds either way. |
| `jti` | A random nonce. The vault accepts each one once. |

The proof's `typ` and header differ from a machine's `Mehen-Proof`, so neither can stand in for the other, and a platform call that also carries `Mehen-Proof` is refused with `bad_request`. The vault checks the proof in this order: the key by its id, with no cache; the signature, method, URL, body hash, time and subject; the platform's status; then the nonce, spent once per key, and the platform's limits. [Keys, proofs and signing](../security/keys-and-signing.md#platform-proofs) has the details.

## Subjects

A **subject** is the platform's own name for one of its users: 8 to 128 of `A-Z a-z 0-9 _ -`. Mehen never interprets it, and it is unique within its platform only: the vault finds a workspace from the verified platform and the subject together, so another platform naming the same string reaches its own workspace or none. Choose a subject that says nothing about the person, and never reuse one.

## Answers and refusals

A success is the JSON the route's table gives. Answers may gain members in later releases; read what you know and ignore the rest. No answer carries a secret value, a client secret, a token, a link to a Mehen page or a command to run.

A refusal is the error object of [Errors and exit codes](errors.md), with the header `Mehen-Error: 1` and the HTTP status that page gives its code. Two codes are only ever a platform's: [`platform_suspended`](errors.md#platform_suspended) and [`quota_exceeded`](errors.md#quota_exceeded).

In a managed workspace, a refusal a machine gets on the ordinary machine routes carries no link: `approval_required` names the approval and its binding code for the platform to decide, and `needs_reauth` says the platform reconnects the account. [HTTP surfaces](http.md#managed-workspaces) lists how each machine route answers there.

### subjects

How many subjects (users) the platform may have at once, counting those still being deleted.

### devicesPerSubject

Live devices in one subject's workspace. A revoked device no longer counts.

### itemsPerSubject

Credentials in one subject's workspace: keys, OAuth apps and connections together.

### projectsPerSubject

Projects in one subject's workspace. Each environment holds up to 500 variables, as everywhere in Mehen.

### openRequestsPerSubject

Requests for a credential and connections the platform has started in one subject's workspace and not yet finished or cancelled.

### callsPerMinute

Platform calls a minute, across all of the platform's subjects. A call is counted once its proof is verified; past it, `rate_limited`.

### subjectWritesPerMinute

Calls that change something, a minute, in one subject's workspace.

### decisionsPerMinute

Approvals and denials a minute, across all of the platform's subjects.

### subjectDecisionsPerMinute

Approvals and denials a minute, in one subject's workspace.

### decisionTtlSeconds

The longest an approval the platform gives may stay usable, in seconds. An approval always serves one use.

### auditRetentionDays

How long a deleted subject's audit is kept before the whole workspace is erased, in days. Secrets are deleted at once, whatever this says.

### defaults.put

The table gives a rule's `action` as the policy shape allows it; a platform's rule may only be `approve` or `deny`, and an `allow` rule is refused with `bad_request`. So are a template, provider or scope the catalogue lacks, and a tag given twice.

### intakes.create

`service` is one of three shapes. `{ template }` names a catalogue template: a key's, or a provider's app template such as `google-oauth-client`, whose answer carries the template's set-up steps in `setup`, each body possibly holding `{callback}` for the platform's page to replace with its own callback URL. `{ host }` is a key for one API host with no template; every request with it is held unless the platform's `customReads` lets reads through. `{ customProvider }` is the user's own OAuth app with its own provider definition: `authorizeUrl` and `tokenUrl` are https on a public host name, with no user name, password or fragment, and never an IP address or a private name; `authorizeParams` holds at most 8 names, none that Mehen sets itself; each scope and host appears once. The shape allows `clientAuth: "none"`, a public app with no secret, but the vault does not support one yet and refuses its intake with `bad_request`. The definition is fixed with the app, and the app's client secret is bound to the token URL's host and path, by `POST`, so it is sent nowhere else. A template outside the platform's `templates` default is `bad_request`. A `slug` the user already has is a rotation of that credential: of another kind or service it is `conflict`, and so is a different definition under an existing app's name. A rotation of a credential with no host answers `binding.hosts` as `["lease-only.mehen.invalid"]`: that reserved name means no host, since the vault never sends the credential to any service, so show it as no host.

### intakes.submit

Seal each field the intake marked `secret` under `intake/<intake>/<field>`, and send the others, such as an OAuth app's `client_id`, in `publicFields`. `terms` is the `binding` and `injection` (`null` for a kind never put into a request) the platform showed its user. It is required for an intake a device's workload opened for a new item with no template, whose binding and injection the workload proposed, and must equal them; with no proposed injection, the kind's usual one is the intake's. When the workload proposed no host, for a kind never put into a request, send `binding: { hosts: ["lease-only.mehen.invalid"] }` and `injection: null`. For any other intake it may be left out, and when sent it must equal that intake's own. Missing or different terms are `bad_request`, naming the fields that differ.

### connects.start

Name a catalogue `provider`, and optionally the `client`, the user's app for it (by default the app named after the provider's app template, such as `google-oauth-client`); or name only the `client`, an app with its own provider definition. `redirectUri` is the platform's own callback, exactly as the user registered it in their app. A `provider` outside the platform's `providers` default is `bad_request`. An existing connection's `slug` is a reconnect: for a catalogue provider, pinned to the same account at the provider; for an app with its own definition, through the same app. A device's own `POST /v1/connect` is refused with `forbidden` in a managed workspace: connections start here.

### connects.finish

Send the `state` and either the `code` or the provider's `error` from the callback, never both. Name the subject who is signed in to the platform at the callback, not the one the platform expects. A `completed` connection made with a catalogue provider names the account the provider verified; one made with an app's own definition names none.

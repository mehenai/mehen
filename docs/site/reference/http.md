---
title: HTTP surfaces
question: What does a client see on the wire?
section: reference
covers: both
order: 70
---

# HTTP surfaces

`mehen` is the supported client; nothing here is needed to use Mehen. This page is for reading what goes over the wire.

## Machine requests

Machines talk to the vault under `https://app.mehen.dev/v1/`. Every request from an enrolled machine carries a `Mehen-Proof` header, a signature over the method, the full URL and a hash of the exact body ([Keys, proofs and signing](../security/keys-and-signing.md#device-proofs)). There is no bearer token.

| Route | What it is |
| --- | --- |
| `POST /v1/enrol`, `GET /v1/enrol/:enrolment`, `POST /v1/enrol/:enrolment/renew` | Start an enrolment, poll it, renew its lease in place. Signed by the key being enrolled. The start may carry `scope`, the narrower scope the machine asks for ([Scoped enrolment](#scoped-enrolment)). |
| `GET /v1/me` | This machine's identity, owner, scope and state, and `ownerRole`: the workspace role of the member who owns it (`owner`, `admin`, `member` or `guest`), or `team` for a team's machine. Signed by a workload, it also carries `workload`: that workload's view. |
| `POST /v1/workloads`, `GET /v1/workloads`, `GET /v1/workloads/:id`, `POST /v1/workloads/:id/renew`, `DELETE /v1/workloads/:id` | Create a workload, list the live ones, read one, renew it, revoke it ([Workloads](#workloads)). Signed by the machine's own key only. |
| `GET /v1/items`, `GET /v1/items/:slug` | Items this machine may use, and one item's public description. |
| `POST /v1/relay` | One HTTP request through the vault relay. `replaces: "apr_..."` names an open ask of this machine (and workload) to the same credential, method, host and path that this request replaces when it is held: that ask then reads `superseded`. Refused with `forbidden` where deciding asks together is off. |
| `POST /v1/approvals/bundles`, `GET /v1/approvals/bundles/:id` | Ask for up to 20 relay requests at once, `{ requests, reason? }`, each as for `/v1/relay` without `approval` or `replaces`: the vault checks each without sending any and holds those that need a human in one bundle, answering `{ bundle, url, expiresAt, results }`. The `GET` answers `{ bundle, approvals: [{ id, status }] }`; `?wait=1` long-polls up to 25 seconds. Refused with `forbidden` where deciding asks together is off. |
| `POST /v1/fill` | One field of a credential for one web page, `{ item, field, origin, page, context?, approval?, recipient }`, sealed to `recipient`, the machine's throwaway public key: `{ box, item, field, input, label, origin, validUntil?, by }`. `mehen fill` calls it. |
| `POST /v1/push` | Ask for one secret field to be put into a provider's secret store ([Put a credential into another service](../guides/push.md)), `{ item, field?, to, with?, reason? }`, with `to` the destination as JSON in its canonical form. The answer is `approval_required` with the ask, or `{ push, item, field, version, destination, via, outcome, at }` when this machine did the same push in the last ten minutes. Never the value. `mehen push` calls it. |
| `POST /v1/mandates/proposals`, `GET /v1/mandates`, `GET /v1/mandates/:id`, `GET /v1/mandates/:id/uses`, `POST /v1/mandates/:id/pause` | Propose a mandate, list this machine's mandates and open proposals, read one, page through what went through on trust, pause one ([Mandates](#mandates)). Every route answers `not_found`, "No such route.", where mandates are off. `mehen mandate` calls them. |
| `GET /v1/policy/context?item=<slug>`, `POST /v1/policy/preview`, `POST /v1/policy/proposals`, `GET /v1/policy/proposals/:id`, `POST /v1/policy/proposals/:id/cancel`, `GET /v1/policy/rules`, `POST /v1/policy/rules/:id/revoke` | Standing rules and task grants: an item's policy as this machine meets it, what a rule from a held request would be, a proposal (a rule, or with `area` a task grant), its state (`?wait=1` long-polls), cancelling your own, this key's rules (`?item=<slug>` narrows, `include=grants` adds task grants) and revoking one. `mehen policy` calls them. Where standing rules are off, preview and propose answer `forbidden`, "Policy widening is not available yet." `GET /v1/policy/state` and `POST /v1/policy/grants/:id/revoke`, from the retired policy windows, always answer so, and `POST /v1/policy/overrides/:id/revoke` answers `not_found`. |
| `POST /v1/adoptions`, `POST /v1/adoptions/index`, `POST /v1/adoptions/:id/items`, `GET /v1/adoptions/:id`, `POST /v1/adoptions/:id/cancel` | Adoption batches: start one, send the plan's value-free index, upload items sealed to the vault into it, read where it stands (`?wait=1` long-polls) and cancel it. `mehen adopt submit`, `status` and `cancel` call them ([Bring a machine's credentials into Mehen](../guides/adopt.md)). |
| `GET /v1/backup/recipients`, `GET /v1/backup/status`, `POST /v1/backup/exports` | Backups: the workspace's backup keys, their status with your own keys' last export, and an export to one of your keys from an owner's machine, `{ export, ciphertext }` with the ciphertext in base64 and its SHA-256 in `Mehen-Backup-Sha256`; the machine only ever receives ciphertext. `mehen backup snapshot`, `status` and `export` call them ([Back up a machine before adopting](../guides/backup.md)). |
| `POST /v1/intakes`, `GET /v1/intakes/:id`, `POST /v1/intakes/:id/cancel` | Ask for a credential, poll the intake, cancel your own. |
| `POST /v1/connect`, `GET /v1/connect/:id`, `POST /v1/connect/:id/cancel` | Ask for an OAuth connection, poll it, cancel your own. |
| `GET /v1/approvals/:id` | Poll an approval; `?wait=1` long-polls up to 25 seconds. A push's approval also carries `push`: `{ destination, field, version, state, outcome?, providerStatus? }`, with `state` one of `pending`, `queued`, `sending`, `done`, `failed`, `not_sent` or `unknown`. |
| `GET /v1/pending` | This machine's own open asks, and the one notice a machine gets, that it was added to the workspace. Where deciding asks together is on, a `mehen` 0.3.17 or later also gets `groups`: `{ id, url, approvals, bundle }` for each review group holding two or more of those asks, with `bundle` false. |
| `POST /v1/projects`, `GET /v1/projects/:id`, `/v1/projects/:id/vars/:name` | Create a project, read it, set a variable. |
| `GET /v1/projects?remote=<remote>` | The project bound to a git remote (normalised as the vault binds remotes, so `git@github.com:acme/app.git` finds `github.com/acme/app`), when this machine may use it: `{ id, slug, defaultEnv, environments: [{ name, protected, variables }] }`, with variable names only, never a value or an item. A remote bound to no project, or to one this machine may not use (outside its scope, or not shared with its owner), is the same `not_found`. `mehen init` uses it to bind a checkout to its project. |
| `POST /v1/runs`, `POST /v1/runs/:id/renew`, `DELETE /v1/runs/:id`, `POST /v1/lease` | Start, renew and end a run; fetch a lease mid-run. The start and every renewal answer `expiresAt`, the deadline for the next renewal, and `endsAt`, the run's hard end, which renewal never passes (12 hours after the start, 2 for an approved protected run; `null` for a service run, started with `service: true` from a device whose scope has `serviceRuns`; absent from an older vault). A run's `remote` is the checkout's normalised `origin`, or `null` for none: `null` is `remote_mismatch` in a project that binds remotes, except from a workload whose scope names the project in `projects`, in an unprotected environment. |
| `POST /v1/freeze` | Freeze the workspace. |
| `POST /v1/devices/self/revoke` | Revoke this machine. |
| `GET /v1/seal-key` | Unauthenticated: the vault's public seal key, which browsers seal secret fields to. |

A [workload](../concepts/machines.md#workloads) calls the same routes as its machine, with its own proof, except the workload routes: only the machine's own key may call those. A workload's requests reach only its own scope, and its asks are its own.

## Workloads

The bodies and answers, as JSON:

```ts
type WorkloadScope = {
  items?: string[]     // item slugs, 1 to 64
  tags?: string[]      // 1 to 32
  projects?: string[]  // 1 to 32
  modes?: ("relay" | "sign" | "mint" | "placeholder" | "fill" | "lease")[]  // 1 to 6; fill needs mehen 0.3.17
}

// POST /v1/workloads, answered 201 with the WorkloadView
type WorkloadCreate = {
  jwk: { kty: "EC"; crv: "P-256"; x: string; y: string }  // the workload's public key
  label: string        // 1 to 120 of A-Z a-z 0-9 . : _ -
  ttlSeconds?: number  // 60 to 86400; 3600 when absent
  scope: WorkloadScope
}

// POST /v1/workloads/:id/renew: expiresAt becomes now + ttlSeconds, never past hardExpiresAt
type WorkloadRenew = { ttlSeconds?: number }

type WorkloadView = {
  workload: string     // wl_...
  device: string
  label: string
  thumbprint: string
  scope: WorkloadScope
  state: "active" | "expired" | "revoked"
  createdAt: string
  expiresAt: string
  hardExpiresAt: string  // createdAt + 7 days
  lastSeenAt: string | null
  revokedAt: string | null
  // device_revoked: its machine was revoked; owner_inactive: the machine's owner
  // was suspended, removed or left, or its team was deleted
  revokedBy: "device" | "member" | "device_revoked" | "owner_inactive" | null
}

// GET /v1/workloads: the live workloads only
type WorkloadList = { workloads: WorkloadView[] }  // at most 256
```

`DELETE /v1/workloads/:id` is idempotent and answers the view with `state: "revoked"`. A scope with a tag, project or mode outside the machine's is refused with `bad_request`, a `jwk` equal to the machine's key or a live workload's with `conflict`, and a 257th live workload with `rate_limited`. A workload holds at most five open asks (approvals, intakes and connections together) within its machine's 20; a sixth is refused with `rate_limited`. A workload whose scope sets `items` asks for an intake (`POST /v1/intakes`) or a connection (`POST /v1/connect`) only for a slug in them, else `forbidden`; a connection also needs the provider's OAuth client in `items` (the provider's client template, such as `google-oauth-client`, or `client` when the body names one), and is refused with `forbidden` saying "also list the provider's client" when it is missing. An intake or connection the workload could not then see is refused with `forbidden` before anything is created or counted: with `tags` in its scope, the request's `tags` (for a connection, `clientTags`) must include one of them, and with `projects`, a `project` home must be one of them; the message names what to add. A workload never creates a project (`POST /v1/projects` is `forbidden`), and `PUT /v1/projects/:id/vars/:name` from one needs its scope to cover both the credential the variable is bound to now and the one it binds, else `not_found`; setting, changing or unsetting a plain value (or binding over one) also needs the project in the workload's `projects`, else `forbidden`. A run a workload starts (`POST /v1/runs`) is that workload's: only it renews, ends, leases from or relays through it, and revoking the workload ends it; with the project in the workload's `projects` it may send `remote: null` even when the project binds remotes, except in a protected environment. A workload calling a workload route, or `POST /v1/devices/self/revoke`, is refused with `forbidden`, and so is `POST /v1/freeze`: only the machine's own key freezes. A workload's proof carries the `wkl` claim ([Workload proofs](../security/keys-and-signing.md#workload-proofs)); one that has ended is refused with `workload_ended`, and a machine that acts only through workloads refuses its own key everything but reading, the workload routes, freeze and self-revoke, with `workload_required`.

## Mandates

The bodies and answers, as JSON. A [mandate](../concepts/mandates.md) is signed by a person in the browser; a machine only proposes, reads and pauses.

```ts
type MandateClass = "read" | "change" | "send" | "delete"
type MandateCaps = Record<MandateClass, number>  // requests a UTC day; 0 for a class not ticked
type MandateSchedule = { tz: string; windows: { days: number[]; from: string; to: string }[] }  // days 0 (Sunday) to 6; 1 to 7 windows

// POST /v1/mandates/proposals, answered 201
type MandatePropose = {
  terms: {
    items: "all" | string[]     // credential slugs, sorted and each once, 1 to 200
    classes: MandateClass[]     // sorted and each once, always with "read"
    caps: MandateCaps           // 1 to the most for each ticked class: 50000, 10000, 500, 200
    ttlDays: 1 | 7 | 30 | 90
    schedule: MandateSchedule | null
    note: string                // 1 to 200
  }
  reason: string                // 1 to 200
}
type MandateProposalCreated = { id: string; url: string; expiresAt: string; existing?: true }

// GET /v1/mandates: newest first, at most 20, with this machine's open proposals
type MandateList = {
  mandates: MandateView[]
  proposals: { id: string; url: string; expiresAt: string; createdAt: string; device: { id: string; name: string }; classes: MandateClass[]; items: "all" | string[]; hiddenItems: number; reason: string }[]
}
type MandateView = {
  id: string                    // mdt_...
  device: { id: string; name: string }
  signer: { name: string }
  state: "active" | "paused" | "tripped" | "stopped" | "expired"
  rev: number
  items: "all" | string[]       // the slugs this machine can use now
  hiddenItems: number
  classes: MandateClass[]
  caps: MandateCaps
  today: MandateCaps            // used today, UTC
  ttlDays: 1 | 7 | 30 | 90
  schedule: MandateSchedule | null
  note: string
  createdAt: string
  expiresAt: string
  endedReason: "stopped" | "expired" | "replaced" | "revoked" | null
  proposal?: string | null      // the mdp_ it was signed from
}

// GET /v1/mandates/:id/uses?before=<cursor>: newest first, 100 a page
type MandateReceiptsPage = {
  receipts: { id: string; at: string; classes: MandateClass[]; method: string; credential: { slug: string; host: string; entry: string; run: string | null } | null }[]
  next: string | null           // the before= of the next page
}

// POST /v1/mandates/:id/pause, answered { mandate: MandateView }
type MandatePause = { rev: number }
```

A proposal with the same terms and reason as an open one of this machine answers that one with `existing: true`. A fourth open proposal is refused with `conflict`, carrying the newest one's link in `next.url`, and an eleventh in a UTC day with `rate_limited`. A workload may pause its machine's mandate but not propose or read one, and neither a team's machine nor a guest's machine may propose one; each is refused with `forbidden`, with `next.command` naming `mehen policy propose --from`. Pausing a paused or tripped mandate changes nothing and succeeds; pausing an active one at an old `rev`, or one that has ended, is `conflict`. A receipt's `entry` is the reviewed route, or `unreviewed`; its `credential` is null for a credential this machine cannot use now. The machine never sees whether its signer still stands behind a mandate.

## Scoped enrolment

`POST /v1/enrol` may carry `scope`, every field optional:

```ts
type EnrolRequestedScope = {
  tags?: string[]              // 1 to 32
  projects?: string[]          // 1 to 32
  modes?: ("relay" | "sign" | "mint" | "placeholder" | "fill" | "lease")[]  // 1 to 6; lease and fill are never granted at enrolment
  privateCredentials?: false   // no private credentials
  workloads?: "allowed" | "required"
}
```

The enrolment's scope is the workspace's default narrowed by it ([Scoped enrolment](../concepts/machines.md#enrolment)). Without `scope` the start is as it always was. `mehen enrol --tag`, `--project`, `--mode`, `--no-private` and `--workloads-only` build it.

## Platforms

A [platform](../concepts/platforms.md) calls the vault under `https://app.mehen.dev/v1/platform`, every request signed with a `Mehen-Platform-Proof` header, its own key's signature over the method, the full URL and a hash of the exact body ([Keys, proofs and signing](../security/keys-and-signing.md#platform-proofs)). Every route, its body, its answer and its refusals are in [Platform API](platform.md). The platform's devices then call the machine routes above, like any machine.

## Managed workspaces

A device a platform provisioned uses the machine routes in its user's managed workspace, with these differences:

| Route | In a managed workspace |
| --- | --- |
| `GET /v1/me`, `GET /v1/items`, `GET /v1/items/:slug`, `GET /v1/pending` | As everywhere. A device reaches every credential in the workspace. |
| `/v1/workloads` | As everywhere. |
| `POST /v1/relay` | As everywhere, with an item or a run. `approval_required` and `needs_reauth` carry no `next.url`, no command and no deciders: `next.say` says the platform decides the request, or reconnects the account. A held request waits for the platform's decision. |
| `GET /v1/approvals/:id` | As everywhere: only the workload that asked reads it. |
| `POST /v1/intakes`, `GET /v1/intakes/:id`, `POST /v1/intakes/:id/cancel` | As everywhere for a workload, with no `url` in the answer: the platform's page collects the value and the platform submits it. |
| `POST /v1/connect` | Refused with `forbidden`: the platform starts connections. |
| `POST /v1/push` | Refused with `forbidden`: a managed workspace has no pushing. |
| `GET /v1/connect/:id`, `POST /v1/connect/:id/cancel` | Every connection there is one the platform started, and it is `not_found` to a device. |
| `GET /v1/projects/:id`, `GET /v1/projects?remote=<remote>`, `/v1/runs` | As everywhere; a workload pinned to the project runs with `remote: null`. |
| `POST /v1/projects`, `PUT /v1/projects/:id/vars/:name` | As everywhere: a device that acts only through workloads may do neither with its own key. |
| `POST /v1/lease` | Refused: a managed device never leases, so a run there holds no lease to give, and the answer is `not_found`. |
| `POST /v1/freeze`, `POST /v1/devices/self/revoke` | As everywhere, with the device's own key. Only the platform unfreezes. |
| `/v1/enrol` | Never reaches a managed workspace: nobody enrols a machine into one. |

While the platform is suspended, every device call except freeze and self-revoke is refused with `platform_suspended`, within 30 seconds; while the user is being deleted, every device call is refused with `device_revoked`.

## Headers

| Header | Direction | Meaning |
| --- | --- | --- |
| `Mehen-Proof` | request | The machine's signature over this exact request. |
| `Mehen-Platform-Proof` | request | A platform's signature over this exact request, on `/v1/platform` only. A platform call that also carries `Mehen-Proof` is refused. |
| `Mehen-Error: 1` | response | The vault refused; the body is an error object ([Errors and exit codes](errors.md)). |
| `Mehen-Upstream: 1` | response | A relayed upstream response, never a vault refusal. |
| `Mehen-Item` | response | The item that acted, `<slug> (<account>)`, so the transcript says which account was used. |
| `Mehen-Rule` | response | On a relayed response a standing rule or task grant let through without asking: the `rul_...` ids, joined with `, `. A task grant is named only to a `mehen` 0.3.17 or later. |
| `Mehen-Posture` | response | On a relayed response how careful the credential is let through without asking: the levels, `routine` or `trust`, joined with `, `. |
| `Mehen-Mandate` | response | On a relayed response this machine's mandate let through without asking: its `mdt_...` id. A request a rule, task grant or posture let through never carries it. |
| `Mehen-Cli` | response | On every `/v1` answer: `minimum=<v>`, with `; recommended=<v>` when the vault has one: the published release once its signature verifies, or the version the vault's operator set when that is higher. A `mehen` below the minimum is refused with `cli_outdated` (HTTP 426), except freeze and self-revoke. |
| `User-Agent` | request | `mehen/<version>`. |

An upstream 403 and a vault refusal are never the same thing: only the vault's carries `Mehen-Error`.

## Errors

```ts
type ApiError = {
  error: ErrorCode
  message: string
  next?: { url?: string; command?: string; say: string }
  approval?: string
  bindingCode?: string
  choices?: { slug: string; account: string | null }[]
  retryAfter?: number
  expiresAt?: string
  deciders?: string[]
  transition?: ...
  mandate?: { id: string; capped: MandateClass[] }  // only with approval_required
  mandateCover?: { classes: MandateClass[]; state: "none" | "unticked" | "paused" | "tripped" | "ended" | "outside_schedule" | "not_covering"; mandate: string | null; url: string | null }  // only with approval_required, to a machine
}
```

Every code, its HTTP status and the exit code `mehen` gives it are in [Errors and exit codes](errors.md), and as JSON at [`/reference/errors.json`](/reference/errors.json).

## The release channel

Releases are served from `https://mehen.dev/dl/`:

| Path | What it is |
| --- | --- |
| `/dl/latest.json` | The signed manifest of the current release. |
| `/dl/v<version>/manifest.json` | One release's signed manifest: `{ version, commit, builtAt, files, signatures }`, each file with its name, platform, size and SHA-256, compressed and uncompressed. |
| `/dl/v<version>/mehen-<os>-<arch>.gz` | The binary, for `darwin` or `linux` on `arm64` or `x64`. |

`https://mehen.dev/install` is the installer for a machine with no `mehen`. Its last line is the receipt, `mehen-install: {"v":1,"result":"installed","version":...,"path":...,"onPath":...,"env":...,"rc":{...}}`, where `result` is `installed`, `already-installed` or `forced`. [Keys, proofs and signing](../security/keys-and-signing.md#releases) says how a release is checked.

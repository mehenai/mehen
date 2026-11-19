---
title: Errors and exit codes
question: What does each error mean, and what do I do?
section: reference
covers: both
order: 30
generate: errors
---

# Errors and exit codes

Every refusal from the vault is JSON with the header `Mehen-Error: 1`, so it can never be confused with a relayed upstream response, which carries `Mehen-Upstream: 1`. The shape is the wire contract:

```ts
type ApiError = {
  error: ErrorCode
  message: string
  next?: { url?: string; command?: string; say: string }
  approval?: string
  bindingCode?: string
  choices?: { slug: string; account: string | null }[]
  retryAfter?: number
  expiresAt?: string   // when next.url is a link that expires
  deciders?: string[]  // only with approval_required: who may decide, by name
  mandate?: { id: string; capped: ("read" | "change" | "send" | "delete")[] } // only with approval_required: the caps that held it
  mandateCover?: { classes: ("read" | "change" | "send" | "delete")[]; state: string; mandate: string | null; url: string | null } // only with approval_required, to a machine
  transition?: ...     // only with account_pending: the account security change in flight
}
```

With `--json`, `mehen` prints the error object on stdout and exits with the code in the table below; without it, the message, the `next` line and any ask block go to stderr. `mehen` adds `ask` to any error that carries a link it accepted, with the enrolment that made the failing call on `ask.context`. A failure that starts on this machine has the same shape.

`next` is the fix, and you should always use it:

| Field | What to do with it |
| --- | --- |
| `ask` | The block to write for your human, when a human must open something. Build the message from it. |
| `next.say` | One sentence written for your human, for anything that has no `ask`. Relay it as it is. |
| `next.url` | A page a human must open. Send it to them; never open or drive it yourself. |
| `next.command` | A command you can run to continue, usually `mehen wait <id>`. Run it. |
| `approval`, `bindingCode`, `expiresAt` | The approval id, the code the human will see on the approval page, and when it expires. |
| `choices` | The OAuth clients that could serve, when `mehen connect` finds several. |
| `retryAfter` | Seconds to wait before retrying a transient failure. |

Refusals include a reason. When the vault sent no `next`, `mehen` fills in the step for its code (the default next in the table below, for example `mehen doctor` for `proof_invalid` and `mehen ls` for `not_found`); some of those steps are a sentence of advice rather than a command, and a local error from `mehen` itself may have `next: null`. Some problems need a human to repair the setup. `expiresAt` comes with every link that expires and with every status `mehen wait` polls.

A started `mehen run` exits with its child's own code. When `mehen run` stops the child itself it uses these codes instead: 7 at the run's maximum life, when its sources changed (`conflict`) or when no renewal succeeded in time, and otherwise the exit code of the refusal that ended the run, such as 6 for `device_revoked` ([Keep a service running with mehen run](../guides/services.md#exit-codes)).

Never guess around a refusal. Do not retry it with a different host, a different item, a body-encoded token, an encoded path or a rephrased URL. The refusal is the vault working.

### Exit 0

**Meaning.** OK

**What you do.** Carry on.

### Exit 1

**Meaning.** Error

**What you do.** Read `error` and `message`. Something is missing or broken; report it.

### Exit 2

**Meaning.** Usage

**What you do.** Fix the command or the request. Also the local workspace selection refusals (`workspace_unknown`, `workspace_mismatch`, `context_ambiguous`, `workspace_unbound`, `workspace_not_allowed`, `config_dir_retired`, `pin_outdated`), which happen before anything is signed or sent; fix the selection. An activation mismatch is different: it is reported after a vault response and an attempted cleanup, so exit 2 alone does not prove no network call occurred. Read the error's outcome: it says whether the new device's revocation succeeded, and if it did not, keep the device id visible so a human can revoke it.

### Exit 3

**Meaning.** Approval required

**What you do.** Write the human the block from `ask` (the check is the binding code), then `mehen wait <approval>`, then repeat the same request. `mehen check` also exits 3 to say a request would need approval.

### Exit 4

**Meaning.** A human must act

**What you do.** Write the human the block from `ask`, then wait (`next.command` when given). Also: `mehen wait` timed out, a connection signed in as the wrong account, `mehen connect` found no OAuth client (`client_missing`), the human must sign in with Google in the workspace (`identity_required`), their account's security change is still settling (`account_pending`), this machine's owner is not an active member (`owner_inactive`), or the project is not shared with them (`project_unshared`).

### Exit 5

**Meaning.** Refused by rule

**What you do.** Retrying will not help. Tell the human what was refused and why; only they can change bindings, policies, ceilings, scopes or fences. Also: the human denied an approval or rejected an enrolment, and `mehen check` saying a request would be refused.

### Exit 6

**Meaning.** Identity

**What you do.** This machine's identity was not accepted. Check `mehen status`: not enrolled in this workspace, revoked, a bad proof (often a clock more than 60 seconds off), a device key file other users can read, or a key made for another vault.

### Exit 7

**Meaning.** Transient

**What you do.** Network, upstream or rate limit. Retry, after `retryAfter` seconds when given. No connection to the vault at all is also 7, and so is a `mehen run` that stopped its child at the run's maximum life: start it again.

### `bad_request`

**What it means.** The request was malformed or failed validation: an unknown provider, a template of another kind, a new item without a template or proposed binding, a run naming variables the vault does not know, a plain value that looks like a secret, a request with nothing for the relay to do.

**What you do.** Fix it as the message says; `mehen <command> --help` shows the options.

### `ambiguous`

**What it means.** Reserved: several items could serve. The vault does not raise it today, because every request names its item.

**What you do.** Pick one slug from `choices`; if you are not sure which account is meant, ask the human.

### `unauthenticated`

**What it means.** No proof, or this machine is not enrolled.

**What you do.** Run `mehen status`; the machine may need `mehen enrol --workspace <slug>`.

### `proof_invalid`

**What it means.** The vault did not accept this machine's signature: clock skew over 60 seconds, a replay, or a URL, method or body that does not match what was signed.

**What you do.** Check the machine's clock; `mehen doctor` checks the clock and the key. Do not hand-craft requests; use `mehen`.

### `device_revoked`

**What it means.** This device was revoked.

**What you do.** Stop. Tell the human; only they can let it enrol again.

### `device_pending`

**What it means.** This machine's enrolment has not been accepted yet.

**What you do.** Write the human the enrolment block (`mehen pending` shows it again), then `mehen wait <enrolment>`.

### `owner_inactive`

**What it means.** The member who owns this machine is suspended, removed or not yet confirmed, or its team is gone; a machine never outlives its owner's standing.

**What you do.** Stop. Tell the human; an owner or admin must act on the membership.

### `identity_required`

**What it means.** The workspace requires a verified Google identity for the human's role, and their sign-in is not fresh enough for what was asked. It is raised to humans in the browser, and reaches a machine only through an operation that needed the human's standing.

**What you do.** Tell the human to open `https://app.mehen.dev/w/<slug>/` and complete the sign-in it asks for, then repeat the step. You cannot clear it yourself.

### `account_pending`

**What it means.** The human's account has a security change (a recovery, a factor removal) still being installed across their workspaces; anything that widens access waits until it has.

**What you do.** Wait; the human can see it on their account page.

### `project_unshared`

**What it means.** The project in `mehen.toml` exists but is not shared with this machine's owner, or no longer is.

**What you do.** Ask an owner or a project manager to share the project with this machine's owner.

### `intake_required`

**What it means.** Reserved: the credential does not exist yet. The vault answers `not_found` today.

**What you do.** Ask the human for it with `mehen request`, write them the block, then `mehen wait <intake>`.

### `needs_reauth`

**What it means.** The OAuth connection is dead (revoked, expired, password changed, client secret rejected), or the item must be replaced.

**What you do.** Write the human the block (a reconnect link pinned to the same account, with `expiresAt`), then `mehen wait`. When the vault's link is the item's own page (a broken OAuth client, or a non-OAuth item that must be replaced), the block opens that page and has no wait: the human replaces the credential there, then you try again.

### `frozen`

**What it means.** The whole workspace is frozen: every use is refused until an owner unfreezes it.

**What you do.** Stop. Tell the human; they review the audit log and unfreeze it in the vault.

### `approval_required`

**What it means.** A human must approve this exact request: a send, a delete, a production run, any use of a protected item. The error carries the approval id, the link, a binding code, `expiresAt` and `next.command`, `mehen wait <approval>`. When a [workload](../concepts/machines.md#workloads) asked there is no `next.command`: `mehen wait` signs with the machine's own key, which cannot see a workload's approval, so the task waits with its own key (`GET /v1/approvals/:id`, or `approval(id, { wait })` in `@mehen/client`).

**What you do.** Tell the human in one message what you are trying to do, then write the block from `ask`; the check is the binding code. Run `mehen wait <approval>`, and when it is approved repeat exactly the same request from the same machine (the same item, method, URL, headers and body). If it is denied or expires, stop and ask the human what they want instead; do not retry in a loop.

Where [mandates](../concepts/mandates.md) are on, two more fields may come with it. `mandate: { id, capped }` means this machine's mandate would have let the request through but for the caps named; `mehen fetch` says which in words, "This machine's mandate has used today's 50 sends.", and the request can go through on trust again the next UTC day. `mandateCover` means a mandate could let requests like this through: `classes` are the kinds it would need, and `state` (`none`, `unticked`, `paused`, `tripped`, `ended`, `outside_schedule` or `not_covering`) says where this machine's mandate stands, with its id and page in `mandate` and `url`. Only a machine whose owner could sign a mandate gets it, never a workload, and never beside `mandate`. Propose a mandate only for `none` or `unticked`, the third time the same kind of ask carries it; for the other states, hand the person `url` ([Agent reference](agent-reference.md#when-a-request-asks-mandatecover)).

### `forbidden`

**What it means.** This device's scope or its owner's rights do not cover the item, project or action (a guest's or a team's machine creating a project, a machine limited to named projects running `mehen init`, a workspace home proposed by a member's machine), the item is disabled or never sent by the relay, a method-override header or parameter was sent, or only an owner or admin may do this. It is also how the vault answers a feature that is off for the workspace: "Standing rules are not switched on for this workspace yet." (`mehen`'s words; over HTTP the vault's own message is "Policy widening is not available yet."), "Typing into web pages is not available in this workspace.", "Asking for several requests at once is not available yet." (`mehen plan submit`) and "Replacing an ask is not available yet." (`--replaces`). For mandates it says "The platform decides what each machine may do without asking." in a managed workspace, "A workload has no mandate" to a workload that proposes or reads one (it may still pause its machine's), and "A team's machine cannot have a mandate yet" to a team's machine, both with `next.command` naming `mehen policy propose --from`. A machine's mandate proposal that names every credential, a credential or class besides read it has not asked for in the last 30 days, more than 30 days or a cap above 500 reads, 100 changes, 10 sends or 5 deletes a day carries `mandateRefused`: `items_all`, `item_unasked`, `class_unasked`, `term_too_long` or `caps_too_high`; the message says what to drop or lower, and `next.command`, when there is a valid bounded retry, proposes the same terms cut to what is allowed, with the same hours. `next.command` is optional: it is left out when there is none, for example when the machine asked for nothing, when the retry would name more than 200 credentials, or when an explicit list shares no credential with what it asked for; `next.say` then says what to do. A task grant the vault will not start carries `areaRefused`: `area.unreviewed`, `area.not-routine`, `area.live-key` or `area.terms` (ask for each request instead), `area.unknown` (an area not on the service's list), or `area.duration` and `area.uses` (a duration or number the vault does not take).

**What you do.** Tell the human; only they can widen a scope or a share. When a feature is off, carry on without it: ask for each request, send requests one by one, or send the request again without `--replaces`. After `area.unknown`, `area.duration` or `area.uses`, pick again from [Agent reference](agent-reference.md#task-grant-areas) and propose again. After `mandateRefused`, propose again without what the message names, or run `next.command`; do not try wider terms, which only the person signing may choose.

### `binding_refused`

**What it means.** The destination is outside the item's binding, or the URL is one the vault will not guess at: an encoded slash, dot or backslash, `..`, `//`, a username in the URL, a scheme other than http or https, or an IP address or loopback name not bound exactly.

**What you do.** Use a host and a plain URL from `mehen show <item>`. If the host really is needed, ask the human to change the binding; only they can.

### `surface_refused`

**What it means.** A run's placeholder appeared outside its item's declared header or query parameter, or at a host it is not bound to. It is recorded as a tripwire.

**What you do.** Remove the placeholder from the body, query or header it is in; the vault injects the credential itself.

### `policy_denied`

**What it means.** The item's policy denies this method or path.

**What you do.** Do not work around it. Use the alternative the template names, or tell the human what you tried.

### `mode_refused`

**What it means.** The item's exposure ceiling does not allow this use, a lease was asked for that the item, the device or the run does not allow, or a request that needs approval cannot be shown in full (a compressed body, a body over 64 KiB, a command line over 4096 characters).

**What you do.** Use relay (`mehen fetch`) or placeholders (`mehen run`), and send anything that needs approval uncompressed and small.

### `environment_refused`

**What it means.** A protected environment without a literal `--env`, a device allowed for it or an owner with the protected right; a protected credential used without a project context naming the protected environment that references it, or outside an approved protected run; an agent setting a protected variable; an OAuth client a protected environment relies on, used by anyone but an owner or admin; or a host fenced to another environment.

**What you do.** Use an unprotected environment, or type `--env <name>` and expect an approval; give `mehen fetch` the context with `--project <prj_id> --env <name>`. For a fence, run in the environment the host belongs to.

### `remote_mismatch`

**What it means.** This checkout's `origin` remote is not the one bound to the project id in `mehen.toml`.

**What you do.** Check you are in the right clone.

### `refresh_retrying`

**What it means.** The provider did not answer the vault's token refresh: a transient OAuth failure.

**What you do.** Retry after `retryAfter` seconds.

### `rate_limited`

**What it means.** Too many requests; also this machine's 20 open asks, too many unavailable names tried in an hour, or an eleventh mandate proposal in a UTC day ("This machine has proposed 10 mandates today; try again tomorrow.").

**What you do.** Slow down, settle an open ask, and retry after `retryAfter` seconds when given.

### `upstream_failed`

**What it means.** The vault could not reach the upstream, or the upstream answered in a compression the vault cannot check for leaked credentials. In the compression case the request itself was sent.

**What you do.** Retry later; in the compression case, check whether the request took effect before sending it again.

### `not_found`

**What it means.** No such item, intake, approval, connection, project, run, mandate or route, or one outside this machine's reach: another member's private credential, a project not shared with your owner, a workspace credential from a guest's or a team's machine, another machine's mandate. Absent and out of reach answer the same, so nothing can be learnt by naming. Where mandates are off, every mandate route answers "No such route.", which `mehen mandate` turns into "This workspace has no mandates: they are not switched on here, or this vault is older than them."; do not propose one again. `mehen mandate pause` with no id, on a machine with no live mandate, answers that there is nothing to pause.

**What you do.** Check the slug or id with `mehen ls`; ask for a missing credential with `mehen request`.

### `conflict`

**What it means.** The request clashes with existing state: a name not available (in use anywhere in the workspace, including by a credential you cannot see), an item of another kind, a project or remote already taken, or an open intake or connect for the same slug with other details, from this machine or another; or a rotation proposing a different home. A request a standing rule or task grant let through gets it, "The rule that allowed this request has ended; send it again to ask for approval.", when the rule ended or ran out of uses as the request went through. A request a mandate let through gets "This machine's mandate changed since this request was checked; send it again." when the mandate was paused, reached a cap or changed between the check and the send. Mandates also answer `conflict` when a machine already has 3 proposals waiting (with the newest one's link in `next.url`; `mehen mandate ls` lists them all), when pausing names an active mandate at an old revision, or one that has ended, and when `mehen mandate pause` with no id finds more than one live mandate.

**What you do.** Pick another slug, wait on the open link (`mehen pending` lists this machine's), or ask again with `--new` to replace your own. When a rule ended, send the same request once more: it asks for approval. When a mandate changed, send the request once more; it goes through on trust or asks. With 3 proposals waiting, hand the person the newest link rather than proposing again.

### `too_large`

**What it means.** The request or the upstream's response is too large; responses are capped at 32 MiB.

**What you do.** Send or ask for less.

### `internal`

**What it means.** Something broke inside the vault, or inside `mehen`.

**What you do.** Retry once; if it happens again, tell the human the time it happened. For a failure inside `mehen`, `mehen doctor` checks this machine.

### `cli_outdated`

**What it means.** An identified `mehen` is below the vault's minimum supported version (HTTP 426); freeze and self-revoke are exempt. The vault refused the request before doing anything.

**What you do.** Follow the returned `next`: after `mehen` has updated itself, it names the original command to run again; if the update did not run or failed, run `mehen update --json`, report any refusal, and never reinstall to get round a signature failure.

### `workload_ended`

**What it means.** The workload that signed the request has expired or was revoked, by its machine, by a person on the machine's page, or because the machine itself was revoked or its owner lost standing on it. Nothing it asked for can be used any more.

**What you do.** Stop the task. The harness that runs it creates a new workload if the task should go on; a workload is never renewed after it has ended.

### `workload_required`

**What it means.** This machine was enrolled to act only through workloads, and its own key asked for something only a workload may do: a relay, an ask, a run or a policy change.

**What you do.** Make the request from a workload the harness created for the task. The machine's own key may still read, manage its workloads, freeze and revoke itself.

### `platform_suspended`

**What it means.** The platform this call comes from, or the platform a managed workspace belongs to, is suspended or retired by Mehen's operator, or is retiring and may not add a user. A platform's own calls stop at once; its machines' calls stop within 30 seconds. See [Platforms and managed workspaces](../concepts/platforms.md).

**What you do.** Stop and tell the human. Nothing a machine or an agent does clears it: only Mehen's operator resumes a platform, and a platform talks to the operator directly.

### `quota_exceeded`

**What it means.** The request would go past one of the platform's limits: its users, or one user's machines, credentials, projects or open requests. The operator sets the limits when the platform is registered, and every managed workspace reads them live.

**What you do.** Remove something that is no longer needed, such as a revoked machine, an old credential or an open request, and try again. If the limit is too low, the platform asks Mehen's operator to raise it.

### `origin_mismatch`

**What it means.** The web page is not one this credential may be typed into: not one of its sign-in pages, or not one of the other pages a human listed for it. No approval can allow a page that is not listed. `mehen fill` also gives it, without asking the vault, for a field whose page is not https or has an IP address for a host.

**What you do.** Do not try another page or another spelling of the address. If the page is right, ask the human to add it on the credential's page.

### `totp_unreadable`

**What it means.** A one-time code secret is not a base32 secret or an `otpauth://totp` link the vault can read: it is a counter-based or Steam code, it is shorter than 80 bits, or it names an algorithm, a number of digits or a period the vault does not support. Nothing was saved.

**What you do.** Ask the human to enter the secret again, exactly as the site showed it when they set up the code.

### `provider_refused`

**What it means.** A [push](../guides/push.md) reached a provider (GitHub, Vercel or Cloudflare) and the provider refused it: the token is invalid or expired, may not write there, cannot see the destination, or the provider rejected the name. `providerStatus` is the HTTP status the provider answered, and the message says what it means in Mehen's words. `mehen push` gets it when the vault's check of the destination, before anyone is asked, is refused; `mehen wait` gets it when the provider refused the approved push, which spends the approval. Only `mehen` 0.3.18 or later sees this code: an older `mehen`, or a caller of `POST /v1/push` whose `User-Agent` does not name 0.3.18 or later, gets `upstream_failed` with the same message.

**What you do.** Tell the human. Pushing again changes nothing until the token's access, the destination or the name is fixed.

### `usage`

**What it means.** Bad arguments; also `mehen connect` finding several OAuth clients, with `choices`.

**What you do.** Run `next.command`, the command's `--help`, and fix the arguments; with several OAuth clients, name one with `--client`.

### `network`

**What it means.** The vault could not be reached.

**What you do.** Check the network connection and the vault URL (`MEHEN_VAULT_URL`), then retry. With `mehen fetch --max-time`, the request may still have reached the upstream: check before sending it again.

### `timeout`

**What it means.** `mehen wait` ran out of time while a human has not acted.

**What you do.** Run `next.command` again; the ask comes back with the error so you can relay it again. A connect link the human signed in to with an unexpected account also ends this way: ask them what the callback page said.

### `stale`

**What it means.** `mehen wait` found the approval or policy proposal stale: access changed under it (a share expired, a role changed, a protected reference was added, the decider lost their basis).

**What you do.** Do not repeat the old approval; follow `next` and ask again from the start.

### `superseded`

**What it means.** A newer ask from this machine to the same place replaced the approval, so it was never decided; `replacedBy` names the newer one. That happens when a request was sent with `--replaces` (MCP `replaces`) naming it.

**What you do.** Wait on the newer ask with the `mehen wait` command in `next`; do not ask again.

### `denied`

**What it means.** The human denied the approval.

**What you do.** Do not retry without asking them what they want instead.

### `rejected`

**What it means.** The human rejected this machine's enrolment, or five wrong hidden groups were typed on its page.

**What you do.** Stop and tell the human; enrol again only when they ask you to.

### `mismatch`

**What it means.** `mehen wait` reports it when a connect link's status says the human signed in as an account other than the one expected. In the current release the vault does not record that status: it refuses an unexpected account at the provider's callback with `forbidden`, overwrites nothing, and the link stays open, so the wait goes on until it times out or the link expires.

**What you do.** Ask the human what the callback page said, tell them which account was expected, and start a fresh connection with `--new` before relaying a new link.

### `client_missing`

**What it means.** `mehen connect` found no OAuth client for the provider. `request` and `setup` carry the exact arguments for the client and the redirect URI.

**What you do.** Run `next.command`, the exact `mehen request oauth-client ...`, or repeat the connect with `--request-client` to ask for the client and the connection at once.

### `expired`

**What it means.** An intake, approval, connection or enrolment expired.

**What you do.** When this machine asked, `next.command` is the exact command to run again (for an enrolment, `mehen enrol --workspace <slug>`); run it and relay the new link.

### `cancelled`

**What it means.** An intake, approval, connection or enrolment was cancelled. An intake you replaced with `--new` is `cancelled`.

**What you do.** Ask the human before asking again; `mehen pending` lists a newer link when you made one.

### `failed`

**What it means.** An intake, approval, connection or enrolment failed; also another `mehen` holding a lock for 30 seconds (the message names its process id), and an unfinished migration of `MEHEN_HOME`.

**What you do.** When this machine asked, run `next.command`. For a lock, retry shortly. For a migration, `next.command` is `mehen doctor --json`: run it and tell the human.

### `upstream_status`

**What it means.** `mehen fetch --fail` was used and the upstream answered 4xx or 5xx.

**What you do.** Read the status and the body; the request reached the upstream.

### `already_enrolled`

**What it means.** The vault activated a second device for a workspace this machine already holds a device in. Nothing was revoked or deleted.

**What you do.** Relay `next.say`, which names both devices and how to keep one.

### `not_available`

**What it means.** The Secure Enclave helper is missing.

**What you do.** Enrol with `--backend software`, or ask the human to fix the helper.

### `helper_failed`

**What it means.** The Secure Enclave helper failed.

**What you do.** Enrol with `--backend software`, or ask the human to fix the helper.

### `key_insecure`

**What it means.** The device key file, a file beside it or the state directory is a symlink, is owned by someone else, or can be read by other users; or this user's home directory in the system's user database cannot be found or is unsafe, so `mehen` cannot tell whether the host is managed.

**What you do.** The message says which; follow `next`, and tell the human when it is theirs to fix.

### `key_scope`

**What it means.** The device key on disk was made for another vault. Once a workspace is selected, a key scope naming another origin or workspace is `workspace_mismatch` instead.

**What you do.** Run `next.command`, `mehen enrol --workspace <slug> --fresh-key`, or set `MEHEN_VAULT_URL` back.

### `command_failed`

**What it means.** A `mehen env` call made through `vault_env` failed.

**What you do.** The message says why and names the fix.

### `cdp_unreachable`

**What it means.** `mehen fill` could not reach the browser: nothing answered at the endpoint, the profile has no `DevToolsActivePort`, the connection closed, or the browser did not answer within 10 seconds. Nothing was typed.

**What you do.** Check that the browser is running with remote debugging on and that the endpoint is current (it changes each time Chrome starts), then retry.

### `page_changed`

**What it means.** The page changed while `mehen fill` worked on it: the field went away, or its frame navigated or moved, between the check and the typing, or before the Enter of `--submit`. `cleared` says whether mehen emptied a field it had already typed into.

**What you do.** Look at the page as it is now, then run the fill again.

### `cdp_refused`

**What it means.** The endpoint is not one `mehen fill` uses: plain `ws://` to another machine, a page's own endpoint (`/devtools/page/...`), or anything but `ws://127.0.0.1:<port>/devtools/browser/<id>`, `http://127.0.0.1:<port>`, a `wss://` URL or `--user-data-dir`.

**What you do.** Give the browser's own endpoint in one of those forms.

### `target_ambiguous`

**What it means.** The browser has several pages, or none, and no `--target` said which one to fill; or `--target` names no page of this browser.

**What you do.** Give `--target` the target id of the page you are driving.

### `field_ambiguous`

**What it means.** `--selector` matches more than one element, in one frame or across the page's frames, or at one of its shadow hops.

**What you do.** Make the selector match exactly one field.

### `field_not_found`

**What it means.** `--selector` matches no element in any frame of the page, or a shadow hop (` >>> `) reaches an element with no open shadow root. A field inside a closed shadow root cannot be filled.

**What you do.** Check the selector against the page as it is now.

### `not_submitted`

**What it means.** `mehen fill --submit` pressed Enter in the field and, within 10 seconds, the page did not navigate, change its address or remove the field. mehen then emptied the field; `cleared` says whether that worked.

**What you do.** Submit the form the way the page expects, for example with its button, then check the result. Fill again first when `cleared` is true.

### `field_kind_mismatch`

**What it means.** The field is not the kind the value is for: a password goes only into a password field that is not for a new password, a username into a text or email field for a username or email, a one-time code into a field for a code, and another secret into a text or password field or a text area.

**What you do.** Point `--selector` at the right field. Do not look for another way to type the value.

### `field_hidden`

**What it means.** The field is disabled, read-only, hidden, transparent or covered by another element at its centre, or it did not take the focus.

**What you do.** Bring the field into view (close what covers it, open the step of the form it is on), then fill again.

### `frame_origin_mismatch`

**What it means.** The field is in a frame inside a page of another origin, or the page's own address differs from the frame's, or the browser and the page do not agree about the frame's ancestors. In this release mehen types only into a frame whose every ancestor has the frame's own origin, so a sign-in form embedded from another site is refused.

**What you do.** Open the sign-in page itself, not a page that embeds it, and fill there.

### `pin_outdated`

**What it means.** A managed host's agent configuration is out of date. Selection fails closed; nothing is signed or sent.

**What you do.** This host uses an outdated managed-agent configuration. Stop and contact the harness owner. Relay the refusal and its next step; do not edit the pin, identity files or launch environment yourself.

### `workspace_unbound`

**What it means.** The checkout's `mehen.toml` names no `workspace`, and this machine is enrolled in more than one.

**What you do.** Run `mehen workspace bind` in the checkout.

### `workspace_mismatch`

**What it means.** Two things name different workspaces or origins: the selector and the manifest, `MEHEN_VAULT_URL` and the enrolment, the key scope and the config, a `vault_env` cwd and the server's workspace, or a selection on a managed host that is not its pin; nothing is signed or sent. Also an enrolment the vault activated in another workspace, with another owner kind or an incomplete scope than asked, or into a directory another enrolment took meanwhile: `mehen` has then contacted the vault, attempted to revoke the new device and written no config.

**What you do.** Give one selection and fix the other. After an enrolment mismatch, read the message: it says whether the revocation succeeded, and when it did not it names the device for a human to revoke.

### `workspace_unknown`

**What it means.** No enrolment on this machine is in the workspace named by `--workspace`, `MEHEN_WORKSPACE` or the checkout's `mehen.toml`.

**What you do.** Run `next.command`, `mehen enrol --workspace <slug>`, or `mehen wait <enrolment>` for a pending one.

### `context_ambiguous`

**What it means.** Several workspaces could serve and nothing selects one. Also a bare entry of `MEHEN_WORKSPACES` that matches workspaces at two vaults.

**What you do.** Name one with `--workspace <slug>`; `next.say` lists them. Never pick a workspace on the human's behalf. For the `MEHEN_WORKSPACES` case, the human writes the entry as `<vault>/<slug>`.

### `workspace_not_allowed`

**What it means.** The workspace named is outside `MEHEN_WORKSPACES`.

**What you do.** Tell the human, who changes the harness; nothing inside `mehen` widens it.

### `config_dir_retired`

**What it means.** The harness sets `MEHEN_CONFIG_DIR`, a retired variable, pointing inside Mehen's state or disagreeing with `MEHEN_HOME`.

**What you do.** Relay `next.say`, which names the `MEHEN_HOME` to set instead; tell the human.

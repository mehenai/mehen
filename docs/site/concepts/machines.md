---
title: Machines
question: What is a machine, and what may it do?
section: concepts
covers: both
order: 20
---

# Machines

A **device** is an enrolled machine in one workspace. A computer can be enrolled in several workspaces; each enrolment is a separate device with its own key and scope.

## Owners and keys

A device is **owned** by the member whose machine it is, or by a team. It holds an ES256 (P-256) key:

| Backend | Where | Key storage |
| --- | --- | --- |
| `secure-enclave` | macOS on Apple silicon, chosen by default; the Secure Enclave helper is embedded in the macOS binary and extracted under `MEHEN_HOME/bin` on first use | A non-exportable Secure Enclave key. Only an enclave-wrapped blob sits in a 0600 file. Keys use "after first unlock" protection so background agents can sign while the screen is locked. |
| `software` | Linux, CI, containers, or `--backend software` | A P-256 key in a 0600 file in the workspace's directory on the machine. `mehen` refuses a key file that other users can read. |

There is no bearer token. Every machine request carries a proof signed by this key ([Keys, proofs and signing](../security/keys-and-signing.md#device-proofs)). A key belongs to one workspace at one vault: its scope file records both, a key made for another is never reused, and the same computer enrolled in two workspaces holds two keys in two slots.

Key and configuration files must be regular files, owned by this user, private and not symlinks. Mehen makes an owned state directory private if its permissions are too wide. The ledger's rules differ: an unsafe or symlinked ledger is not trusted as existing state, and is read as empty and replaced.

**A platform's devices.** In a [managed workspace](platforms.md), the platform provisions a device for each of its agents by registering the agent's public key: there is no enrolment page and nobody accepts it. Such a device may only relay and serve placeholders, acts only through workloads, has no private credentials, and reaches every credential in its workspace within those limits. From then on it uses the same proofs, workloads, relays and runs as any machine.

## Enrolment

1. **The machine asks.** `mehen enrol --workspace <slug> --name my-laptop` (`--team <team-slug>` for a machine a team will own) reuses the key in the workspace's slot when it can vouch for it, otherwise it creates one; `--fresh-key` always creates one. A key is scoped to the vault and workspace it was made for: with another `MEHEN_VAULT_URL` it is refused with `key_scope`, never overwritten.
2. **The vault answers with a link.** It returns an 8 character code, the link `https://app.mehen.dev/w/<slug>/e/<code>`, a lease that ends in 60 minutes and a hard cap 24 hours out. `--connect <code>`, with a connect code from the workspace's Connect an agent page, **claims** the attempt for that account: only that account can accept it, and it lands in that account's Needs you. The CLI computes the key's fingerprint itself and prints the ask: the link, the fingerprint, the four words and which group the page hides. There is one live link per key: a new attempt for the same key supersedes the older one.
3. **The person whose machine it is accepts it.** They open the link, sign in, and see the machine's name, host, backend, when and from where it asked, the words and three of the four fingerprint groups, and the complete scope it will get. They type the hidden group and accept with a passkey that signs the workspace, the enrolment, the key's full thumbprint, their own account and membership, the whole scope including the private-credentials tick, and the start context. The tick starts on for an owner's, admin's or member's own machine and off for a guest's; they may change it before they sign, and the passkey signs what the box says. The server checks the typed group against the stored key before it honours the passkey. Nobody, owner or admin, can accept a machine on a member's behalf. A guest's machine then also needs **admission** by an insider who manages every project the scope names, a distinct action that never counts as acceptance; a team's machine is admitted by an owner or admin instead of accepted. Owners and admins are told that a machine was added, with a link to narrow or revoke it.
4. **The machine finishes.** `mehen enrol` records the attempt, prints the ask and exits 0 (`--wait` waits in place). `mehen wait enr_...` (or `vault_wait`) from any process polls until the attempt is active. A live attempt is listed and can be accepted; when nothing renews it, it **lapses** (it cannot be accepted, "This link has lapsed") but stays revivable: `mehen wait` renews it in place, with the same id, code, link and fingerprint, when under five minutes remain, at most once a minute and never past the hard cap. An attempt is **terminal** when it is active, rejected or expired. Only a terminal `expired` calls for a new attempt with `mehen enrol`, which keeps the key. Five wrong typed groups reject an attempt across any number of renewals.

**Scoped enrolment.** A machine may ask for less than the workspace's default scope when it enrols: `mehen enrol --workspace <slug>` with `--tag <tag>`, `--project <id>` or `--mode <relay|sign|mint|placeholder>` (each repeatable), `--no-private` (no private credentials) and `--workloads-only` (it acts only through [workloads](#workloads)). The scope the enrolment registers is the default narrowed by the request: the tags and projects as given, only the modes in both lists (never `lease`; `fill` is never given at enrolment, and a request naming it is refused with `mode_refused`), the private-credentials tick off when it asked for none, and workloads required when it asked for that. The enrol page shows that scope, says "This machine asked for less than usual" with the narrowing in plain words, says "Acts only through short-lived workloads" when it asked for that, and hides the private-credentials tick when it asked for no private credentials. The person accepting cannot widen it past the request: the page leaves them only the private-credentials tick, and only when the machine did not ask for none. Their passkey signs that scope as at any enrolment. Without these flags nothing is asked for and enrolment is as above. Running `mehen enrol` again with a different requested scope starts a new attempt with the same key. `mehen` 0.3.0 has neither these flags nor `mehen workload`, and refuses them as a usage error; they came with 0.3.1.

On `active`, `mehen` checks the answer before it writes anything: the returned workspace id agrees with what it asked for, the slug matches the requested workspace, the owner is of the requested kind (self or team), and the scope is complete. That does not by itself verify a particular human account or team; read the accepted owner that `mehen wait` prints. If activation does not match, `mehen` writes no new configuration, attempts to revoke the returned device and removes only files that belong to that attempt. Cleanup can fail; read the reported outcome, and keep any device id it names visible for a human to revoke. Two processes finishing the same attempt with the same key is one success, never a revoke; two different devices approved for one workspace on one machine is `already_enrolled`, which revokes and deletes nothing.

## Scope and reach

A device's scope is a **ceiling under its owner's rights**, never a grant of its own:

| Field | Meaning |
| --- | --- |
| `tags` | Items the device may use: an item must carry one of these tags. Empty means every item its owner may use. |
| `projects` | Projects the device may use. Empty means every project its owner may use, and only such a member-owned device may create projects. |
| `maxEnvironment` | `unprotected` or `protected`: whether the device may ever use a protected environment or a protected credential, given that its owner has the protected right there. |
| `modes` | Which rungs of the [exposure ladder](credentials.md#the-exposure-ladder) this device may use at all. Never `reveal`. `fill` (typing into web pages) joins only as a widening on the machine's page and never as its only mode, and the vault refuses it with `mode_refused` until the machine has called with `mehen` 0.3.17 or later. A `mehen` older than 0.3.17, or of unknown version, is answered a mode list without `fill`. |
| `privateCredentials` | Whether the device may use its owner's private credentials and private overrides. Only a member-owned device; a team's is always false. Default: the enrol page ticks it for an owner's, admin's or member's own machine, leaves it off for a guest's, never offers it for a team's, and offers no tick when the machine asked with `--no-private`. Turning it on later is a widening: proposed on the machine's page and accepted there by the machine's owner, two passkey prompts. Without it, the owner's private credentials are `not_found` to the machine, and asking for a new one in the owner's private home (`mehen request` and `mehen connect` without `--home`) is refused with `forbidden`, saying to ask in a project or the workspace instead, or to tick the private credentials box on the machine's page. |
| `workloads` | `allowed` (also when absent): the device acts with its own key and through the workloads it creates. `required`: it acts only through workloads ([Workloads required](#workloads-required)). |
| `serviceRuns` | Whether the device may start [service runs](projects.md#service-runs) (`mehen run --service`), which renew with no maximum life. False when absent, as for every machine at enrolment: no machine can ask for it. Turning it on is a widening, the **May run services** tick on the machine's page, proposed there and accepted by the machine's owner (signed by an owner or admin for a team's machine). Turning it off applies at once and ends the live runs of the owner's machines: their next request gets `not_found`, and a restart with `--service` gets `forbidden`. |

**Reach** is what a device can actually do: for each project, its owner's effective access, with protected runs only when `maxEnvironment` is `protected`; a workspace credential only for a member's device (owner, admin or member, never a guest's or a team's); a project credential where the owner has `use`; a credential a protected environment references only inside that environment, with the owner's protected right; a private credential only for the owning member's ticked device, and never in a protected environment. Reach is re-evaluated on every request: a suspended or removed owner makes every call `owner_inactive`, an expired share or a lost project `not_found` or `project_unshared`, and a device never outlives its owner's standing.

## Narrowing, widening and revoking

A device is active or revoked. A revoked device's proofs are refused with `device_revoked`. A device can revoke itself (`mehen revoke`); its owner, an owner or an admin can revoke it from the browser with a passkey.

**Narrowing** a device's scope (every field a subset, `maxEnvironment` not raised, neither the private tick nor May run services turned on) is done by its owner, an owner or an admin with a passkey. **Widening** one is proposed and then accepted by the device's own owner with their passkey, as at enrolment; a team's device is widened by an owner or admin, and can never get the private tick. A change applies from the device's next request, live runs included. The audit records the scope before and after.

Revocation stops subsequent uses through Mehen. It cannot recall an upstream request already sent, undo what happened at the provider, erase a value already leased into a process, or revoke a credential at its provider; rotate an exposed credential at the provider ([A machine or a key is compromised](../guides/incident.md)).

The Machines page shows each device as a card with its key's four words, key type, owner, last seen, status and what it may use. A member sees their own machines and their teams'; owners and admins see all.

It also shows the version of `mehen` each machine last called with, marked "update available" below the vault's recommended version and "too old to connect" below its minimum.

**Carrying on without asking.** Where mandates are on, a member's own machine can have a [mandate](mandates.md): its owner signs, with a passkey, that it may send its held requests with the credentials and kinds named, within daily caps, until a date. The machine's page has a **Carry on without asking** card with its mandate, today's counts and its controls, or **Trust this machine** for its owner. The machine may propose one (`mehen mandate propose`) and pause its own (`mehen mandate pause`), and so may any of its workloads pause it, but it never signs, resumes or stops one. A mandate covers nothing a workload sends, so a machine that acts only through workloads gets nothing from one. A team's machine cannot have one yet, and a guest's machine cannot have one or propose one. Widening its scope ends its mandate's cover until the signer resumes it with a passkey; narrowing it does not. Revoking it ends its mandate for good.

A non-exportable key cannot be copied off the machine, but any process running as the same user can ask it to sign. The device key proves which machine is asking, not which process. It is not what keeps secrets from an agent: that is the vault never returning values, the bindings, the owner's rights capping the machine, and approvals that need a passkey. A harness that runs several tasks on one machine can give each its own key the vault tells apart: a workload.

## Workloads

A **workload** is a short-lived child key a machine creates under itself for one task: a hosted agent platform gives one to each conversation, a CI runner to each job, a harness to each subagent. Its scope can only narrow the machine's, so the vault itself keeps one task out of another's credentials, asks and runs, names the task in the audit and on the pages a person decides on, and ends the task's reach when the workload is revoked or expires.

**Who creates one.** Only the machine's own device key, never a workload. The harness that holds the device key generates a P-256 key pair for the task, registers the public half with a label and a scope, and hands the private key to the process that runs the task; that process signs its own requests as the workload. There is no human step, because a workload can only narrow what the machine's owner already accepted. `@mehen/client` does this ([One workload per task](../guides/harnesses.md#one-workload-per-task)). `mehen` does not create workloads: a second key on the same disk, next to the device key, would confine nothing.

**Scope only narrows.** A workload's scope has four fields, each optional and each a further limit on the machine's scope, applied as an intersection with it and with the owner's rights, never a union:

| Field | Meaning |
| --- | --- |
| `items` | Only these credentials, by slug, 1 to 64 of them. |
| `tags` | Only credentials that carry one of these tags, 1 to 32. |
| `projects` | Only these projects, 1 to 32. |
| `modes` | Only these rungs of the [exposure ladder](credentials.md#the-exposure-ladder), 1 to 6. `fill` needs the machine to have called with `mehen` 0.3.17 or later, as for the machine itself. |

A field left out adds no limit. A tag, project or mode outside the machine's own scope is refused with `bad_request` when the workload is created. Items are not checked then, since an intake or connection the workload asks for may create one later; an item outside the machine's reach is simply never usable, and an intake or connection for a slug outside `items` is refused before anything is created. So is one the workload could not then see: with `tags`, the request's tags (a connection's `clientTags`) must include one of the workload's, and with `projects`, a project home must be one of them. A rotation is judged by the credential's own tags. A credential outside a workload's scope looks to it as one outside a machine's scope does to the machine.

**Projects.** A workload never creates a project: `POST /v1/projects` signed by one is refused with `forbidden`, whatever its scope. A machine that acts only through workloads creates none with any key, so a person creates the project on Mehen's site, or from a machine enrolled without `--workloads-only`. A workload changes a project variable only when its scope covers both the credential the variable is bound to now and the one it binds it to; replacing a bound variable with a plain value needs the current one covered. Out of cover it gets `not_found`, as a machine outside its scope does. A plain (non-credential) variable it sets, changes or unsets only in a project its scope names in `projects`; a workload whose scope names no projects (only items or tags, or nothing) is refused every plain variable change with `forbidden`. A change between plain and bound needs both rules.

**Life and limits.** A workload lives an hour, or what its creator asks for, from one minute to 24 hours. Renewing moves its expiry to that long from now, never past seven days from its creation. A machine may hold at most 256 live workloads; one more is refused with `rate_limited`. A workload may hold at most five open asks (approvals, intakes and connections together), within its machine's 20, so one runaway task never uses up the asks of the machine's other tasks; a sixth is refused with `rate_limited`. A workload's key may not be its machine's key or another live workload's: such a key is refused with `conflict`. Expiry is checked on every request. A workload never outlives its machine: revoking the machine, or its owner losing standing on it, ends every workload at once. The workload's `revokedBy` says which: `device_revoked`, or `owner_inactive` when the owner was suspended, removed or left, or the owning team was deleted. Reinstating a suspended owner does not bring an ended workload back; the machine creates a new one.

**Signing.** A workload signs with its own key ([Keys, proofs and signing](../security/keys-and-signing.md#workload-proofs)). The vault finds the machine and the workload, verifies the workload's key, and only then checks that the workload is live: one that has expired or been revoked, or whose machine was revoked, is refused with `workload_ended`, and a proof that does not verify is `proof_invalid` either way. Only the machine's own key creates, lists, renews or revokes workloads; a workload never creates another, and is refused with `forbidden` if it tries. A workload may neither freeze the workspace (`POST /v1/freeze`) nor revoke its machine; both are `forbidden`. Freezing stops every member and machine in the workspace, so it stays with the machine's own key and with people. Freezing only narrows, so a frozen workspace still lets a machine create, renew and revoke its workloads.

**Asks belong to the workload.** Every approval, grant, intake, connection and run a workload creates records it. Only that workload may poll, wait on, cancel or spend it. The machine's own key sees its workloads' asks in its pending list, but cannot poll, cancel or spend one (it gets `not_found`); its clean-up is revoking the workload, which ends every open ask the workload owns. Another workload of the same machine gets `not_found` too.

**What a person sees.** Approval, intake and connection pages still say "An agent on my-laptop", and add a quieter line, "Task: <label>, as the machine named it", when a workload asked. The label is the machine's words: the program that created the workload chose it, and the vault does not check it. The machine's page lists its live workloads (label, scope in words, expiry, last seen) with Revoke, which needs the same passkey step-up as revoking the machine and, like it, is a tightening action, so it stays allowed while the person's account is cooling off after a recovery. The audit names the workload, by id and label, on every event it caused. Needs you is unchanged.

On the machine itself, `mehen workload ls` lists its live workloads and `mehen workload revoke <wl_id>` ends one; both are signed by the device key, and revoking is safe to repeat.

### Workloads required

A machine whose scope says `workloads: required` (enrolled with `--workloads-only`, or narrowed to it) acts only through workloads. Its own key may still read who it is (`GET /v1/me`), list and show items, list its pending asks, manage its workloads, freeze the workspace and revoke itself. Everything else, relays, intakes, connections, approvals, projects, runs, leases and policy changes, is refused with `workload_required`. `required` is the narrower setting: turning it on is a narrowing, turning it off a widening, under the rules above.

## Fingerprints and the hidden group

A key's fingerprint is what a human compares between the terminal and the enrol page. The CLI, the server and the page derive it the same way:

- **Glyphs.** Four groups of four characters from an alphabet with no I, L, O or U, such as `5NZV DP67 PXT0 DB6E`. When a human types a group, `I` and `L` read as `1` and `O` as `0`.
- **Words.** Four words, each with a colour name: `puppy (violet) potato (indigo) juice (mint) oven (olive)`. The colour name is always printed beside the swatch, so colour alone never carries the check. The words are a quick look; the glyphs and the typed group are the check.
- **The hidden group.** The enrol page shows three groups and renders the fourth as dots. Which one is hidden depends on the enrolment code, so it moves when the link is re-issued. The page never carries the hidden group, the full fingerprint or the key; the server compares what was typed when the owner accepts, counts every attempt, and rejects the enrolment at the fifth wrong group.

`mehen status` prints the fingerprint recorded at enrolment and the Machines page shows the words, so a machine can be matched to a card at any time. The derivation is in [Keys, proofs and signing](../security/keys-and-signing.md#fingerprints).

## Sessions

A session is a label an agent puts on its requests: `MEHEN_SESSION` for `mehen` and `mehen mcp`, 1 to 120 letters, digits, `.`, `:`, `_` or `-`. It might be a session id, a task id, a subagent run, or a label an app sets from its conversation. It is for the audit log and for the details of an intake, connect or approval page. It grants nothing, and because an agent chooses it, no page infers who asked from it: the "who asked" line is always the enrolled device's name ("An agent on my-laptop"), which its owner accepted at enrolment. Grants are per device, or per workload when a workload asked, and per request digest, never per session. A session is a label; a [workload](#workloads) is a key the vault checks.

## Workspaces on a machine

A machine identity's state lives under one root, `MEHEN_HOME` (default `~/.config/mehen`): one **slot** per workspace, `workspaces/<origin>/<tn_id>/` once active (its configuration, the device key and its scope file, and the ledger) and `pending/<origin>/<slug>/` while an enrolment waits. Slots are keyed by origin and workspace id, so a rename costs nothing. They are discovered from disk, and a directory that is not a slot is named by `mehen doctor` and never deleted. Locks serialise enrolment, finishing and revocation per slot.

Harness registrations and skills remain per OS user, and installation and update state sits beside the executable, so separate homes do not create separate MCP profiles or separate updater installations.

**Selection.** Every command selects a workspace before it signs or sends anything:

1. **The ceiling** `MEHEN_WORKSPACES` (comma-separated slugs, `tn_` ids or `<origin>/<slug or id>`; unset or `*` for every slot, empty for none) is the set this process may use. It only narrows, and nothing inside a process widens it.
2. A checkout's `mehen.toml` without `workspace` while several slots are allowed is `workspace_unbound`.
3. Then `--workspace <slug or id>` or `MEHEN_WORKSPACE`; then the checkout's `mehen.toml` (`workspace` and `vault`); for `mehen wait`, the one slot that records the id; then the only active slot.

There is no default: several and nothing deciding is `context_ambiguous` for a command that needs one, while `status`, `doctor`, `ls`, `pending` and `workspace list` span the allowed set. These refusals are local, exit 2, and sent before anything is signed: `workspace_not_allowed`, `workspace_unknown`, `workspace_mismatch`, `context_ambiguous`, `workspace_unbound`, `config_dir_retired`. A workspace's name is data from the vault, never a selector; only the id and the canonical slug select. `mehen status` reports a renamed workspace's current slug and name without recording them; `mehen workspace list --check` and `vault_status` can each record them for the slot after a successful signed check. `mehen workspace list --check` refuses an answer for another workspace or origin, or a slot that changed while it asked, as `workspace_mismatch` and changes nothing; `vault_status` keeps the recorded names when the answer names another workspace.

The ceiling is an accident control, not an identity boundary: an environment variable can be edited. **A separate `MEHEN_HOME`** selects a separate local identity store, a separate machine to the vault with its own keys and slots. Commands using one home do not discover the other's slots. That is organisation under one OS user, not isolation from other processes running as the same user. [Several workspaces on one machine](../guides/several-workspaces.md) and [A second identity on the same machine](../guides/second-identity.md) are the how-to.

**Managed hosts.** An agent launcher that pins each agent to one workspace places a marker under the user's home directory as the system's user database records it, never as `HOME` says. Commands that open Mehen's state fail closed with `key_insecure` when that home cannot be resolved or its path is unsafe. There the pinned slot and `MEHEN_MANAGED_CONTEXT`, checked against the host's pin map, are the sole authority: no manifest or ceiling widens it, and a selector that disagrees refuses. Managed selections fail closed: an outdated managed-agent configuration is `pin_outdated`, and only the harness owner can repair it.

**One MCP server.** One `mehen mcp` server can serve several allowed workspaces, with a separate identity latch for each. Its startup workspace, the checkout's manifest, a managed pin and the harness ceiling may restrict that set, and a tool argument cannot widen it. A slot whose enrolment later changes device, workspace or origin, or vanishes, is refused for the life of the process with restart advice, while the other slots keep serving. `mehen setup` writes one `mehen` entry per harness, carrying the ceiling in `MEHEN_WORKSPACES` whenever it is restricted, so setup never makes a server wider than the shell it ran in.

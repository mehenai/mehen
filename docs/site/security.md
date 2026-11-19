---
title: What Mehen protects, and what it does not
question: What is the promise, and where does it stop?
section: security
covers: both
order: 0
---

# What Mehen protects, and what it does not

**Use credentials without reading them.** Relay and placeholder modes keep credential values out of the agent's hands, and off the agent's machine when the vault runs on another one. If a human explicitly allows lease mode for a credential, the value reaches the child process that needs it. Whoever operates the vault and the upstream service that receives the credential remain trusted.

**On your own machine.** A vault started with `mehen up` keeps keys out of the model's context, transcripts, logs, shell history and `.env` files, and refuses to send a key to a host it is not bound to, as Mehen Cloud does. It does not protect the keys from a determined program running as you: the vault's files, root key included, are readable by your user. Running the vault on another machine you own, or turning on Claude Code's sandbox, closes that gap; [Threat model: a vault on your own machine](security/threat-model.md#a-vault-on-your-own-machine) has the detail.

**For a business that builds on Mehen.** A [platform](concepts/platforms.md) uses its users' credentials and decides the requests Mehen holds, but never reads a stored key: no route returns a value, its machines cannot lease or reveal, and a credential's destination never changes once it is stored. Its users type keys into the platform's own pages, sealed in their browser to the vault, so the platform's servers never hold them either; the one place a platform could capture a key is its own page, while it is hostile. [Threat model: a platform](security/threat-model.md#a-platform) has the detail.

Limits are stated plainly on these pages, because a vault that oversells itself is worse than none. [Threat model](security/threat-model.md) goes attacker by attacker; [Keys, proofs and signing](security/keys-and-signing.md) is the cryptography. To report a security problem, see [Reporting a vulnerability](security/disclosure.md).

## The rules

| # | Rule | In one line |
| --- | --- | --- |
| R1 | References, not values | Repos, configs, prompts and transcripts hold `mehen://` references and placeholders; no API returns a secret to an agent's machine by default. |
| R2 | Every secret has a destination | An item without a binding (hosts, schemes, ports, paths, methods) cannot be used, and one matcher checks it everywhere. |
| R3 | Explicit beats default | Nothing is chosen by first match: every request names its item, and policy rules combine deny over approve over allow. |
| R4 | Environment fences | A protected environment needs a typed `--env prod`, an allowed machine and a live approval; a run cannot reach hosts fenced to another environment. |
| R5 | The vault decides | Manifests and agent requests express intent; bindings, modes, policies and protection are set in the vault by a human with a passkey. |
| R6 | Humans approve what they see | Approvals are bound to a digest of the exact request and signed with the human's passkey; agents cannot approve. A person may also sign terms in advance, with a passkey, for one of their own machines (a [mandate](concepts/mandates.md)), which never cover what always asks. |
| R7 | Fail closed, say the fix | Refusals include a reason. The CLI adds a next step where it can: a command, a human link or advice. Some problems need a human to repair the setup. |
| R8 | Least exposure wins | Each item has a ceiling on the exposure ladder and the vault uses the lowest rung that works. |
| R9 | Secrets go only where declared, inside the request too | A placeholder found anywhere but the declared injection surface is refused, never substituted. |
| R10 | Agents cannot move a credential | Agents may propose new items; changing an existing item's binding, ceiling or policy needs a passkey that signs the change. |

In a [managed workspace](concepts/platforms.md), the platform's signature over the exact request stands where a person's passkey does in R5 and R6, and R10 is stricter: nothing can change an existing credential's binding, ceiling or own policy at all, and the platform's defaults, which apply to every credential at use, can only make the catalogue's policies stricter; their one loosening is to let reads through, without a hold, on keys with no template.

## What it protects

| Asset | Where it lives | Why it matters |
| --- | --- | --- |
| Secret values (API keys, passwords, private keys, OAuth access and refresh tokens) | Encrypted in each workspace's own store. Plaintext in the human's browser while they type it, in the vault while it uses it and in the upstream request, and, if lease mode is explicitly allowed, in `mehen` and the child process during delivery and use | The whole point. |
| The root key | Held by the operator; possession of a root key and the stored ciphertext permits decryption | It decrypts every workspace's stored secrets. |
| The seal key | Held by the operator | Opens secrets sealed by browsers while in flight. Nothing at rest depends on it. |
| Device keys | The Secure Enclave on macOS, or a 0600 file, one per workspace a machine is in | Prove which machine is asking, in which workspace. |
| The backup identity | Never in Mehen: wherever the owner who registered its key keeps it. `mehen backup` refuses to make one, or open, restore or compare with one, on an enrolled machine unless told `--on-enrolled-machine` | Opens every export made to its key, offline and for good: a credential rotated or deleted in Mehen is still in an older export; only rotating it at the provider ends that. |
| Accounts: passkeys, recovery codes, sessions, linked Google identities | The person's authenticators; hashed codes and session tokens in the account directory | Everything that widens access needs a passkey; after one, actions that cannot widen access do not ask again in that browser session for 15 minutes. Recovery is the way back in. |
| Memberships, roles, teams, project shares, credential homes | The workspace's own store | They decide who may use, edit, manage and approve what. |
| Bindings, policies, ceilings, machine scopes, protection, four-eyes, fences, overrides | The workspace's own store | They decide where credentials may go. Changing them is as good as stealing. |
| Approvals and grants | The workspace's own store | A forged or reused approval is an unauthorised action. |
| The audit chain | The workspace's own store, hash-linked | The record of who used what. |
| Data reachable through a credential (mail, repos, payments) | The upstream | An agent can misuse a capability without ever seeing the secret. |

## Mistakes the vault will refuse, and why

| You try to | The vault | Why |
| --- | --- | --- |
| Put a run's placeholder in a body, query string or another header | Refuses (`surface_refused`) and records a tripwire | Otherwise anyone who can steer an agent could write the real token into a comment on a bound host. |
| Send a credential to a host outside its binding | Refuses (`binding_refused`) | Every secret has a destination. A prompt injection cannot redirect it. |
| Use `http://` where the binding says `https` | Refuses (`binding_refused`) | Credentials do not travel in clear text unless a human bound it that way. |
| Use a URL with `..`, `%2e`, `%2f`, `%5c`, a backslash, `//` or a username in it | Refuses before anything is decrypted | Upstreams read such paths differently from the matcher; the vault does not guess. |
| Spell a path with escapes or odd case (`%73end`, `/me/SendMail`) | Applies the deny and approve rules anyway | Restrictive rules match a decoded, lower-cased path. |
| Put an encoded `?` or `#` (`%3F`, `%23`) in a path | Applies the deny and approve rules to the path cut there; an allow rule or a binding path must cover the path both as sent and cut there | An upstream that decodes the path again may end it at that character. |
| Send `X-HTTP-Method-Override`, `X-HTTP-Method` or `X-Method-Override`, or a `_method`, `_httpmethod` or `x-http-method-override` field (or a spelling frameworks read as one, such as `_METHOD`, `%5Fmethod` or `.method`) in the query string, a form, a multipart part or a top-level JSON key | Refuses (`forbidden`) | It would let a GET-only rule admit a DELETE. |
| Send a body compressed with `gzip` or `deflate` that carries one of those fields | Decompresses it, up to 10,500,000 bytes (the largest body a relay request can carry uncompressed), and refuses it (`forbidden`) when the field is in the body as sent or after any step of decompressing it | An upstream may read the body as sent, undo some of its encodings or undo them all, so the vault checks every one of those forms. |
| Send a body in any other content encoding (`br`, `zstd`) or in more than three stacked encodings, with a `Content_Encoding` header, whose data does not match its encoding, is cut short, goes on past its end or joins gzip members (an upstream may read only the first), or that decompresses to more than 10,500,000 bytes | Refuses (`forbidden`, or `too_large` for the size) | The vault cannot check what it cannot read. |
| Send `X-Original-URL`, `X-Rewrite-URL`, `X-Original-URI`, `X-Forwarded-Prefix`, `X-Forwarded-Path`, `X-Forwarded-Uri`, `X-Forwarded-Url`, `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Original-Host` or `Forwarded` (`_` read as `-`) | Refuses (`forbidden`) | An upstream may act on the path or host they name instead of the one the binding and policy checked. `X-Forwarded-For`, `-Proto` and `-Port` are forwarded as sent. |
| Set the auth header yourself | Replaces it with the item's credential | Security-relevant parameters belong to the item, set by a human. |
| Change an item's binding, ceiling, policy or tags | Cannot; needs a human's passkey | Agents may propose new items but cannot move an existing credential. |
| Approve your own request, or accept a machine | Cannot | Approval and acceptance need a passkey on the vault's page. No MCP tool approves a request, starts an enrolment, revokes a machine or freezes a workspace; `vault_wait` can finish an enrolment already started at the terminal. The CLI has `mehen enrol`, `mehen revoke` and `mehen freeze`, and human acceptance and approval still need a passkey. |
| Open a link the vault returned that is not on the vault's origin under the workspace's canonical slug | `mehen` refuses to show it and warns | A hostile or misconfigured vault URL, or a stale alias, cannot make an agent send a human to another site or workspace. |
| Name another member's private credential, or a project not shared with your owner | `not_found`, exactly as for a name that does not exist | Nothing outside your owner's reach can be discovered by naming it. |
| Use a workspace outside `MEHEN_WORKSPACES`, or select one by its display name | `workspace_not_allowed` or `workspace_unknown` (exit 2), nothing sent | The harness decides which workspaces an agent may use; names from the vault are data, never a selector. |
| Run production through `MEHEN_ENV`, a default or a branch name | Refuses (`environment_refused`) | Protected environments need a literal `--env`, an allowed machine and an approval. |
| Point a dev variable at a production credential | Refuses (`environment_refused`) | A protected credential reaches only an approved protected run. |
| Reach a host fenced to another environment, from a run | Refuses (`environment_refused`) and records a tripwire | The wrong database at the wrong time is a refused connection. |
| Use a project id from a repo whose reported `origin` is not bound to it | Refuses (`remote_mismatch`) | A checkout of another repo cannot use your project by accident. |
| Store a secret-looking value as a plain variable | Refuses (`bad_request`) | Plain variables are for non-secret config only. |
| Ask for a lease on an item whose ceiling is not exactly `lease` | Refuses (`mode_refused`) | A `reveal` ceiling is for humans in the browser; machines never get it. |
| Push a credential into a GitHub, Vercel or Cloudflare secret store | Refuses (`mode_refused`) until a person allows that credential to be pushed, and `forbidden` where the workspace has no pushing; otherwise asks a person every time, and sends the value itself | The value goes only where a person read and approved, and never through the agent's machine. |
| Keep using a placeholder after its run ended | It does nothing | Placeholders die with their run. |

## Limits, stated plainly

- **Whoever can deploy the vault's code can read every secret while it is used.** Whoever can deploy vault code, write trusted account identity state or operate account recovery can take over the vault's trust boundary. The operator must restrict those powers independently of agent access. These pages do not establish current operator-machine isolation. Beyond Cloudflare's own durability, every workspace's stored data has Cloudflare's 30-day point-in-time recovery, and each workspace not managed by a platform also has a daily dump of the whole workspace, sealed under a key derived from the root key and kept in a separate bucket. Setting that bucket to refuse deletion for 30 days is a step in the operator's setup, and whether an account administrator can lift that lock is not established. A dump opens only with that root key and only as its own workspace, so it lets no one read what the root key does not already open. Where copies of the root key and of the dumps are kept off the host is not established here.
- **Lease mode gives the value to a process.** Redaction catches it printed as is or in common encodings, never transformed, and not when it is shorter than six characters.
- **Scrubbing has limits.** The vault scrubs credential echoes in raw, URL-encoded, JSON-escaped and supported base64 forms; it cannot catch arbitrary transformations.
- **A device key proves which machine asks, not which process**: any process running as the same user can ask it to sign.
- **Policy, not intent, decides, and some requests run without asking.** These go through with no one asked at the time: what the credential's policy allows, usually reads; a request a [standing rule](concepts/policy.md#standing-rules) covers, for up to 30 days; routine building a [task grant](concepts/policy.md#task-grants) covers, for up to four hours; what a credential's [posture](concepts/policy.md#how-careful-a-credential-is) lets through, which at its widest includes routes nobody has reviewed; and a machine's held reads, changes, sends and deletes within its [mandate](concepts/mandates.md)'s terms and daily caps. An injected agent can misuse exactly those.
- **On a service nobody has reviewed, a mandate judges a request only by its method, path, query names and body shape.** It asks for what those name and lets the rest through, so a route that sends money but whose path says nothing about money would go through as a change. On GitHub, Stripe and Cloudflare, the routes on their reviewed lists and the floors their templates name hold route by route; any other route there is judged as on a service nobody has reviewed.
- **Fences match host names, not DNS aliases**, and the local relay's refusals happen on the machine and are not audited; traffic it tunnels is never swapped or inspected.
- **Enrolment codes travel in URL paths** (low, deferred).
- **Mehen Cloud is hosted on Cloudflare** and trusts it completely.
- **A vault on your own machine trusts everything running as you.** Its root key is in a file in its data folder, not wrapped by the Secure Enclave or any other hardware key yet, so a program running as your user can read every stored key. [Run it on another machine](start/another-machine.md), or turn on Claude Code's sandbox and run `mehen guard install` again, to keep an agent's shell away from it. A separate-user mode is planned.
- **Windows is not supported yet**, for the command line or a local vault.


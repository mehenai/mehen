---
title: Threat model
question: Who is the attacker, and what can they do?
section: security
covers: both
order: 10
---

# Threat model

What Mehen protects, from whom, how, and where each protection stops. The assets and the short list of limits are on [What Mehen protects, and what it does not](../security.md); the model it protects is on [The model in one page](../concepts.md).

## Mechanisms in one place

Each mechanism, and what it stops.

| Mechanism | Stops |
| --- | --- |
| No value returned to a device except a lease and a fill's one field, sealed to the machine for `mehen` to type; relay and placeholder modes first | Secrets in context, transcripts, logs and files. |
| Reveal is human only: a device lease needs a ceiling of exactly `lease`, and device scopes cannot include `reveal`; no route shows a stored value to anyone, except a backup export (below) | A ceiling raised so a human can view a password widening what devices get; an owner or admin reading a colleague's credential. |
| Backup exports: an owner registers an age X25519 recipient with a passkey over the key, its label and their export scope; it works only 24 hours later; every owner and admin and the owner who added it are told when it is added, becomes active and is removed; any owner can remove it, a restricted one included; only the owner who added it exports, from the browser or their own machine (never a workload or a team machine, never while their sign-in is restricted or pending); the vault encrypts each export itself, so the caller only ever receives ciphertext; one export per key every 10 minutes; every export is audited and recorded as an exposure of each value it holds; none in a platform-managed workspace | A stolen session or a single quiet owner turning Mehen into a bulk read; a machine or agent reading values through an export. An export holds the workspace's credentials, those of the projects the owner manages and the owner's own private ones; never another member's private credential, a four-eyes credential or an OAuth connection's tokens. |
| One access check decides every human and machine right from live state, after the last step; a machine's reach is its scope intersected with its owner's current rights | A machine outliving a removed, suspended or demoted owner; a share that expired still being honoured; a stale cached decision. |
| A credential belongs to one home: the workspace, a project or one member; out of reach is `not_found`, byte for byte as absent, before status, ceiling or OAuth state is read; creation under a taken name is one generic `conflict`, rate limited | Learning that a colleague's private credential exists, its status or its provider by naming it; a reconnect link minted for a credential the caller may not use. |
| A team's or a guest's machine reaches a workspace credential only through a project environment that references it, named in the request, never implicitly; a project's own credential needs `use` on that project; a private credential is reached only by its owner's own ticked machine (a guest's included) and by nobody else's | A shared CI or chat machine (a confused deputy) using whatever the workspace holds; a colleague's or a team's machine using someone's private credential. |
| Protected use needs the explicit protected environment that references the credential, the owner's protected right and `maxEnvironment: "protected"`; four-eyes needs a manager of every applicable project other than the owner; loosening protection on an environment that references a workspace credential, and any fence change, is owner or admin only | A prod credential reached through a dev context or a self-approved run; a project manager quietly unprotecting what an owner delegated. |
| Required binding, one matcher, canonical paths, ambiguous paths refused | Sending a credential anywhere it was not meant to go. |
| A lease-only credential (no template, no host, no injection, of a kind the relay never injects) carries the reserved host `lease-only.mehen.invalid`, which the vault refuses as a destination before matching, and never as a placeholder | A secret only meant for a process (`JWT_SECRET`, `DATABASE_URL`) being relayed or swapped anywhere. |
| Restrictive rules matched on a decoded, lower-cased path; permissive ones on the exact canonical path | Dodging a deny or approve rule with `%73end` or `SendMail`. |
| IP literals, loopback, `*.workers.dev` and the vault's own host only when bound exactly | A wildcard binding turning the relay into an open proxy. |
| Declared injection surface; the vault sets the header, replacing any copy sent; placeholders refused elsewhere and recorded | Smuggling a token into a body, query string or comment on a bound host. |
| Method-override headers and parameters refused | A GET-only rule admitting a DELETE. |
| Policies combined as deny over approve over allow; body matchers fail closed | A new rule silently opening something; GraphQL mutations passing as reads. |
| Templates fail closed: reads allowed, other methods held for approval unless a narrow everyday write is allowed, the worst routes denied (Gmail `drafts/send`, Graph `$batch` and send, forward or reply of a stored message, forwarding, rules, keys, webhooks, collaborators) | Writes nobody looked at; sending mail without a real approval; persistence at the provider. |
| Approvals bind item, method, URL, content type, content encoding, forwarded-header hash and body hash; an eligible decider signs within their own rights, and grants and runs become stale when the recorded decision basis goes | Agents approving; approvals reused for other requests; the same bytes read another way; a guest approving a manager's ask; a consent surviving the decider's removal. |
| Standing rules are turned on only by a person's passkey on the vault page, over terms the vault built from the request it stored and the page checked against its own copy; an agent only proposes one, and no other surface can sign one | An agent widening its own access; a rule whose terms differ from what the person read; a rule approved somewhere that does not show the terms. |
| A standing rule serves only the key that asked (the machine's own or one workload's), one credential, one method, one host, one path or a pattern with `*` in place of one id segment, the same query parameter names and, for GraphQL, one mutation with the same root and nested fields; it serves only the project, environment and mode its request was asked in | One approved request shape becoming access for another key, another task, another context or another operation on the same credential. |
| A standing rule only turns a request the policy would hold into one that goes through: never a deny, the binding, the ceiling, a lease, a reveal, a protected credential, environment or run, or a managed workspace, nor a send, money, sharing, credential or persistence floor; a GraphQL mutation's floor only with a field-by-field proof; no `DELETE` and no request that sends, pays, shares, changes credentials or access or sets up persistence ever qualifies, nor any request on a credential holding a live key | An agent being allowed to delete, pay or send unattended; a rule opening what the policy refuses or what protection guards. |
| The machine's owner approves a standing rule for their own machine (any approver of a team's machine's ask for a team's machine), never an owner or admin for another member's machine and never a guest; when the approver does not manage the credential's home, a different manager of it co-signs | An admin allowing standing access on a colleague's machine; one person on a shared credential granting standing access alone. |
| Standing rules end: at most 30 days after they are made or extended, and sooner when stopped (no passkey needed), when the approver's or co-signer's decision basis goes, when the machine or workload is revoked or rescoped, when a protected reference is added or when the credential is edited; in an identity-gated workspace a rule rests on the approver's live standing under the gate. Every use is audited and counted on the credential's and the machine's pages | A forgotten rule outliving its reason; a rule surviving the person or the access it rested on. |
| A task grant is never for a guest's machine, a protected credential or one holding a live key, and covers only the routes a reviewed list marks as routine building, in the areas a person ticked, on that credential's host, for the key, project, environment and mode it was made from, with no query string and with a JSON body unless the route takes raw bytes or is Cloudflare's Analytics Engine SQL (one statement, as plain text or a form); routes added to the list after signing are not covered; it ends at 15 minutes, an hour or four hours and after at most 200 uses; a person's passkey signs the areas, duration and uses the page shows, as terms the vault built, and who approves and co-signs it is as for a standing rule; none in a managed workspace | A burst of building turning into access to the service's other routes, to routes nobody has read, or to another key or context; a grant running on without end. |
| A posture is set only by a manager of the credential's home with a passkey, only for a service with a reviewed list, and is read after rules and grants for a request the policy holds; routine building reaches members' and teams' machines, never guests'; trust reaches only machines of the home's managers; neither covers a protected credential, a query string, a live key or the floor; a move to another home or a managed workspace puts it back to ask | An agent or a guest widening how careful a credential is; a trusted posture serving a colleague's machine; a posture opening a delete, a send, a payment or a share. |
| A mandate is signed only by the member who owns the machine, with a fresh passkey over terms the vault built (machine, credentials, kinds, caps, end date at most 90 days away, hours, note), for a member's own machine only, never a team's, a guest's or a workload; it is read last, after rules, grants and the posture, for a request the policy holds; it never covers the floor's credential, persistence, sharing and money checks, a request the vault cannot read, a live key, a method other than GET, HEAD, POST, PUT, PATCH or DELETE, a host only a wildcard in the binding admits, a protected credential, environment or run, reveal, lease, fill, push, connect or enrolment, or a managed or frozen workspace; each kind has a daily cap, and more than 120 covered requests beyond reading in a minute trips it until its signer resumes it with a fresh passkey; at each use the signer must still stand where they signed (account security, role, no cooling-off, the machine theirs, the credential's home theirs to manage), and a change lapses it until they resume it with a fresh passkey, telling them once; the signer, an owner or admin, or the machine itself may pause it, and the signer, an owner or admin may stop it, without a passkey; the machine never signs, resumes or stops one; every use is a receipt, and on a shared credential an audit entry, with method, host and reviewed route, never a path | An agent letting itself carry on; a mandate outliving its signer's standing or reaching further than they could approve now; a runaway agent sending without bound; a stolen session signing or widening one. On a service nobody has reviewed, the never list is only as good as the method, path, query names and body shape can tell. |
| Deciding asks together: one passkey signs a sorted list in which each entry is the digest its own page would sign, at most 25; each entry is decided in its own transaction with every check of a single decision; the floor starts unticked, and protected runs, four-eyes and warned asks are never in a batch; a batch never shortens a grant or makes a rule or grant; none in a managed workspace | One tick approving a request the person did not see; a batch skipping a check a single decision makes; a send or a protected run slipped into a list of routine ones. |
| Fill: the vault seals the value to the machine and `mehen` types it only into a field it checked, of the right kind, visible, in a frame whose every ancestor shares one https origin the credential's lists name; the page is checked again before typing; one-time codes are made in the vault, each to one origin; every field but a sign-in's username needs an approval; the value is never printed or logged; only a person adds a page or allows fill on a credential or a machine; none in a managed workspace | A credential typed into a lookalike page, a hidden field or a frame from another site; a value landing in a transcript or a screenshot; a one-time code secret leaving the vault. |
| Push: a credential is pushed only once a person who may change it has allowed it with a passkey, and never an OAuth client or connection; a push counts as a reveal, so a machine whose owner is cooling off after a recovery is refused; every push asks a person, on its own page, whose passkey signs the exact destination, the field, both credentials and their versions and settings; no rule, task grant, posture or batch decides one, and the approval is spent once it is used, even when the provider refuses; the vault sends the value to the provider itself, from URLs built from the canonical destination, following no redirect, and the machine gets back only where it went; the provider credential must be one the machine may use, of that provider, bound to its API and not denied by its policy, and the vault reads the destination before asking only where that policy allows; an ask still waiting goes stale when either credential's value or settings change; a push is checked again just before it is sent and is not sent once either credential, the allowance, the machine or its access changed, or after two minutes; none in a managed workspace | A machine reading a value it asked to put elsewhere; a push to a place no person read; an approval for one destination spent on another; a push sent after the credential, the allowance or the access it rested on changed. |
| The vault keeps a held request's copy only when it could become a rule at its own path, and deletes it two days after it was kept; a rule or a pending proposal keeps its own copy, deleted when the rule ends or the proposal closes, and never sooner than two days after it was made; every copy goes when the credential is deleted | Held request bodies, such as a comment's text, kept for good in the workspace's store. |
| Approvals are bound to hashes of the exact request; the page shows its headers and a presentation of its body (JSON formatted, forms decoded, email decoded where recognised, a non-UTF-8 body only as a byte count) under a decision card drawn from that presentation; compressed bodies, bodies over 64 KiB and forwarded headers over 16 KiB are refused for approval | A truncated preview hiding a recipient or payload. The presentation is not a lossless raw-byte view, and a binary body cannot be inspected on the page. |
| Hidden and text-direction characters spelled as markers where they sit, with a warning; markers styled only when the vault generated them, as structured segments, never by matching marker-shaped text | `fdp.exe` shown as `exe.pdf`; an attacker typing `[RLO U+202E]` to earn the trusted style. |
| Policy notes read as fact only for a verified built-in template; anything an agent could have written is described from its matchers | A rule noted "reads mail" that allows sending being summarised as a read. |
| "Who asked" is the enrolled device's name, never the agent's session label; a workspace's name is data, never a selector | A session label naming an agent the owner trusts making a page say that agent asked; a label picking which workspace acts. |
| Workloads: a key per task that the machine's own key creates, with a scope applied as an intersection with the machine's in the one access check; every ask, grant and run a workload makes is its own; it ends at expiry, at revocation by the machine or a person, or with its machine, checked on every request | One task on a shared machine reaching another task's credentials, asks, grants or runs; a task acting after its harness or a person revoked it, or after its machine was revoked. |
| Scoped enrolment: a machine's requested narrowing is applied to the default scope before the page shows it, and the person's passkey signs the result; the page cannot widen it past the request, and its only choice is the private-credentials tick when the machine did not ask for none | A machine that asked for little being granted the workspace's default anyway. |
| Run approvals bind the SHA-256 of the whole command line | An approved `bun deploy` grant spent on another command. |
| `mehen` hands over only links on the vault's own origin, under the canonical slug of the workspace the call was made in, on the vault's ask routes; a refused link is rebuilt from the id under that slug or replaced by a warning, every ask carries the enrolment that raised it, and the QR code encodes exactly the printed text | A hostile or misconfigured vault sending a human to another site; a link under an alias or another workspace getting trusted chrome; a QR that differs from what the eye reads. |
| One `mehen mcp` server serves only the workspaces its ceiling allows, resolved once at start; active slots are latched to the identity (origin, workspace, device) read at server startup; later admitted slots latch on first validation or activation, and a slot whose enrolment changes or vanishes is refused for the life of the process while the others keep serving; a later slot is admitted only by the start's resolution, never by a reused slug; sessions are cached by origin, workspace and device | A tool argument, a cwd or a replaced enrolment making a running server sign for a workspace it was not admitted to, or as a device it did not latch. |
| A machine is enrolled in a named workspace and activated only as asked: the CLI checks workspace id and slug, owner kind and a complete scope before writing, and on any mismatch attempts to revoke the new device, reporting the outcome; keys never cross workspaces or origins | A machine silently enrolled into the wrong workspace; one key serving two workspaces. |
| One terminal boundary: every human line is spelled out (controls, format characters, noncharacters) and only the styler's closed set of styles becomes an escape | Vault or ledger text moving the cursor, recolouring a line or hiding part of it. |
| One live enrolment link per key, under the workspace it was started in; the page shows three fingerprint groups, when and from where the machine asked and the complete scope, and the person whose machine it is types the hidden one and accepts with a passkey that signs the key's full thumbprint, their own account and that scope; nobody accepts for them, and a team's or a guest's machine needs a distinct admission that never satisfies acceptance | Approving a page that only looks right; guessing the hidden group through the page; an admin planting a machine in a colleague's name; a guest's machine admitted by the guest. |
| Widening a machine's scope needs its owner's own fresh acceptance; narrowing is compared on effective sets (empty as all); owners and admins are told of every new machine and can only narrow or revoke | A machine widened behind its owner's back; a widening smuggled as a rename. |
| The account directory stores an enrolment code hashed only, and a connect code likewise, bound to one account and workspace for a day; a connect code routes an enrolment to that account's inbox and claims it, and is never what accepts it; every refused connect code answers with the same bytes after a per-address limiter | A directory reader claiming a pending key with a passkey; a guessed connect code steering a machine into someone's inbox. |
| Pending enrolments are listed only to the people the workspace's own access check says may act on them, at read time: owners and admins of the intended workspace (an unclaimed own-machine start is a deliberate discovery surface for them, so a machine never waits unseen), the account a connect code claimed it for, and whoever may admit it; by id, never by code; a plain member or guest reaches an unclaimed machine only through the code the agent printed. A claimed machine is accepted only by the claimed account, enforced where the device is created | One workspace's members seeing another's pending machines; a colleague accepting a claimed machine from a list or through the code route; an id page showing a machine to someone the code route would not. |
| An enrolment attempt has a 60 minute lease renewable by the key that started it, in place, to a 24 hour cap, stored once in the directory; the signed terms never include the lease; five wrong typed groups reject the attempt across any number of renewals | A renewal reviving a rejected or superseded link; a lease change invalidating a guest's stored acceptance; renewals resetting the guessing budget. |
| Device key, enclave sidecar, scope file, config and enrolment record reused only as regular files owned by this user, not symlinks, with no group or other bits; an owned state directory (`MEHEN_HOME`) and its slots are made private; an unsafe or symlinked ledger is not trusted as existing state | A planted or shared key becoming this machine's identity; a symlink pointing the key write at another file. |
| A key is scoped to the vault it was made for and refused, not replaced, for another | A changed `MEHEN_VAULT_URL` silently enrolling the same key elsewhere. |
| `MEHEN_WORKSPACES` only narrows what a process may use, resolved once per process; nothing inside a process widens it, and `mehen setup` writes it into every MCP entry it adds, never wider than the shell it ran in. It is an accident control, not an identity boundary; a separate `MEHEN_HOME` is a separate device | A work agent requesting a credential into a personal workspace, or a setup run from a restricted shell writing an unrestricted server. |
| A managed host's marker and version-3 pin are read under the user's home as the system's user database records it, looked up by uid, never from `HOME`; state-opening commands fail closed with `key_insecure` when that home cannot be resolved or its path is unsafe; pure help, guide and version output does not open the managed marker | `HOME=/elsewhere mehen ...` escaping a managed launcher's pin. |
| An installed `mehen` trusts only the release keys compiled into it and the file hashes a signed manifest names. Automatic updates must be newer than the running version, at least the highest seen and above any rollback hold; an explicit force or rollback is still signature-checked. The updater replaces the binary with one journalled rename under a lock ([Releases](keys-and-signing.md#releases)). | Whoever controls the download channel making installed machines run their binary; a downgrade to a release with a known hole. |
| A consuming app should draw a trusted vault card only for an ask from its own authenticated call, after checking exact origin, workspace and device context. Each app must enforce this boundary. | A lookalike link getting the vault's chrome, or an ask imported from another conversation or workspace. |
| Step-up on every change that widens access, rebuilt by the server and bound to the workspace it is spent in (`mehen-stepup/v2` with the workspace id as scope, `-` for account actions); only tightening actions while an account is cooling off or has a security change pending; during a recovery, only a sign-in with a passkey from before it can end other sign-ins; after a passkey assertion, a browser session may confirm graced actions for 15 minutes without the passkey (never sliding, never in an app's own prompt, never while cooling off or pending, ended by sign-out, a security change, the passkey's removal, suspension or **Ask every time**), each still single use over the exact rebuilt action and marked in the audit; any action that could widen access, or is signed as a digest, is always fresh | Agents or stolen sessions moving a credential; a step-up begun on one workspace's page spent on another's; a recovered account widening anything before its older factors have had their say, or ending their sign-in before it cancels the recovery. |
| Invites by owners and admins only (an owner for an owner), with complete terms signed; memberships active only after an eligible confirmer signs the exact terms, or, for an email-bound invite below owner whose signed terms say to let the person straight in, once the invitee proves that email and the inviter may still invite that role, so the inviter's passkey signature on the terms stands in for the second one; owner invites and open links always wait for a confirmer; email-bound invites redeemed only with a proof of that email, from Google or from a six-digit code emailed to it (which proves only that the person can read that mailbox, never a workspace identity rule) | A member, or a stolen session, letting someone else in; a stale invite activating more than was granted. |
| Intake tags and the credential's home shown to the human and signed in the submit digest; a machine may only propose a home within its reach | An agent quietly making a new credential usable by another machine, or shared with the whole workspace. |
| Overrides are chosen in the browser only, by the member, for their own private credential or a plain value, in unprotected environments, and apply to their own ticked machines only; protecting an environment clears them | A member's private credential reaching a colleague's or a team's run; a dormant override reviving when protection is loosened. |
| Events about a private credential are minimised before hashing: no hosts, paths or fields, even for the owner; non-elevated readers get a filtered chain | Owners and admins reading what a colleague did with their own credential; a guest reading the workspace's history. |
| Account recovery is separate from workspace rights: no workspace role resets another person's factors; recovery cancellation tightens first and lifts restrictions last | A co-owner taking over a colleague's account, and with it their private credentials, through a reset. |
| Joining or creating a workspace needs a way back in first: an unused recovery code, two passkeys, or one passkey whose authenticator reports it backed up (synced through a password manager). That report is read again at every sign-in and step-up, so a passkey that stops syncing stops counting from the next check, without ending any session. An account's first recovery codes, from its sign-up session within 15 minutes, need no step-up, since there are no codes to replace; any later set does, and so does an account with a synced passkey, which sign-up never asks for codes | A person in a workspace one lost device away from the operator's break-glass. A synced passkey survives a lost device, not a lost or taken-over password manager account. The backed-up flag is the authenticator's own claim and is not attested; a false one leaves only its own holder without a way back in. |
| Keyed secret fingerprints (HMAC under a per-workspace key from the root) | Offline guessing of passwords from stored data. |
| Device proofs with body hash, URL, 60 second skew and a nonce store | Bearer tokens on disk, replayed or reused requests. |
| Protected environments: literal `--env`, an allowed device whose owner holds the protected right, an approval by an eligible decider | Prod by typo, inherited variable or branch name; a member without the protected right running prod from a permitted machine. |
| Protected items: an item any protected environment's variable uses reaches only approved protected runs, and in item mode needs the explicit protected context and an approval; only an owner or admin can point a protected environment at a workspace credential | Leasing a prod secret through a dev variable or a contextless `mehen fetch`; an editor delegating a workspace credential to a guest's or a team's machine. |
| Fences enforced by the vault on every run-mode request, and early by the local relay | The wrong database at the wrong time, including through `mehen fetch --run`. |
| Run maximum life: 12 hours, 2 hours for approved protected runs. A service run (`mehen run --service`) has none, but only from a machine a human allowed (`serviceRuns`, granted only by a passkey-signed widening), in unprotected environments only, and planned again on every renewal, which ends it with `conflict` when a binding, override, delivery, credential or another environment's fence changed | A run, and its placeholders and approval, living forever by renewal. For a service run it no longer bounds how long its placeholders stay valid or how long its process holds a leased value: revocation, a freeze, narrowing the machine (unticking May run services), the re-plan and an expiry 15 minutes after the last renewal end it instead. A new fence reaches a service run's leased values only when its next renewal, up to 5 minutes later, ends the run; placeholder requests are checked against the current fences on every call. An approval never outlives its 2 hours, since no service run is protected. |
| The checkout's reported remote checked against the project's bound remotes (a workload whose scope names the project has no checkout and may send none, outside protected environments) | Accidental use of a project from a mismatching checkout. It does not attest the repository's contents or stop a hostile same-user process from changing or misreporting the remote. |
| Envelope encryption with AAD naming workspace, record type and id; one key per workspace | Ciphertext swapped between rows or workspaces. |
| Sealing secret fields in the browser | Plaintext in logs and tail sessions between the edge and the workspace's store. |
| Response scrubbing of raw, URL-encoded, JSON-escaped and supported base64 forms (not values shorter than six characters, not arbitrary transformations); gzip or br only from upstreams; no reason phrase; echoes flag the item for review | Echoed secrets reaching the agent in those forms, including in a compression the redactor cannot read. |
| Redirects not followed | Bouncing a credential to another host. |
| Run CA name constraints on both DNS names and IP addresses, path length 0, key in memory | A stolen run CA impersonating anything else. |
| Hash-chained audit, only appended by the application | An inconsistent edit or deletion. A storage or deployment authority could recompute or truncate the chain; a head saved outside the vault detects that. |
| Freeze and revoke, per workspace; removal of a person revokes their machines, deletes their private credentials and voids their decisions in one transaction | Further misuse through Mehen once noticed; a leaver's machines or decisions outliving them. Neither recalls a request already sent, undoes provider-side effects, erases a leased value or an exported backup, or revokes a credential at its provider. |
| Platform proofs: the platform's P-256 signature over method, URL, body hash, time and a nonce, in its own header and `typ`; keys registered by the operator, looked up on every call, rotated with an overlap, revoked at once | A platform credential on disk or in a log being replayed; a device proof passing for a platform's, or one platform's key acting as another. |
| One managed workspace per subject, its own store under its own key, found from the verified platform and the subject; any miss is `not_found`, exactly as absent; no account, page or invitation can name one | One user of a platform reaching another's credentials; one platform reaching another's users, or anyone's own workspace. |
| In a managed workspace, a credential's binding, injection and ceiling never change, and a managed device never leases, mints, signs or reveals | A platform turning use into reading by pointing a stored credential at a host it controls, or asking for its value. |
| A platform's decision names the approval's digest, serves one use of that exact request by the workload that asked, for at most 15 minutes, and is audited with the platform, its key, the proof's nonce and the platform's reference | A platform decision becoming a standing grant, or approving a request other than the one it read. |
| A platform's defaults may only hold or refuse; a managed credential's policy is computed at each use from the catalogue's current policy plus those rules, a key with no template failing closed; a change stales approvals given under the old ones | A platform loosening the catalogue's holds and refusals for its users; an approval outliving the rules it was given under. |
| A platform's limits and rate limits keyed by the verified platform and subject; suspension by the operator, at once for the platform's calls and within 30 seconds for its devices | A runaway or hostile platform filling the vault, or acting after the operator stopped it. |
| Every audit row in a managed workspace names its platform, and the chain's first link binds the platform and the workspace | A platform's actions going unattributed; one workspace's chain passing for another's. |
| The operator console: the operator role changes in the app only when two operators agree (one proposes, a different one approves within 24 hours, and a new operator accepts with their own passkey), or from the operator's own machine; every other account gets `not_found`, exactly as absent; an operator account needs recovery, two passkeys with one a security key, no cooling-off and no pending security change for any write; every write needs that account's fresh passkey (at most five minutes old, used once) bound to the platform, the command and its digest, a destructive one or one that adds a key the slug typed back; each is recorded with the account and gives it a notice, and a key added also notifies every operator account and the platform's other admins | A session or a page alone changing a platform; a stolen session without the passkey doing anything but read; an operator write going unrecorded or unnoticed by the operator. |
| Platform admins: added and removed only by the operator, with a passkey; see only the platforms they administer (every other is `not_found`); every change needs their own passkey and is recorded with their account; never the last live key; the same plans and refusals as the operator's | One platform's admin reaching another platform, doing the operator's work, or leaving a platform without a key. |
| A managed workspace's OAuth app is the user's own, its client secret sealed in their browser; Mehen exchanges the code with that secret, and with a PKCE verifier wherever the provider supports it; the state is single use and found only in the named subject's workspace | A platform, or anyone holding the code its callback received, getting the user's tokens; one user's code completing another user's connection. |
| An OAuth app with its own provider definition takes only https URLs on public host names, no user names, IP addresses or private names, and must have a client secret; its definition and destination are fixed with it, its client secret is bound to the token URL's host and path by `POST`, and its connections' policy holds every request unless the platform's defaults let reads through. The vault's outbound requests run on its host's network, which cannot reach private networks, so a custom provider's hosts are checked by name, not by resolving them | A custom provider pointing the vault's token request, or a token, at an internal service; the app's client secret going anywhere but its token URL; a connection to an unknown API acting without a decision. |
| The identity gate: a workspace may require a verified Google identity on its domains for covered roles, checked at new sessions, acceptances, admissions and widenings and re-checked on rule change, promotion or unlink; Google only identifies, a passkey still authenticates and signs; Google is never a recovery path | A person who left the company, or never had a company identity, keeping or gaining a covered role on a still-valid passkey; a Google account standing in for a passkey. |

## A vault on your own machine

With `mehen up`, the vault runs on the same machine as your agents, as your own user, at `http://localhost:7787`. The engine is Mehen Cloud's, so bindings, policies, approvals, scrubbing and the audit chain work the same way, and every section below holds for it except where it says Mehen Cloud. What differs is where the root key and the stored data are: in files in the vault's data folder on this machine. The operator and the host are you and your machine.

**What it protects against:**

- **Keys in the model's context, transcripts, logs, shell history and `.env` files.** The agent asks the vault to make the call (relay) or gets a placeholder (`mehen run`), and never handles the value.
- **An agent sending a key to a host it is not bound to.** The vault refuses it before anything is sent, as on Cloud, whatever the agent was told.
- **An agent reading a key file, or pasting a key into a command or a file**, by accident or because a page or a file told it to: the [guard hooks](../guides/guard.md) block it in Claude Code and pi.
- **Other machines, and web pages.** The vault listens on the loopback address only and answers only requests addressed to `localhost` or `127.0.0.1` on its port, so another machine cannot reach it and a page that points a name of its own at it is refused.
- **Other user accounts on this machine.** The vault refuses to start unless its data folder is yours and closed to everyone else (mode 700), with no folder above it that another user can write, so no other account can read or replace its files. Another account can reach the port, and like anyone needs a passkey or an enrolled machine's key to do anything there. While the vault has no account, a one-time code in a file only you can read lets the first person sign up; it is gone once your account exists.

**What it does not protect against:**

- **A determined program running as you.** On a Mac the root key and the seal key are sealed by the Secure Enclave, on a Linux desktop they are in your login keyring, and otherwise they are in `keys.json`; each workspace's data is in SQLite files in the data folder, readable and writable by your user. The Secure Enclave seal has no Touch ID prompt, so a program running as you can ask it to open the keys, as it can read an unlocked keyring or `keys.json`, and then decrypt every stored key, or edit the files and change what the vault holds. An agent's shell runs as you, so it could too if it set out to; the guard reads command lines, which such a program can disguise.
- **The running process, on macOS.** On Linux the vault makes itself undumpable, so another program running as you cannot attach to it or read its memory, and the root key stays out of core dumps. That protects the process, not the files.
- **Copies of the data folder, where the keys are in a file.** On a Mac or a Linux desktop with a login keyring, a copy of the data folder (a backup, a synced folder, a stolen disk image) cannot be opened on another machine: the keys stay sealed by this Mac's Secure Enclave or in your keyring. Elsewhere the copy holds `keys.json` with the data, and whoever has it can read every key. The vault's own daily dumps are in the same folder, on the same disk. `mehen doctor` says which applies to your vault.
- **Windows** is not supported yet.

**How to close the gap:**

- **Run the vault on another machine you own** ([Run it on another machine](../start/another-machine.md)). The agent's machine then holds only its device key, and the vault's files are on a machine the agent has no shell on: only a program running as the vault's user there can read them.
- **Turn on Claude Code's sandbox, then run `mehen guard install` again.** The install adds the vault's data folder to the sandbox's read and write deny lists, so the operating system stops the agent's shell reading or changing the vault's files, while `mehen mcp` and the hooks, which Claude Code runs outside the sandbox, still reach the vault. Only Claude Code's sandbox is covered today.
- **A separate-user mode**, the vault running as its own user on the same machine, is planned and not built.

## Actors

### A prompt-injected agent

An agent that has read hostile text (a web page, an email, an issue, a dependency's README) and now follows someone else's instructions, with the full rights of the device it runs on.

**Can:**

- Use every credential its device's reach covers (its scope, under its owner's rights: the workspace's credentials for a member's machine, the referenced credentials of shared projects for a team's or a guest's, the owner's private credentials on a ticked machine), in every mode its device and the item's ceiling allow, against the hosts and paths the binding allows, within policy.
- Misuse a capability without seeing a secret: read mail the connection can read, delete what policy allows it to delete, and move data (not credentials) out through a write API on a bound host, for example by writing an email's contents into a GitHub issue with an allowed token.
- Ask a human for things: open intakes with misleading reasons, ask for tags, open connect links, and ask for approvals with a persuasive story.
- Propose a standing rule or a task grant with a persuasive reason, and once a person turns one on, repeat that request shape, or build in those areas, without asking until it ends.
- Propose a mandate with a persuasive note and, once a person signs one, send held requests of the kinds it names, with the credentials it names, without asking until it ends: sends and deletes included, and on a service nobody has reviewed, any request whose method, path, query names and body shape the floor does not name. Each kind stops at its daily cap, and more than 120 requests beyond reading in a minute trip the whole mandate.
- Pause its machine's mandate, as any process with the machine's key or a workload's can: a pause only narrows.
- Ask for many writes at once (a plan of up to 20) or keep asking one at a time, so that a person decides them together on one page. The page sorts each ask by what it does, not by what the agent says.
- Type a credential into a page its lists name, once a person allowed fill for that credential and that machine, and, with an approval, its password or a one-time code.
- Ask for a credential a person allowed to be pushed to be put into a GitHub, Vercel or Cloudflare secret store of its choosing, with a persuasive reason.
- Pull the brake (`mehen freeze`) or revoke its own device. That is denial of service, available to any device whose owner is not a guest, by design.
- Fill the machine's queue with asks: the cap is 20 open asks per machine, which bounds the noise, not the persuasion.

**Cannot:**

- Read a secret value in relay or placeholder mode: no API returns one to a device (R1, R8).
- Send a credential to an unbound host, over an unlisted scheme or port, or through an ambiguous path (R2).
- Dodge a deny or approve rule by encoding or re-casing the path.
- Put a placeholder or secret into a body, query string or undeclared header and have it substituted (R9).
- Change a binding, ceiling, policy, tags, fence, protection, home or device scope, or move an existing credential: these need a passkey step-up (R5, R10).
- Approve anything, or reuse an approval for a different request: approvals need a passkey, an eligible decider and are bound to the request digest (R6).
- Turn a standing rule or a task grant on, widen or extend one, or have one cover a send, a payment, a share, a delete or a protected context: only a person's passkey makes or extends a rule, over terms the vault built.
- Set how careful a credential is, or add a page fill may type into: only a person, with a passkey.
- Sign, renew, resume, stop or widen a mandate: only the machine's owner signs, with a fresh passkey over terms the vault built, and only they resume. Nor have one cover what it never covers: minting or reading credentials, webhooks, forwarding, inbox rules, SSO, members, invites, permissions, sharing, publishing, money, a live key, a request the vault cannot read, a host only a wildcard in the binding admits, a protected credential, environment or run, a workload's request, or a push, fill, lease or reveal.
- Go past a mandate's caps or its rate, keep one covering after its signer's standing changed, or learn why it is not covering.
- Have fill type a value into a page that is not on the credential's lists, into a frame from another origin, into a hidden field or over http.
- Read a value it asked to push, allow a credential to be pushed, or push one without a person approving that push on its own page: no rule, task grant or posture covers a push.
- Reach a protected environment through `MEHEN_ENV`, a default or a branch name, or get a protected item outside an approved protected run in the environment that references it (R4).
- Do more than its owner: use a project its owner is not shared on, a credential outside the owner's homes, or anything at all once the owner is suspended or removed. Naming what is out of reach tells it nothing: absent and forbidden answer the same.
- Use a key outside its workspace, or make the running MCP server serve an identity outside its admitted ceiling or replace a latched device. A spanning server can deliberately use several admitted workspaces; `MEHEN_WORKSPACES` is an accident control, not same-user process isolation.
- Make a human act in the wrong workspace: every link it can hand over is under the canonical slug of the workspace the call was made in.
- Lease a value whose ceiling is `reveal`.
- Send mail through Gmail drafts, Graph `$batch` or a stored Graph message without an approval that shows it.

**Honest limits:**

- **Lease mode exposes the value to the process.** If an item's ceiling is `lease`, and the device and the run allow it, the agent can make the child print, transform or send the value. Redaction will not catch a transformed value. Lease is off by default for that reason.
- Inside the binding and policy, the capability is the agent's to misuse. The vault narrows the blast radius; it does not judge intent. Templates allow reads and a few narrow everyday writes without asking, and an injected agent can misuse exactly those: read everything the credential can read, and make the allowed writes.
- A shared machine's capability belongs to everyone who can drive it. A team's machine on a chat platform or in CI acts for whoever can make it act; Mehen authenticates the machine and caps it at the team's shares, not the person behind the message, and removing that person from Mehen does not remove their access to the machine.
- Intake and approval pages rely on a human reading them. A custom destination is shown in red with the host spelled out, tags are shown, the decision card and the request are shown, hidden characters are marked, the binding code must match and Deny leads when the page warns, but a tired human can still approve the wrong thing. A body that is not text cannot be read meaningfully by a human, so approving one is approving it largely unseen.
- A protected run's approval binds the whole command line (its SHA-256), not what the command does: an approved `bun deploy` runs whatever the scripts at that commit say.
- The session label is the agent's to choose. Pages never read it to say who asked, but it is shown in the details and in `mehen pending`, spelled out, and an agent can make it misleading.
- A standing rule lets the agent repeat its request shape unattended, as often as it likes, until the rule ends. Uses are counted and shown on the credential's and the machine's pages, but there is no rate cap. A GraphQL rule pins the mutation's fields, not its variables: a rule for `commentCreate` posts any text on any issue the key can reach. A REST rule likewise pins the request's shape (method, host, path and query names), not its body.
- A task grant lets the agent make any routine building request in its areas, up to its uses, with bodies nobody reads: a Workers grant uploads any script the key can deploy.
- **A mandate is the widest standing approval.** Under one, the agent can do each day, unseen, as much of each kind it names as the caps allow (by default 50 sends, 20 deletes, 2000 changes and 5000 reads a day, for up to 90 days), with bodies nobody reads first. The receipts say what went through, afterwards. On services Mehen has reviewed (GitHub, Stripe and Cloudflare), the never list holds route by route. On a service nobody has reviewed, Mehen judges a request only by its method, path, query names and body shape: a payment, a share or a new key made through a route whose path and body name none of those goes through as a change or a send. The sign page says so before the passkey. Few kinds, few credentials, low caps, a schedule and a short length narrow it, and a pause stops it at once. A machine cannot ask for more than it has used: the vault refuses a machine's proposal that names every credential, or a credential or kind besides read that the machine has not asked for in the last 30 days, so wider terms are always the signer's own choice on the sign page.
- A posture has no end and no cap on uses; each use is in the audit. One that lets routine building through lets every route the reviewed list marks routine through, with bodies nobody reads, on every machine that may use the credential and belongs to an active member who is not a guest or to a team (only the machines it names, when it names some), until a person sets it back to ask or the credential moves to another home. A trusted posture lets through everything but the floor on the managers' own machines, including routes nobody has reviewed.
- Deciding together relies on a person reading a list. Every ask the person may approve that no floor reason names and that is not decided on its own page starts ticked, including a write to a route nobody has reviewed. The floor, a protected credential's use and an ask that a newer one of the same shape follows start unticked, and the page says why each floor row needs a look, but ticking every row is still possible.
- **Fill gives the page the value.** Once typed, a script on that page can read the field before the form is sent, and an agent running script in its own browser is such a script. Fill stops lookalike pages and leaks into transcripts and screenshots, not an agent determined to read the value. It is opt-in per credential for that reason.
- **A push puts the value where others can read it.** Once in a provider's store, whoever can run or change the workflows, deploy the project or change the Worker can read it. The card says who, and marks a new destination, a fork and a public repository, but a person who approves a push to a repository the attacker controls has handed it the value. Mehen cannot take a push back; deleting the credential leaves every copy where it is.
- `mehen check` is advisory: it runs the vault's matcher on public metadata, locally. A wrong local answer cannot loosen anything, because the vault evaluates the real request on its own, but an agent that trusts it instead of the vault's answer can still be surprised.
- Response content is attacker-controlled. The vault scrubs secrets out of responses; it does not make their content safe to follow.
- The vault cannot tell one process from another. Any process on the device, not only the agent, can use the device's capabilities.

### A compromised machine

Malware, or a hostile process, running as the same user as the agent on an enrolled machine.

**Can:**

- **Use the device key as a signing oracle.** A Secure Enclave key cannot be copied off the machine, but any process running as the same user can ask it to sign. So the attacker has every capability of the device, for as long as the machine is compromised and the device is not revoked, including creating workloads up to the device's scope and using any workload key it can read.
- Read lease values from a leased child's environment or memory, and placeholders from any run's child. Placeholders are worthless outside their run, but the run's local relay is on the same machine while the run lives.
- Watch the human's screen and try to talk them into approving something.

**Cannot:**

- Copy a Secure Enclave key off the machine, so revoking the device ends the attacker's access to the vault.
- Read relay-mode secrets, or a value it pushes: they never reach the machine. With the vault on the same machine, they are in the vault's files, which a process running as the vault's user can read ([A vault on your own machine](#a-vault-on-your-own-machine)).
- Approve: approvals need a passkey assertion with user verification, normally on another device. If the human's passkey is on this same machine, the attacker still cannot produce an assertion without the human's touch or face, but can try to trick them into giving one.
- Widen the device's scope or move credentials (step-up).

**Honest limits:** The device key proves which machine is asking; it does not prove which process. Telling one process from another on the same machine is not built; a harness that gives each task a [workload](#a-task-running-as-a-workload) gets a key per task the vault can tell apart, but whoever can use the device key can create new workloads up to the machine's whole scope. A `software` device key is a 0600 file and can be copied, after which the attacker can sign from anywhere until the device is revoked. A browser on this machine whose session confirmed with a passkey in the last 15 minutes is inside the window: a process that can drive that browser or read its cookies can decide approvals and take the other graced actions without a fresh passkey until the window ends, as [someone holding the session](#someone-holding-a-persons-browser-session) can. **Ask every time** on the account page ends it. Whatever the machine's mandate covers goes through for the attacker as for the agent, within its caps, until someone pauses it. [A machine or a key is compromised](../guides/incident.md) is the playbook.

### A machine adopting credentials

A machine, compromised or not, that sends values with `mehen adopt`, including under names the vault already holds ([Values already in the vault](../guides/adopt.md#values-already-in-the-vault)).

**Can:**

- Send a value under a name the vault holds, or another machine staged, to be compared with it.
- Propose its value in place of a stored one. Only a reviewer replaces it, with a passkey.

**Cannot:**

- Learn anything from a comparison. The vault gives the same answer, and does the same work, for a row sent to be compared as for any other row, and no answer to a device carries a result: a batch's status says only `created`, `mapped` or `replaced`, and `mapped` stands both for a value the vault already held and for a differing one the reviewer kept the vault's for. `mehen adopt inventory` reads only those device answers. A name held by a credential the machine may not see is refused as any taken name is, so sending one tells it nothing new.
- Grind one credential with guesses. A batch may compare one row with a given credential, and a stored credential is compared at most 10 times a day, after which the result is recorded as not compared. Every comparison is audited with the credential and never its result.
- Replace or restore anything itself. Replacing is a reviewer's decision, which needs the right to rotate the credential and to change any protected environment that uses it; restoring is a person's, with a passkey, and a machine never restores.

**Who sees a result:** only a reviewer who may see the batch and the credential or row holding the name. For short or guessable kinds (password logins, basic auth, SMTP or IMAP, one-time code secrets and generic secrets), only someone who may rotate or reveal the stored credential sees one, and never against a staged row. Keeping a value under another name spends the reviewer's name budget as any new name does: twenty unavailable names in an hour, then rate limited.

**Value history:** a value that a rotation or a replace overwrites is kept sealed, exactly as it was stored, for 30 days; it is never shown, and only a person who may rotate the credential restores it, with a passkey. An OAuth connection keeps none. A kept value is deleted with its credential, including when offboarding removes a member's private credentials, and restoring a value that a member who has since left saw flags the credential for review at once, as offboarding does.

**Honest limits:** a reviewer who sees a result learns whether two values agree, which is why, for a short or guessable kind, that needs the right to rotate or reveal the credential. A replaced value stays in the vault for 30 days, so someone who may restore can put an old key back in use; when a value was exposed, rotate it at the provider too.

### A task running as a workload

A task (a conversation, a CI job, a subagent) that a harness runs with its own [workload](../concepts/machines.md#workloads) key and not the device key, and that is now prompt-injected or hostile.

**Can:**

- Use what its workload's scope covers, within the machine's scope and its owner's rights, the bindings and policy, until the workload expires or is revoked.
- Ask a human for things, as itself: its asks show "Task: <label>, as the machine named it" under the machine's name, and the label is the harness's choice, not a verified identity.
- Wait on, cancel and spend its own asks and grants.
- Sign from anywhere until it ends, if it has its workload's private key: that key can be copied.

**Cannot:**

- Reach a credential, project or mode outside its workload's scope, whatever the machine's scope allows.
- Create a project, or rebind or overwrite a project variable bound to a credential outside its scope.
- Set, change or unset a plain (non-credential) project variable in a project its workload's scope does not name in `projects`: a workload scoped only by items or tags changes no plain variable.
- See, wait on, cancel or spend another workload's asks, grants or runs: they are `not_found` to it.
- Create, renew, list or revoke workloads, or revoke its machine: only the machine's own key may.
- Freeze the workspace: freezing stops every member and machine, so one task never may; the machine's own key and people still can.
- Use a grant or a standing rule made for its machine's own key or for another workload: every grant and every rule serves only the key that asked, and a workload's rule ends with the workload.
- Act after it ends: the next request after expiry or revocation, or after its machine is revoked, is `workload_ended`.

**Honest limits:** Workloads limit what a task can do, not who holds the parent key. Whoever holds the device key (the harness, or anything that compromises it) can create new workloads up to the machine's whole scope, so the device key must stay with the harness and never reach the task. A task given the device key, or able to ask it to sign, is the machine. A workload's own key bounds a task only as far as its scope and its life do.

### A run's own program

The program `mehen run` starts, which may be hostile (a malicious dependency) or simply careless.

**Can:**

- Read every value the run leased, and every placeholder.
- Send placeholders anywhere. **Tunnelled traffic is never swapped**: a placeholder sent to a host the run does not intercept travels as a worthless string, and the vault never sees it, so it is not recorded as a tripwire either.
- Ignore `HTTPS_PROXY` or the run's CA (Go on macOS and some older Python builds ignore the CA variables), in which case its placeholders go straight to the upstream and fail.

**Cannot:**

- Get a placeholder swapped at an unbound host, outside the declared surface, or at a host fenced to another environment: the vault refuses and records it.
- Use the run's CA for anything but the bound hosts: its name constraints cover both DNS names and IP addresses.

**Honest limits:**

- **Fences match host names only.** A CNAME alias inside a wildcard binding is not caught: with an item bound to `*.example.com` and `db.prod.example.com` fenced to prod, a dev run reaching `alias.example.com`, a CNAME for the same server, is allowed. The vault never resolves DNS. The local relay refuses CONNECT to raw IP addresses while a run has fenced or intercepted hosts, and the vault relay refuses IP addresses unless bound exactly, but neither can see where a name points.
- **The local relay's refusals are not audited.** A fenced host or an IP address refused by the local relay is refused on the machine; the vault never hears of it. Only requests that reach the vault are in the audit chain.

### A malicious upstream

An API the credential is bound to that misbehaves: echoes the secret back, redirects elsewhere, or returns hostile content.

**Can:**

- See the credential. It is the destination; that is unavoidable.
- Echo it back in some form, or put hostile instructions in a response.
- Redirect.

**Cannot:**

- For supported representations of values at least six characters long, get the echo past the scrubber in its raw, URL-encoded, JSON-escaped or supported base64 forms, in headers or body. A detected echo also flags the item for review.
- Hide an echo in a compression the vault does not decode: the relay asks for gzip or br only and refuses any other content coding with `upstream_failed`.
- Pass free text past the redactor in the reason phrase: it is dropped.
- Bounce the credential to another host: the relay calls upstream with `redirect: "manual"`, and any redirect must come back through the binding check.
- Move the credential's destination with a token response: OAuth token and identity URLs are fixed in templates, and agents cannot set token URLs or scopes outside the allowed set.

**Honest limit:** Redaction cannot catch a transformed value (reversed, split, hashed, re-encoded in a way not listed, encrypted). Values shorter than 6 characters are not redacted at all. Hostile response content reaches the agent.

### A stolen laptop

A thief, or a finder, with an enrolled machine.

**Can:**

- Use the device key if they can log in as the user, or if the machine was taken unlocked: Secure Enclave keys use "after first unlock" protection so background agents keep working while the screen is locked.
- Send whatever the machine's mandate covers, within its caps, until someone pauses or stops it.
- Read a `software` key file from an unencrypted disk.

**Cannot:**

- Find cached vault credential values in `mehen`'s own files: per active workspace slot, the CLI stores its config, device key or enclave blob and public sidecar, scope and non-enrolment ask ledger. A pending slot holds the key and `enrolment.json`, including the public JWK, requested intent and lease. There are no cached credential values or bearer sessions; a software device private key is nevertheless a sensitive signing credential. Ask links require a signed-in eligible human and the required passkey ceremony to complete.
- Extract a Secure Enclave key.
- Approve anything without the human's passkey.

**Honest limit:** a laptop that runs the vault itself carries its data folder. Whoever is logged in as the user can open every stored key. Whoever reads an unencrypted disk from elsewhere can too where the keys are in `keys.json`; where they are sealed by the Secure Enclave or in the login keyring, the disk alone does not open them. Turn on the operating system's disk encryption, or keep the vault on [another machine](../start/another-machine.md).

**What to do:** pause or stop its mandate (no passkey; **Pause all** on the mandates page pauses every one at once), then revoke the device from the browser (passkey step-up `device.revoke`, in each workspace it was enrolled in), or freeze the workspace first if unsure. See [A machine or a key is compromised](../guides/incident.md).

### Someone holding a person's browser session

Someone with a person's signed-in session in the vault's pages, from a stolen cookie or a browser left open, but not their passkey.

**Can:**

- Read what the person can read, and do what needs no passkey: pause or stop a mandate the person may pause or stop, stop a standing rule or a task grant, freeze the workspace.
- Resume a mandate the person signed that they or its machine paused, while they still stand where they signed: that resume needs no passkey, by design.
- Inside the 15 minutes after the person's own passkey confirmation in that same session, take graced actions without the passkey: decide approvals, one at a time or up to 25 together; deny a standing rule or task grant proposal; store a credential from an intake; start an OAuth connection; push a credential again, restore it or delete it; create a project; narrow or revoke a machine, or revoke a workload; resume a mandate an owner or admin paused. [The 15-minute window](../concepts/approvals.md#the-15-minute-window) has the whole list. Two of these are recorded residual risks. Deleting a credential destroys its value and its history, though it widens nothing. Storing a credential from an intake can create one in the workspace that may be read or typed into pages, from a value the holder supplies, which exposes nothing already stored.

**Cannot:**

- Sign, renew or widen a mandate: a signature is always a fresh passkey over the terms, window or not.
- Resume a mandate after a trip or a lapse, which always needs a fresh passkey, or, outside the window, one an owner or admin paused.
- Do anything that is always fresh, window or not: change passkeys, recovery codes or linked identities; accept, admit or widen a machine; approve and allow from now on, or approve a standing rule or task grant; set a credential's posture above asking; change a credential's binding, policy or ceiling; invite, promote or remove anyone; share a project.
- Do anything else that needs a passkey once the window has ended, or carry the window to another browser, a new sign-in or an app's own passkey prompt.

**What to do:** **Ask every time** on the account page ends the window at once. **Sign out everywhere** ends every session and every window with them; it also lapses every mandate the person signed until they resume each with their passkey, and their machines stay enrolled.

### Someone who learns an enrolment code

Enrolment codes travel in URL paths: `/w/<slug>/e/<code>` and the workspace's `/enrolments/<code>` API. A code can end up in browser history, request analytics or a pasted transcript. The inbox and the id form (`/w/<slug>/e/enr_<id>`) never carry it.

**Mitigations:** a link is served only under the workspace it was started in, so a code cannot be claimed into another workspace; only the person whose machine it is can accept it, with a step-up that signs the key's full thumbprint, their own account and the complete scope, so they accept exactly the key whose fingerprint they checked; they must type the hidden fingerprint group, which the page never carries and which the server checks with five attempts per row before the row is rejected; the code is stored hashed; the attempt lives 60 minutes, renewed in place by the machine that started it while something waits, never past 24 hours, and while nothing waits it lapses and cannot be accepted until the machine returns; a new attempt for the same key supersedes the older one, so there is one live link per key; the CLI checks the activated workspace against the one it asked for and, on a mismatch, writes no config, attempts to revoke the device and reports whether that succeeded, naming the device for a human to revoke when it did not.

**Honest limits (low, deferred):** while an enrolment is pending, another active member of the same workspace who learns the code could accept the machine as their own; the CLI then reports it enrolled under that owner's name, which the human at the terminal should read. The typed group does not stop this on its own: the page's gate hash is a 20-bit preimage, so whoever holds the page can recover the group offline; it is a forcing function for the honest owner to look at the terminal, and the server's five-attempt cap is what stops guessing through the page. Moving the code into the URL fragment, as invites already do, is deferred. An enrolment started with a connect code can be accepted only by that account, so this limit does not apply to it. A member who holds a superseded id learns that a newer link exists for the same machine and intent only when the inbox would have shown it to them anyway, and never the link of a differently claimed or differently intended attempt.

### Someone who guesses connect codes

A connect code is 8 characters from a 31-letter alphabet (about 40 bits), stored as a hash and matched exactly, so it cannot be searched prefix by prefix; starts with a code are limited to 20 a minute per address. A right guess claims a new enrolment for the code's owner, which lands in that owner's Needs you; it accepts nothing.

**Honest limits:** every refused code answers with the same bytes, but not in the same time: a well-formed code that still matches a suspended member's row costs one more workspace lookup before the same refusal, and a workspace that is unavailable at that point answers with an error instead. That distinguishes a matching suspended member's code from an unknown one; it reveals no account or workspace name. The per-address limit bounds one address; many addresses guessing many live codes raise the odds, so it is not a bound on a distributed guesser.

### Someone who holds an email-bound invite link

An invite link can be forwarded, pasted or seen over a shoulder. Its invitation is bound to one email, and redeeming it needs a proof of that email: Google's, or a six-digit code Mehen sends to that address and that must be typed back in the browser that asked for it.

**Mitigations:** the code goes only to the invitation's own address, never one the requester types; it is drawn uniformly from a million, stored only as a keyed hash, lasts ten minutes and dies after five wrong tries. An invitation is sent at most three codes an hour and five a day, and takes at most ten wrong tries a day across all its codes; each limit is a condition of the database write it guards, so requests in parallel cannot pass it. Over its seven days an invitation therefore takes at most 70 wrong tries, about a 0.007% chance of a right guess. Past a limit the page says to verify with Google or ask for a new invitation.

One address is sent at most five codes an hour and ten a day across all its invitations, however many invitations name it, so making many invitations cannot flood an inbox from `mehen.dev`.

An inviter cannot use Mehen to mail arbitrary text: the invitation email goes only to the invitation's own address, carries no text the inviter chose beyond their name and the workspace's (each replaced when it looks like a link), and is limited to 10 an hour and 30 a day per inviting account and 3 a day per address. The per-address limit is shared: anyone who can invite in any workspace can spend an address's three emails for the day, after which an invitation to it says the email was not sent and the inviter copies the link to them instead; that answer also tells an inviter under their own limits that the address has had three invitation emails that day, and nothing more.

**Honest limits:** each new code ends the invitation's earlier ones, and the sends count against the invitation and the address, so whoever holds the link can spend the invitee's codes and delay the email path. They cannot use it, since the code goes only to the invitee's inbox, and Google still works.

### A platform

A business that builds on Mehen and holds a platform key ([Platforms and managed workspaces](../concepts/platforms.md)), or whoever has taken that key or the platform's servers.

**Can:**

- Create and delete its users' managed workspaces, provision devices in them, and through those devices' workloads use every credential in them, within each credential's destination and policy.
- Decide every request Mehen holds in its workspaces. A decision serves one use of that exact request, for at most 15 minutes, and the audit names the platform and its key.
- Add keys, OAuth apps and connections for its users, and set defaults that make the catalogue's policies stricter for all of its workspaces at once, or let keys with no template be read without a hold.
- Read its users' audit, freeze and unfreeze their workspaces, and delete one user or all of them.
- Capture a key while its user types it, if its own page is hostile, or open a request for a host it controls so that a newly typed key goes there: the page is the platform's, and Mehen cannot see it.

**Cannot:**

- Read a stored credential: no route returns a value, its devices cannot lease, mint, sign or reveal, and a stored credential's destination never changes.
- Be led by one of its workloads into storing a newly typed key under terms only the workload chose: when a workload opened the intake and named the key's host and injection with no template, the submit must carry the binding and injection the platform showed its user, equal to the workload's, or it is refused.
- Make a template's policy looser, reach another platform's workspaces, or reach anyone's own workspace.
- Get a user's OAuth tokens from the connection flow: the client secret was sealed in the user's browser and only Mehen holds it, so the code its callback receives is useless without Mehen, and Mehen also binds the code to a PKCE verifier wherever the provider supports one.
- Act after Mehen's operator suspends it: its calls stop at once, its devices' within 30 seconds.

**Honest limits:** the platform says which of its users is signed in, and Mehen cannot check that. A hostile platform harms only its own users, but all of them, within its limits, until it is suspended. A platform that runs a separate OAuth flow of its own, outside Mehen, can of course get tokens of its own; that is not Mehen's flow. A user's own OAuth app is theirs at the provider: Mehen cannot check how the user configured it. A custom provider's URLs and hosts are checked by name only, when the app is stored and again at every connection and refresh: they must be https on a public host name, never an IP address or a private name such as `localhost` or `*.internal`. Nothing resolves them first, because the vault makes every outbound request from its host's network, which cannot reach private networks; a public name that resolves to a private address reaches nothing there. What the checks cannot judge is whether a public host is honest: a custom provider is as trustworthy as the service it names, which is why its connections hold every request for a decision.

Platform-owned OAuth apps, one app of the platform's at Google, GitHub or Microsoft serving all of its users, are not offered yet; every connection uses the user's own app. Public OAuth apps, with no client secret and PKCE alone, are not supported yet either: their intake is refused, so every app's code is useless without a secret only Mehen holds.

### The operator

On Mehen Cloud, someone who can see the service's dashboard, logs and storage, but does not deploy code. On a vault on your own machine, that is you, and anything running as you.

**Can:**

- See the account directory: accounts, workspaces and their slugs, memberships and roles, passkey public keys, hashed session tokens and recovery codes, hashed invite codes and their terms, Google identity subjects and emails, emailed invitation codes (each a keyed hash under the root key, with the invited email, its browser's hashed cookie and its attempt count), challenges, enrolments (the code hashed, the public key, the name, host, start context, status and wrong-group attempt count) and hashed OAuth state values. No secrets, and no enrolment code in the clear.
- Write the account directory, where the dashboard allows it, and so forge a session or a passkey: a directory writer, like a deployer, is a trusted takeover path, not a cryptographic one.
- See the service's logs. These never carry secret values, tokens, codes or nonces, and request logs are switched off because they would carry URLs and headers.
- See audit events (slugs, ids, hosts, field names).
- See each workspace's stored data: ciphertext, each field under its own data key, plus each secret's length, well-known prefix and keyed fingerprint.
- See each platform's registration: its keys' public halves, its status, limits and defaults, its subjects and their workspaces' status, and its recent activity in counts. Register, suspend, resume, retire and remove a platform, set its limits, rotate or revoke its keys, and add or remove its admins, from the operator's own machine or from the operator console in the web app ([An operator's session in the web app](#an-operators-session-in-the-web-app)).

**Cannot:**

- Decrypt stored secrets without a root key.
- Test password guesses against fingerprints: they are keyed with a key derived from the root key.
- Read secrets sealed in flight without the seal key.

**Limit:** metadata is visible: which items exist, their hosts, who used them and when, and how long each secret is.

### An operator's session in the web app

The operator console puts the operator's platform work in the web app, on the accounts holding the operator role. Before it, no web route could change a platform. This is what someone gets with one operator account's signed-in session, and with its passkey too.

An operator account must have recovery set up, at least two passkeys with at least one of them a security key, no cooling-off after a recovery and no security change pending; without all of them it can read but not write.

**With the session alone, can:**

- Read what the console shows: every platform's status, limits, keys' public halves, defaults, subject counts by status, the last day's usage in counts, its admins and its events; and every workspace's name, slug, id, status, who created it, its owners by name, its people counted by role, whether it is frozen, its dumps and restores, and its operator events.

**With the session alone, cannot:** change anything. Every write needs a fresh passkey assertion from that account, made for that platform and that exact command, at most five minutes old, and used once; a replayed or reused assertion is refused.

**With the session and the passkey, can:**

- Register a platform with a key of their own, and so serve users of their own through Mehen.
- Suspend, retire or remove any platform, which stops it and its users' agents, and with removal deletes every one of its users' credentials for good: denial of service and destruction, within the platforms that exist.
- Delete every user of a platform, revoke its keys (and so stop it) or add a key of their own to an existing platform, which lets them act as that platform toward its users ([A platform](#a-platform)) until the key is revoked.
- Change a platform's limits, and add or remove its admins.

**Cannot, even with both:**

- Read a stored credential, or see or act inside any workspace, managed or anyone's own, through the console: no console route reaches one, beyond freezing it and, with a second operator, restoring it ([Freezing and restoring a workspace](#freezing-and-restoring-a-workspace)). A key they add is another way in, below.
- Grant the operator role to another account, or take it from another operator, alone: in the app that needs a second operator's passkey too, and a new operator's own passkey to accept ([Operators and the two-person rule](#operators-and-the-two-person-rule)). Nor keep the role once two other operators revoke it, or once it is revoked from the operator's machine.
- Recover access to another person's account, or delete one, alone: both need a second operator's passkey ([Operators and the two-person rule](#operators-and-the-two-person-rule)).
- Act unrecorded: every write is a platform event with the account's id and gives that account a notice. A key added also gives every other operator account and every live admin of the platform a notice, and removing a platform gives one to each admin it ends.

**What a key added here can do:** a key added in the console, by the operator or an admin, is the platform: until it is revoked, whoever holds its private half can provision devices, use every credential by relay, decide held requests, and read item lists and audits in every one of that platform's users' workspaces ([A platform](#a-platform)). That is the reach of a stolen session and passkey through a key, for the operator here and for an admin below.

**What contains it:** the passkey on every write, bound to the exact command and spent once; a slug typed back for anything destructive and for every key added; writes refused while the account is cooling off after a recovery; the notice on the account for every write, and to the operator and the platform's admins for every key added; the platform events, which the operator reads from the script as well as the console; and the operator's own machine as the break-glass: revoking the role there, or by two other operators in the app, ends the console at once, and the script does everything the console does without it. A platform that was removed cannot be put back: its users' credentials are gone, and that is the cost of a stolen passkey here.

### Operators and the two-person rule

Mehen may have several operators. A change to who is one needs two of them in the app.

**Can, one operator alone:** propose a change to the role (making an account an operator, or ending another operator's role), recovering access to an account or deleting one; decline another operator's proposal (never one that names them), cancel their own, and resign their own role with their passkey. The brakes are one operator's, each with a passkey: suspending an account that is not an operator's (every session ends, and it cannot sign in, recover or step up until lifted), lifting a suspension, and allowing or denying one account's workspace creation. Every operator and the account are told of a suspension and of its lifting. A suspended account's machines keep their scope in each workspace, which is its owners' call: each workspace's owners and admins are told so they can revoke them.

**Cannot, one operator alone:**

- Make an operator or end another operator's role: a different operator must approve the proposal with their own passkey within 24 hours, signed for the same digest of its kind, target and parameters, and a new operator must accept with their own passkey before the role is set.
- Recover access to an account (the operator break-glass): a different operator must approve it, and the proposer records how they verified the person out of band. Once every workspace has ended the account's old sessions and passkeys, the proposer alone takes its single-use link, once, with their passkey.
- Delete an account: a different operator must approve it, the name is typed back (the proposal keeps only its hash), and only an account in no workspace, no platform's admin and not an operator's is deleted. Its row and its events stay; its name, passkeys, sessions, recovery codes, Google sign-ins and notices go.
- Approve their own proposal: refused by the vault and by the database's own `CHECK`.
- Propose or approve a change to their own account, or leave Mehen without an operator: the last one cannot resign or be revoked in the app.
- Act unrecorded or unseen: every proposal, approval, decline, cancellation, expiry and change is a `deployment_events` row naming the proposer and the approver, and a notice to every operator account.

**Two operators together, with both passkeys, can** make any account that meets the requirements an operator (it must still accept with its own passkey), end any other operator's role, take over any account that is not an operator's by recovering its access, or delete any account in no workspace that is no platform's admin. The two-person rule holds against one stolen operator session and passkey, not against two. One stolen operator session and passkey can still suspend any account that is not an operator's, which is denial of service until another operator lifts it.

**Limit:** the rule lives in the app. The operator's scripts, run from the operator's own machine, are the break-glass for when the app is down or every operator is locked out, and need one person. Whoever can write the account directory or deploy the vault's code bypasses the rule, as they bypass everything else ([Whoever can deploy the vault](#whoever-can-deploy-the-vault)).

### Freezing and restoring a workspace

The console's Workspaces view lets operators pull a workspace's brake and roll it back, and nothing else inside it.

**Can, one operator alone, with their passkey:** freeze any active workspace. It is the workspace's own freeze, the one its members pull: every credential use and everything that widens is refused, while reads and narrowing carry on. The workspace's own audit chain records it with the operator's account id, and its owners and admins and every operator are told.

**Can, two operators together, each with their passkey:** restore a workspace to any moment in the last 30 days, or from a day's dump into an empty workspace object. One proposes, a different one approves within 24 hours, both signed for the same digest of the workspace and the point; approval records the same one-hour restore intent the operator's script records, the cron carries it out, and every operator and the workspace's owners are told. A restore undoes everything after its point, revocations, removals and rotations among them, so it is destruction within that window: a revoked machine works again and a rotated credential holds its older value until the owners re-apply what it undid.

**Cannot:**

- Unfreeze a workspace: only its owners do, from its home page with a passkey.
- Restore alone, restore a workspace while another restore of it is in progress, restore one that is not active (being created, being deleted or deleted), or restore from a day with no recorded dump.
- Read a credential, a project, a member other than the owners, a machine or the audit chain's contents: the view counts people and names only the owners.
- Act unrecorded: every proposal, approval and freeze is a `deployment_events` row naming the operators, as well as the notices above. A freeze the workspace has made is recorded even when the operator lost the role meanwhile, marked unguarded.

**Limit:** a freeze is a brake anyone stopping it would want; one stolen operator session and passkey can freeze every workspace, a denial of service that each workspace's owners undo. The two-person rule on restoring holds against one stolen operator, not two, and the operator's script still restores with one person, as break-glass ([Operators and the two-person rule](#operators-and-the-two-person-rule)).

### A platform admin

A Mehen account the operator added to one platform, or whoever holds its session and passkey.

**Can:** for that platform only, read its status, limits, keys, defaults, subject counts, usage and events; and, with a fresh passkey for each change, change its defaults (only stricter than the catalogue, as the platform's own can be), add a key and end the others after an overlap, revoke a key, and delete one of its users by the name the platform knows. A key the admin adds lets them act as the platform ([A platform](#a-platform)).

**Cannot:** reach another platform (its routes answer `not_found`), revoke the platform's last live key, register, suspend, resume, retire or remove a platform, change its limits, add or remove admins, or read anything inside a managed workspace through the console. A key they add is the platform, though, with the reach set out under [An operator's session in the web app](#an-operators-session-in-the-web-app): until it is revoked it can provision devices, use every credential by relay, decide held requests, and read item lists and audits in every one of the platform's users' workspaces. Every change is recorded with the admin's account, and a key added also notifies Mehen's operator and the platform's other admins.

### Whoever can deploy the vault

Anyone who can deploy the vault's code, or change its keys. On a vault on your own machine, that is whoever can replace the `mehen` binary or the vault's files: you, and anything running as you.

**Can:** change the code, and so read every secret as it is used or as it sits encrypted, because the running vault holds the root key. Whoever can deploy the vault's code can read every secret while it is used. The same goes for whoever can write the account directory, run the account recovery procedure or issue app sessions: those are the operator's powers, guarded as one.

**Cannot:** without writing trusted identity state, use members' passkeys to forge step-ups on their behalf against an honest deployment. Anyone who can write the account directory can substitute a passkey for an account and sign with the matching key, no code change needed, so deploy rights are not the only takeover path. Against a modified deployment, the checks are whatever the attacker's code says.

**Limit:** Whoever can deploy vault code, write trusted account identity state or operate account recovery can take over the vault's trust boundary. The operator must restrict those powers independently of agent access. These pages do not establish current operator-machine isolation. Beyond Cloudflare's own durability, every workspace's stored data has Cloudflare's 30-day point-in-time recovery, and each workspace not managed by a platform also has a daily dump of the whole workspace, sealed under a key derived from the root key and kept in a separate bucket. Setting that bucket to refuse deletion for 30 days is a step in the operator's setup, and whether an account administrator can lift that lock is not established. A dump opens only with that root key and only as its own workspace, so it lets no one read what the root key does not already open. Where copies of the root key and of the dumps are kept off the host is not established here.

### The host

**Can:** in principle read everything: on Mehen Cloud, Cloudflare runs the code, holds the vault's keys and stores the data. A legal demand, an insider or a platform compromise falls here.

**Cannot:** decrypt a sealed tier at rest. A sealed tier, not built, would additionally wrap chosen items under a key from the owner's passkey; even then, a relayed credential must be plaintext in the vault while it is used. An external key management option is not built either.

**Limit:** for now the vault trusts its host completely: Cloudflare for Mehen Cloud, and for a vault you run, the machine and everything running as the vault's user.

### A phishing page

A page that imitates the vault or a provider, linked from an email, a chat or a hostile agent.

**Cannot:**

- Use a passkey: passkeys are bound to the relying party `app.mehen.dev`, so a look-alike domain gets nothing it can replay.
- Finish an OAuth connection with the attacker's account against your vault: connect links need the requester's signed-in vault session and a passkey confirmation of the connection's terms, are single use and last 15 minutes, `state` is bound to the member, and the verified account is compared with the expected one.
- Pass a Google sign-in off as yours: the identity check is a purpose-bound flow with state, nonce and PKCE, verified against Google's keys and the vault's own client, and it only ever identifies; a passkey still has to answer.
- Turn an approval meant for one request into another: the passkey signs the digest the vault computed.
- Drive a state-changing browser route from another origin: every non-GET `/api` request passes one same-origin check.
- Get its link printed by `mehen`, drawn as a QR code, put in `--json`, returned as an MCP `resource_link` or stored in the ledger: every link `mehen` hands over has passed `askUrl` against the vault it is enrolled with, and the rest get a warning instead.
- Get the vault's card or button in an app that enforces the card boundary: a consuming app should draw a trusted vault card only for an ask from its own authenticated call, after checking exact origin, workspace and device context. Each app must enforce this boundary; in such an app a lookalike is plain text.

**Can:** ask the human to type a key into a form it controls. The vault cannot stop a human pasting a secret into a page that is not the vault. The rule for humans: paste secrets only into `https://app.mehen.dev/w/<slug>/i/...` intake pages, and only after checking who asked, where the secret will go, who it will belong to and which tags it will carry.

A platform's users never see a Mehen page: they type keys into the platform's own pages, which seal them in the browser ([A platform](#a-platform)). For them the rule is the platform's to state, and a page imitating the platform is the platform's phishing problem, exactly as for any site a person types a password into.

### Hostile text on the way to a human

An agent, an upstream or a planted ledger file can put hidden characters, text-direction overrides, terminal escapes or marker-shaped text into a subject line, a device name, a session label, a policy note, a slug or an error message.

**Cannot:**

- Reorder or hide text on an approval card: every string is spelled, markers name each hidden character where it sits, and a warning leads the page. A marker typed as text is not styled, because styling comes from the segments the vault emitted, never from a regex over rendered text.
- Move the cursor, recolour a line or hide part of one at the terminal: every human line crosses `terminalText`, which spells out controls, format characters and noncharacters, and only the styler's named styles become escapes. The same spelling is applied to MCP text content and `resource_link` names; `structuredContent` and `--json` stay raw JSON with controls escaped.
- Make a policy summary say what a note claims: an item's notes are never read; the three lines come from the matchers.
- Make a page say an agent the owner trusts asked: the asker line is the device name its owner accepted.
- Pick a workspace with a name: a workspace's display name is never a selector, in the CLI or in a copied prompt; only the id and the canonical slug select, and the Connect an agent page puts the canonical slug and origin, plus an optional connect code, into copied setup text, never the display name as a selector.

### A co-owner, an admin or a colleague

Someone inside the workspace with real rights, hostile or careless.

**Can:**

- As a co-owner, remove or demote the other owners and take the workspace: co-ownership is a trust relationship, and the vault does not arbitrate it. Owners are told of every change to an owner.
- As an owner or admin, see the workspace's credentials' metadata, every project, every machine, the whole audit chain, and narrow, revoke, suspend and remove at will.
- As a project manager, share the project further (not with a guest unless an owner or admin) and change its environments, within the fence and loosening rules.

**Cannot:**

- Read a stored value, except as an owner through a backup key they registered, which every other owner and admin is told about a day before it works and can remove. Whoever holds that key's identity reads every value in an export made to it, offline and for good: rotating or deleting a credential in Mehen does not recall an export; only rotating it at the provider does.
- Reach a colleague's private credential, or see where it was sent: it is `not_found` to everyone else, an owner or admin may only purge it, and its audit events carry no hosts or paths even for its owner.
- Accept a machine in a colleague's name, or widen one: acceptance and widening are the owner's own passkey over the exact key and scope.
- Turn a standing rule on for a colleague's machine: only the machine's owner approves one; an owner, admin or manager may co-sign it or stop it.
- Approve beyond their own rights, approve their own machine's protected run where four-eyes applies, or approve anyone else's ask as a guest.
- Reset a colleague's passkeys, end their cooling-off or take their account: recovery is the account's own, and the operator's break-glass is not a workspace power.
- Reach another workspace: nothing crosses that wall, not a credential, a share, a machine's key or a step-up.

**Honest limits:** a workspace is a shared trust domain. Metadata (which credentials exist, their hosts, who used them and when) is visible to owners and admins by design. A guest or a colleague who holds a machine can still use it for what their rights cover. A sole owner's backup key and exports are checked only by their own notices; the 24-hour wait and the notices contain a hostile registration, not a stolen backup identity.

**Honest limit:** what is spelled is still shown. A human reading `Pay [RLO U+202E]fdp.exe[PDF U+202C]` has to understand the warning; the page says to deny unless they know why the characters are there.

## Out of scope today

- Hostile code in a dependency the vault itself uses (supply chain). The vault has few dependencies, and all cryptography is WebCrypto; that is a mitigation, not a guarantee.
- Denial of service against the vault beyond the rate limits.
- Open sign-up on Mehen Cloud. Accounts there are created by invitation and workspaces by allow-listed accounts; hardening for strangers comes before either opens. A vault you run has one first account, made with its one-time code.
- Keeping the vault apart from other programs running as the same user on one machine: the separate-user mode is planned ([A vault on your own machine](#a-vault-on-your-own-machine)).
- Side channels in the host's runtime.
- Timing differences between absent and out-of-reach answers: the bytes are identical, the time is not promised to be.

## Open

- Which tripwires (a placeholder out of place, a fenced host, an echo) should freeze the workspace or suspend the device automatically. Today they are recorded and refused, nothing more.
- Anchoring the audit head outside the vault automatically (for example daily to object storage); today a head saved by hand is the check.
- Telling one process from another on the local relay and in `mehen mcp`: not built.

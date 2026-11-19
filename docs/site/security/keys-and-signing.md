---
title: Keys, proofs and signing
question: How do device keys, proofs, sealing, encryption, the audit hash, step-up and release signing work?
section: security
covers: both
order: 20
---

# Keys, proofs and signing

The exact formulas behind the other pages. All cryptography is WebCrypto. Canonical JSON, wherever it appears below, means keys sorted, no whitespace, arrays in order.

## Fingerprints

A machine key's fingerprint is what a human compares between the terminal and the enrol page. The CLI, the server and the page derive it the same way:

- **Glyphs.** The first 80 bits (10 bytes) of the key's RFC 7638 thumbprint in Crockford base32 (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`: no I, L, O or U), as four groups of four, upper case: `5NZV DP67 PXT0 DB6E`. When a human types a group, `I` and `L` read as `1` and `O` as `0`; a `U` is refused.
- **Words.** Bytes 10 to 13 pick four words from a fixed list of 256 common nouns, and bytes 14 and 15 pick a colour name for each from 16.
- **The hidden group.** Which group the enrol page hides is the first byte of a SHA-256 over the enrolment code, modulo 4, so it moves when the link is re-issued. The page's data holds only the hidden index and a hash the browser compares with what is typed, to enable Approve. The server does its own comparison when the owner accepts or an insider admits: every attempt is counted in one conditional write before anything is compared, a wrong group is refused, and the fifth wrong group rejects the enrolment. Without a valid passkey, a right and a wrong group get the same answer. The page's hash is a 20-bit preimage, so whoever holds the page can recover the group offline; it is a forcing function for the honest owner to look at the terminal, and the server's five-attempt cap is what stops guessing through the page.

A secret field's fingerprint (shown by `mehen show`) is different: the first 12 characters of the base64url HMAC-SHA256 of the item id and the value, under a per-workspace key derived from the root key (`mehen/fingerprint/v1/<workspace id>`). Someone holding only the stored data cannot test guesses against it.

## Device proofs

Every `/v1` request from a machine carries a `Mehen-Proof` header: a compact JWS, ES256, `typ: mehen-proof+jwt`, `kid` the device id (a workload's id when a workload signs), over:

| Claim | Meaning |
| --- | --- |
| `ten` | Workspace id (`tn_...`) |
| `dev` | Device id; for a workload, its machine's |
| `wkl` | Workload id (`wl_...`), only when a workload signed |
| `sid` | Session label (optional, audit only) |
| `gnt` | Grant the request acts under (optional, unused) |
| `htm` | HTTP method |
| `htu` | Full request URL without fragment |
| `bh` | base64url SHA-256 of the exact body bytes |
| `iat` | Issued at, seconds |
| `jti` | Unique per request |

The workspace verifies the signature, rebuilds the method, URL and body hash from the request it received, allows 60 seconds of clock skew and refuses a `jti` it has already seen. A captured proof cannot be replayed or reused for another request. While a key is enrolling it signs with `ten` set to `enrol`, and the account directory keeps its own nonce table for those proofs.

### Workload proofs

A [workload](../concepts/machines.md#workloads) has its own P-256 key, made by the harness that creates it; only the public half reaches the vault, registered by the machine's own key with `POST /v1/workloads`. The workload signs its requests itself, with the same proof and two differences: `kid` and `wkl` are the workload id, and `dev` is its machine. A `kid` must equal `wkl` when `wkl` is present and `dev` otherwise.

The vault finds the machine (enrolled) and the workload under it (an unknown one is `unauthenticated`), verifies the signature with the workload's key, and only then checks that the workload is live: not expired, not revoked, its machine not revoked. A workload that fails that check is refused with `workload_ended`; a proof that does not verify is `proof_invalid` whether or not the workload has ended, so it learns nothing about that. The owner's standing is checked on every request after that, as for the machine itself. Nonces are kept per signing key, so a `jti` one key spent never blocks another. A vault that does not know workloads refuses such a proof, since its `kid` is not `dev`, so a workload never acts with its machine's wider reach.

`@mehen/client` makes a workload key extractable, so a host can wrap and store it; like a software device key, it is a signing credential that can be copied. What bounds a copied workload key is its scope, its short life and revocation.

## Platform proofs

A [platform](../concepts/platforms.md) signs every call to `/v1/platform` with its own P-256 key, in a `Mehen-Platform-Proof` header: a compact JWS, ES256, `typ: mehen-platform+jwt`, `kid` the platform key's id (`pky_...`), over:

| Claim | Meaning |
| --- | --- |
| `plt` | Platform id (`plt_...`) |
| `sub` | The subject the path names, on every route under `/v1/platform/subjects/:subject`; absent on every other route |
| `htm` | HTTP method |
| `htu` | Full request URL without fragment |
| `bh` | base64url SHA-256 of the exact body bytes |
| `iat` | Issued at, seconds |
| `jti` | Unique per request |

The vault looks the key up by `kid` with no cache, and refuses it when it is unknown, revoked, past the end of its rotation overlap or another platform's. It then checks the signature, the method, URL and body hash it received, 60 seconds of skew, and that `sub` equals the subject in the path (both absent, or equal). Only after the signature verifies does it look at the platform's status, so nobody without the key learns it: every call is refused while the platform is suspended or retired. Last, the platform's own counter, one per platform, refuses a `jti` it has already seen for that key, before anything else runs. There is no workspace claim: the vault finds the workspace from the verified platform and the subject, never from the caller.

A platform proof and a device proof cannot stand in for each other. Each parser refuses the other's `typ`, a platform proof's header and claims may hold nothing but the members above (so a device proof's `ten` and `dev` never parse as one), a platform `kid` must start `pky_`, and a platform call that also carries a `Mehen-Proof` is refused.

In a managed workspace the platform's proof over the exact request stands where a person's passkey step-up would, for these actions only: `intake.submit`, `connect.start`, `approval.decide`, `item.delete`, `project.create`, `project.delete`, `device.revoke`, `workload.revoke`, `workspace.unfreeze`, and `item.update` only for a project's variables, never for a credential's binding, policy or ceiling. Where an action binds state, the body names it (an approval's `digest`, a variable's `before`) and the vault compares it in the same transaction, as it does for a passkey.

A platform key is rotated with an overlap: the operator adds the new key and sets an end on the old one, 24 hours by default, so the platform deploys the new key inside it. A leaked key is revoked at once.

## Sealing

The browser encrypts secret fields to the vault's P-256 seal key before sending: ephemeral ECDH, HKDF-SHA256, AES-256-GCM, with a context string (`intake/<intake>/<field>`) bound into both the key derivation and the additional data, so a box sealed for one intake field cannot be replayed into another. TLS already protects the hop; sealing keeps plaintext out of request logs, tail sessions and error reports between the edge and the vault call that opens it. The public key is served unauthenticated at `GET /v1/seal-key`. The CLI never sends a secret, so it seals nothing.

**From a platform's page.** A platform's intake answers the seal key and the intake id; the user's browser seals each value with the same context, `intake/<intake>/<field>`, and the platform's server passes on boxes it cannot open. The vault opens a box only with the context it derives from the intake it holds, so a box fills only that field of that intake, in that user's workspace, and only once: the submit closes the intake in the transaction that stores the credential. An OAuth app's client secret is sealed the same way, as a field of its intake, so the code a platform's callback receives is useless without Mehen, the only holder of that secret. What sealing cannot stop is the page itself: a hostile page reads a value as it is typed, and a hostile server can hand the page another key to seal to ([Threat model: a platform](threat-model.md#a-platform)).

## Encryption at rest

Each secret field is encrypted under its own data key, wrapped by a per-workspace key derived from the versioned root key with the workspace id in the derivation, with additional data naming the workspace, record type and id. A ciphertext swapped between rows or copied into another workspace fails to decrypt. The root key is held by the operator; possession of a root key and the stored ciphertext permits decryption. A new version can be added and every version still decrypts. This is not end-to-end encryption against the operator or the host: the running vault decrypts a secret to use it.

## The approval digest

An approval is bound to one exact request:

```
digest = base64url(SHA-256(canonicalJson({ item, method, url, contentType, contentEncoding, headersSha256, bodySha256, constraints })))
```

`contentType` and `contentEncoding` are the request's headers as sent (null when absent), because they change how the same body bytes are read. `headersSha256` is `base64url(SHA-256(canonicalJson([[name, value], ...])))` over every header the relay forwards from the agent, as sent: after the relay strips hop-by-hop, `cookie`, `mehen-*` and `cf-*` headers, names in lower case, sorted by name then value, leaving out the header the item's own injection overwrites. A protected run binds the empty list. `constraints` are what the request asked for: `{ uses: 1, ttlSeconds: 600 }` for a relayed request, `{ uses: 1, ttlSeconds: 3600 }` for a protected run. The human may choose fewer uses or a shorter window on the page; that choice travels in the signed decision, so changing it never changes the digest. For a protected run, `item` is the project slug, `method` is `RUN`, and `bodySha256` is a digest of the project, environment, remote, worktree, HEAD, variable names and which get a real value; the run's approval also binds the SHA-256 of the whole command line.

## Step-up

A step-up is a passkey assertion over one exact action, or, inside the 15-minute window below, a proof that rides an earlier one:

```
challenge = base64url(SHA-256("mehen-stepup/v2\n" + nonce + "\n" + scope + "\n" + canonicalJson(action)))
scope     = the workspace id for a workspace action, "-" for an account action
```

The server rebuilds the action and the scope from what it is about to do, never from the action the page claims, so a step-up begun on one workspace's page can never be spent on another's. The nonce is single use and bound to the account and the scope. While an account is cooling off after recovery, or has a security change pending, only tightening actions (narrow, deny, revoke, freeze, cancel the recovery) are allowed.

**The 15-minute window.** A passkey assertion in a browser session, a step-up's or the sign-in that created the session, opens a window for that session, 15 minutes from the assertion; it does not slide, and only another assertion renews it. While it lasts, starting a step-up for a graced action answers `{ nonce, grace: { until } }` with no WebAuthn options, and the proof is `{ nonce, grace: true }` in place of `{ nonce, assertion }`; no proof carries both. The nonce is still single use and bound to the exact action and scope, and every check of the passkey path runs except the WebAuthn verification, with one more: a live window for the same session, account and security epoch, whose passkey is still on the account and not waiting to be removed. A grace proof for a challenge started without the window is refused, and so is the reverse. No window opens or applies while the account is cooling off or has a security change pending, and starting either deletes the account's windows. The app's own step-up never answers with grace. An audit entry made inside a window records `confirmation: { kind: "grace", provenAt }`, with `provenAt` the time of the assertion it rode on. An action is graced only when the action the server rebuilds shows it cannot widen who can act, how someone proves who they are or what a credential is exposed to, nor relax a protection; an action signed as an opaque digest is fresh. [The 15-minute window](../concepts/approvals.md#the-15-minute-window) lists both.

The actions:

| Action | Signs | Used for |
| --- | --- | --- |
| `intake.submit` | intake id, digest of slug, binding, public fields, sealed boxes, tags and home | Storing a new credential or rotating one |
| `connect.start` | connect id, provider, slug, home, tags, expected account, scopes, the client and reconnect subject | Starting an OAuth connection, before the provider is visited |
| `enrol.accept` | workspace, enrolment, the key's full RFC 7638 thumbprint, the accepting account and membership, the complete scope with `privateCredentials`, the start time, place and client | A member accepting their own machine |
| `enrol.approve` | enrolment, its digest, the owner, the admitting role | An owner or admin admitting a team's machine, or an insider admitting a guest's; never satisfies acceptance |
| `device.rescope` | device, thumbprint, the scope the page showed, the whole new scope | Narrowing a machine (its owner, an owner or an admin), or widening a team's (owner or admin) |
| `device.rescope_accept` | device, thumbprint, the owning account, before and after, whether admission is also needed | A member accepting a proposed widening of their own machine |
| `device.revoke` | device | Revoking a machine |
| `workload.revoke` | device, workload | Revoking one of a machine's workloads from the machine's page |
| `approval.decide` | approval id, the stored digest, approve or deny, the chosen uses and duration, and for **Approve and allow this from now on** the rule's path, duration and terms digest | Deciding an approval |
| `policy.decide` | proposal or rule id, digest, approve or deny, the effect digest (the rule's terms with the chosen path and duration, or the extension's duration) | Approving, co-signing or denying a standing rule proposal; extending a rule |
| `item.update` | item, digest of the update body (`binding`, `policy`, `ceiling`, `tags`, `description`), or a project id and digest of `{ change: "var.set" \| "environment.update" \| "remote.bind" \| "remote.unbind", ... }` (an environment change signs `protected`, `fences` and `fourEyes` together) | Changing where or how a credential may be used; setting a variable, protection, four-eyes, fences or a bound repository from the browser |
| `item.rehome` | item, the home before and after, the dependency revision | Moving a credential between homes |
| `item.delete` | item | Deleting a credential |
| `mandate.sign` | the machine and the digest of the terms, the workspace and the signer | Signing a [mandate](../concepts/mandates.md) for your own machine; always fresh |
| `mandate.resume` | the mandate, its digest, the revision resumed and what it resumes from: `paused`, `tripped` or `lapsed` | Resuming a mandate; graced only from `paused`, and none at all when its signer or the machine paused it and the signer still stands behind it |
| `override.set` | project, environment, variable, the source by stable id or null | Choosing or clearing a personal override |
| `project.create`, `project.share`, `project.configure`, `project.delete` | slug, remote and environments; project, subject, the share terms before and after; project and configuration digest; project | Projects and their shares |
| `member.invite`, `member.confirm`, `member.role`, `member.suspend`, `member.reinstate`, `member.remove`, `member.leave` | the complete invite terms; member, terms digest and identity-rule revision; member, role before and after; member | People |
| `team.update`, `team.members` | team and the change (create, rename, delete; add, remove) | Teams |
| `workspace.create` (account scope), `workspace.update`, `workspace.identity_rule`, `workspace.delete`, `workspace.delete_cancel`, `workspace.unfreeze` | slug and name; the whole rule or null; the name; nothing else | The workspace itself (owner only; creation needs the account's `canCreateWorkspaces`) |
| `passkey.add`, `passkey.remove`, `recovery.generate`, `recovery.resolve`, `identity.link`, `identity.unlink`, `account.delete` (account scope) | the passkey; the notice and outcome; the provider and identity | The account |

`item.reveal` is reserved and uncalled: there is no page that shows a stored value. Rule R10 depends on this table: agents may propose new items, but changing an existing item's binding, ceiling, policy or home needs a step-up that shows the change.

## The audit hash

```
hash = base64url(SHA-256(prev + "\n" + canonicalJson({ seq, at, actor, action, target, detail })))
```

`prev` is the previous event's hash (`mehen/audit/v1` for the first), and `detail` is the canonical JSON string as stored. In a [managed workspace](../concepts/platforms.md) the first `prev` is `mehen/audit/v1/platform/<platform id>/<workspace id>` instead, and every event's `detail` names the platform before it is hashed, so the chain is bound to its platform and workspace and one copied from elsewhere never verifies. To verify a chain, walk forward from sequence 1 checking each `prev` equals the hash before it and each `hash` recomputes. [Audit, review and freeze](../concepts/audit.md#reading-it) says what a reader sees, and why a head saved outside the vault matters.

## Releases

`mehen` updates itself from the release channel at `https://mehen.dev/dl/` ([HTTP surfaces](../reference/http.md#the-release-channel)).

- **Signed manifests.** Every release manifest is signed with an ES256 release key, and the public half of each trusted release key is compiled into the `mehen` binary. An installed `mehen` installs only a manifest signed by a compiled key, and only bytes whose SHA-256, compressed and uncompressed, that manifest names. A release it cannot verify is refused, never installed; a build with no compiled release key updates nothing.
- **Anti-rollback.** An automatic update must be newer than the version running, at least the highest version this installation has seen, and above any hold a rollback set. `mehen update --force` and `--rollback` are explicit, local, and still signature-checked.
- **One rename.** The updater runs as the user, never with sudo, reads no workspace slot and no key, and replaces the binary with one journalled rename next to it, under a lock, so a kill at any step leaves the old or the new binary and a state file beside it that says which.
- **In the background.** After a command, `mehen` checks for a release about every hour, and 15 minutes after a check that failed. When the vault recommends a newer version than the one running, it checks at the end of that command instead. `MEHEN_NO_AUTO_UPDATE=1`, or `autoUpdate: false` in `settings.json` under `MEHEN_HOME`, turns it off; CI and source runs never update themselves. A running `mehen mcp` that does not switch in place (below) keeps the version it started with and asks for a restart in a tool result once a newer signed binary is in place. Switching automatic updates off stops automatic installation, not this notice: a human may still run `mehen update`, and the agent is told.
- **Switching in place.** With automatic updates on, a running `mehen mcp` instead switches to the newer signed binary itself, at a moment when no call is running, keeping its process, its connection to the agent and every workspace it had checked; the agent sees no restart notice. It switches only to a binary the updater verified and recorded, never to a hand copy or a lower version. If the switch is refused or fails, it keeps serving and asks for a restart as above. This is on by default; `"mcpHandover": false` in the same `settings.json`, or automatic updates off, switches it off. Each server decides when it starts whether it will switch, so removing that setting applies to servers started after it. Turning it off also reaches servers already running: each looks at the setting again before it switches, so the next switch does not happen and the server asks for a restart as above. `mehen doctor --json`, `mehen status --json` and `vault_status` report `cli.mcpHandover`, `on` or `off` with the reason; inside a server, `cli.mcp.action` is `switch` while it will switch and `restart`, with the reason, when the agent must restart.
- **The release key.** The release mechanism keeps the signing key in a hardware-backed key store on the release machine, and each compiled entry says whether every signature needs the operator's presence. That describes the mechanism, not proof that a production key is provisioned today: a build with no compiled release key updates nothing. A stolen key is retired by shipping a release without it and raising the vault's minimum version.
- **The vault recommends the published release.** The vault reads the release channel's `latest.json` itself, at most every five minutes, and recommends its version only when the manifest is signed by one of the same release keys `mehen` compiles in. A machine usually sees a new release recommended within five minutes, on its next calls to the vault. The vault runs on many servers and each reads for itself: one that has just started recommends the version its operator set until its first good read, one that has been idle answers its first call with what it read up to an hour before, and one that has gone an hour without a good read recommends the version its operator set again, which is also the lowest it ever recommends. Pausing a release, by pointing `latest.json` back at the previous signed manifest, lowers the recommendation the same way, usually within five minutes.

**What the release channel can and cannot do.** Whoever controls the channel (its storage, the site that serves it, DNS, or a TLS interception) can serve any `latest.json`, binary or install script, and can withhold updates. It cannot make an installed `mehen` run its binary without a compiled key's signature. Withheld updates become visible when the vault's minimum version rises above the frozen version.

**What the installer checks, and what it trusts.** `curl -fsSL https://mehen.dev/install | sh` checks the release manifest's ES256 signature before it reads anything else in it. The keys it accepts are the ones compiled into `mehen`, written into the script. It rebuilds the bytes that were signed (the canonical JSON of the manifest without `signatures`) and checks them with `openssl dgst -sha256 -verify`, which OpenSSL and the LibreSSL a Mac ships both do. A manifest it cannot rebuild exactly is refused (an escape, a duplicate key, a number that is not a plain integer), and so is an unsigned one or one whose signature does not verify, before any binary is downloaded. Then it checks the size and SHA-256 of the compressed and the uncompressed binary against that verified manifest. What it still trusts is the script itself: it comes over TLS from the site that serves it, so whoever can change the script can change the keys in it. It also keeps no record of earlier versions, so it has no anti-rollback. The one update from a 0.2.0 `mehen` to 0.3.0 is hash-checked over TLS only, since 0.2.0 cannot check a signature. That is why the installer is only for a machine with no `mehen`: it refuses to replace a verified install unless forced, and no page recommends it as a way round a refused update.

**The version gate.** Every `/v1` answer carries `Mehen-Cli: minimum=<v>; recommended=<v>`. The recommended version only hurries an update. The minimum is the lever that forces one: the operator sets it by hand, it never depends on a read of the release channel, and a `mehen/<v>` client below it is refused with `cli_outdated` (HTTP 426), except freeze and self-revoke. A `mehen` that updates itself and knows the vault's minimum is above it updates before its next vault command. It is a compatibility aid, not a boundary: a client that sends no `mehen/` user agent passes, and it protects nothing the proof and the access check do not already protect.

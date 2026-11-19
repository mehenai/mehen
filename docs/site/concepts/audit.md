---
title: Audit, review and freeze
question: What is recorded, and how do I stop things?
section: concepts
covers: both
order: 90
---

# Audit, review and freeze

## The audit chain

Every action that reaches the vault is an audit event in the workspace's own store: a sequence number, time, actor (`device:<id>`, `enrolment:<id>`, `member:<id>`, `system`, `public`), action (`item.create`, `relay.allow`, `relay.refuse`, `relay.tripwire`, `relay.echo`, `approval.approve`, `run.lease`, `member.remove`, `override.set`, `workspace.freeze`), target and details. Events carry slugs, ids, hosts and field names only, never a secret, token, code or nonce.

An event a [workload](machines.md#workloads) caused also names the workload, by id and label, so the audit says which task of a machine acted; the label is the machine's words. Creating a workload is itself an event, `workload.created`, with its label, scope and expiry.

The workspace audit records authorised uses, decisions and refusals that reach the vault. An event about a **private credential** is minimised before it is hashed (action, time, actor, owner, session, item id and slug, outcome, run id; never hosts, paths or fields), so even its owner will not see where their private credential was sent: investigate misuse with the provider's own logs. Refusals by the local relay of `mehen run` happen on the machine, and traffic it tunnels is never inspected, so neither is in the vault's audit chain.

The chain is hash-linked: each event stores the hash of the previous one, and its own hash covers that previous hash and the event. The application only appends, and verification detects an inconsistent edit or a deletion. A storage or deployment authority could recompute or truncate the chain, though, so comparing against a head you saved outside the vault is what detects that kind of rewrite; automatic anchoring outside the vault is not built.

In a [managed workspace](platforms.md), every event names the platform, whoever caused it. An event the platform caused has the actor `platform:<id>` and names the platform's key; a decision also names the approval's digest and the platform's own reference. The chain starts from a value naming the platform and the workspace ([The audit hash](../security/keys-and-signing.md#the-audit-hash)). Only the platform reads it, and it keeps a deleted user's chain, which holds no secrets, until the workspace is erased.

## Reading it

The Audit page (`/w/<slug>/audit`) shows a workspace's events newest first, 50 a page by default and up to 200. **Owners and admins** read the whole chain, with its head (the newest event's sequence number and hash) and whether the vault's own walk of the chain verified. **Everyone else** gets only the events their rights cover (a member: their own actions and their machines', the projects they edit or manage, their teams, the credentials they may see and their own private events; a guest: their own actions and machines, and their own private events), no head, and a mark when some stored event was left out. Not every reader can verify an unfiltered chain.

To check the chain by hand: page back to sequence 1, walk forward checking that each event's previous hash equals the hash before it and that each hash recomputes ([Keys, proofs and signing](../security/keys-and-signing.md#the-audit-hash) has the formula); the vault does the same walk on every read. Note the head from time to time somewhere outside the vault; if a later read does not extend from it, history was rewritten. There is no `mehen` command that does this check.

## Review flags

When an upstream sends a credential's value back in a response, the relay scrubs the echo and **flags the item for review** (a reason and since when). The vault scrubs credential echoes in raw, URL-encoded, JSON-escaped and supported base64 forms; it cannot catch arbitrary transformations, and values shorter than six characters are not redacted. A flagged item shows "Needs review" in the web app, `needs review: <reason>` in `mehen ls` and `mehen show`, and `review` in `--json`. The detected echo was scrubbed; review the service before using the credential again, because the upstream has seen the value and chose to send it back. The flag clears when the item's secret is replaced through an intake; there is no "mark reviewed" action yet.

## Freeze

Freezing a workspace refuses every machine use of it until an owner unfreezes it. Any enrolled machine whose owner is not a guest may pull the brake (`mehen freeze`, a team's machine too), and any member who is not a guest may, from the workspace's home page, with no passkey: pulling the brake is always allowed. Only an owner with a passkey may release it. A freeze is one workspace's; the account's other workspaces carry on. In a managed workspace the platform or any of its devices may freeze, and only the platform unfreezes.

A frozen workspace answers machines with `frozen` (HTTP 423) and a `next` asking the human to review the audit log. What stops is the use of credentials and everything that widens; reads (status, metadata, pending, audit) and narrowing (ending a run, denying, revoking, a machine revoking itself) carry on. Members, signed in with passkeys, can still read, deny and revoke machines; an owner unfreezes. Tripwires (a placeholder out of place, a fenced host) are recorded but do not freeze the workspace.

Smaller switches exist per machine (revoke it), per task on a machine (revoke its workload), per run (end it) and per credential (delete it, with a passkey). Revocation and freeze stop subsequent authorised uses through Mehen. They cannot recall an upstream request already sent, undo provider-side effects, erase a leased value or revoke a provider credential outside Mehen; rotate exposed credentials at the provider. [A machine or a key is compromised](../guides/incident.md) is the order to do it in.

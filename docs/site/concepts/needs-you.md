---
title: Needs you and asks
question: What is an ask, and where does it show up?
section: concepts
covers: both
order: 70
---

# Needs you and asks

## Asks

An **ask** is one link handed to a human: an enrolment, an intake, a connect, a reconnect, an approval, a [standing rule](../guides/standing-rules.md) or task grant proposal, an adoption batch, a bundle of requests to review together, a [mandate](mandates.md) proposal or the unfreeze page ([`kind`](../reference/ask.md#the-object) names which). `mehen` builds every ask as one object and renders it the same way everywhere: the terminal block, the `ask` field of `--json`, and the text and `resource_link` of an MCP result. [The ask object](../reference/ask.md) is the exact shape.

```
Human needed: approve a request
  open:    https://app.mehen.dev/w/acme/a/apr_7Hq2
  what:    Send an email to sam@example.com, from gmail-personal (you@example.com)
  check:   the page shows code K7Q2MX
  expires: in 58 min (17:12)
  then:    mehen wait apr_7Hq2
```

`open:` is always the second line. The `check:` sentence always starts "the page", so the human knows where to look: a fingerprint for an enrolment, a binding code for an approval, an account for a connection, and who asked for an intake. Every status and every error that carries a link carries `expiresAt`, so a card can count down.

**The link is only ever on the vault's origin, under the workspace's canonical slug.** `mehen` checks every link the vault returns against the enrolment it acts under (scheme, host and port; no username, query or fragment; the `/w/<slug>/` of that workspace; one of the vault's own ask routes) before printing it, putting it in `--json` or drawing a QR code. A link that fails is never shown: `mehen` warns instead, and where it knows the id it rebuilds the link under the canonical slug. On a terminal, the QR code encodes exactly the printed link.

A consuming app should draw a trusted vault card only for an ask produced by its own authenticated call, after checking the exact origin, workspace and device context. Mehen supplies that context on every ask; each app must enforce its own rendering boundary.

## The ledger and `mehen pending`

Every ask a machine makes is recorded in the workspace's ledger on that machine (a private file: links, ids, titles, codes and expiries, the command that made it, and for an enrolment the key's public half and the workspace asked for; never a secret). Links and codes are still workflow details worth keeping private. `mehen wait` drops an entry when the ask settles; expired entries are pruned.

`mehen pending` (and `vault_pending`) lists what is still open in every workspace this machine may use: the ledger merged with each vault's own list of this machine's open asks and each pending enrolment, plus the one notice a vault sends a machine, that it was added to the workspace. `mehen pending <id>` (or the slug an ask creates) prints the block again; use it when a conversation lost the link. Listing creates and extends nothing.

## Needs you

**Needs you** is the human's side, in the web app. It spans workspaces: for the signed-in account, it gathers every workspace's inbox at read time and opens the right workspace from each row. A workspace that cannot be read in time is marked, never shown as empty. It lists:

- the account's own asks, and the asks they may approve or deny (in the detail or stop view their rights allow);
- intakes and connects they may fill in, and credentials flagged for review that they manage;
- member confirmations and scope proposals to those who sign them;
- **pending enrolments**, only to the people who may act on them: owners and admins of the intended workspace, the account a connect code claimed it for, and whoever may admit it;
- notices: a machine added, a mandate signed, tripped, about to end or lapsed, credentials to rotate, a backup key added, able to receive exports or removed, a protection change, and account and membership changes such as a recovery, an owner added or removed, a member joining, a suspension or the workspace scheduled for deletion.

A mandate proposal is not listed here: it waits under **Waiting for you** on the workspace's mandates page, and on the machine's page.

With the connect code from the workspace's Connect an agent page, an enrolment is claimed for that account and appears in its Needs you, and only that account can accept it. Without a connect code, whether an enrolment is listed depends on role and eligibility: an unclaimed start from a member's own machine is listed to owners and admins, not to every member. The inbox opens an enrolment by its id, never by its code. Always give the human the exact returned link and the full fingerprint, whether or not it is listed for them.

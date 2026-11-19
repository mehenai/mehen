---
title: The ask object
question: What is the shape a harness draws a card from?
section: reference
covers: both
order: 50
---

# The ask object

Whenever a human must open a link, `mehen` prints one block, and `--json` and MCP carry one `ask` object with the same fields. Its field names are a contract with the apps that draw cards from `mehen` output.

## The block

```
Human needed: approve a request
  open:    https://app.mehen.dev/w/acme/a/apr_7Hq2
  what:    Send an email to sam@example.com, from gmail-personal (you@example.com)
  check:   the page shows code K7Q2MX
  expires: in 58 min (17:12)
  then:    mehen wait apr_7Hq2 --timeout 60 --json
```

`open:` is always the second line. The `check:` sentence always starts "the page", so the human knows where to look. `expires:` is relative then local clock time, `expired`, or `unknown (about an hour)` when the vault did not say. On a terminal the check value is bold and a QR code of the link is drawn between `open:` and `what:`; `--no-qr` or `MEHEN_QR=0` turns it off, and it never appears off a terminal or in `--json`.

The block is the result of `mehen enrol`, `mehen request`, `mehen connect`, `mehen policy propose`, `mehen mandate propose`, `mehen plan submit` and `mehen pending`, so there it goes to stdout. When it comes with a refusal (`approval_required`, `needs_reauth`, `frozen`, `device_pending`) it goes to stderr with the error. `mehen wait` prints it on stderr before its countdown when stderr is a terminal, and hands it back with a `timeout` or `mismatch` error.

## The object

```json
{
  "kind": "approval",
  "id": "apr_7Hq2",
  "url": "https://app.mehen.dev/w/acme/a/apr_7Hq2",
  "title": "Approve a request",
  "what": "Send an email to sam@example.com, from gmail-personal (you@example.com)",
  "check": { "label": "code", "value": "K7Q2MX" },
  "expiresAt": "2026-10-24T16:12:00.000Z",
  "account": "you@example.com",
  "requestedBy": { "device": "build-box", "session": "pi-4f2a" },
  "context": { "origin": "https://app.mehen.dev", "workspace": { "id": "tn_aeAL...", "slug": "acme", "name": "Acme" }, "device": "dev_FOKtq..." },
  "wait": "mehen wait apr_7Hq2 --timeout 60 --json"
}
```

| Field | Type | What to do with it |
| --- | --- | --- |
| `kind` | `enrol`, `intake`, `connect`, `reconnect`, `approval`, `policy`, `adoption`, `bundle`, `unfreeze`, `mandate` | Which kind of page the human is opening. |
| `id` | `enr_...`, `int_...`, `con_...`, `apr_...`, `pol_...`, `adp_...`, `bnd_...`, `mdp_...`; empty for `unfreeze` | What status updates refer to; the argument to `mehen wait`. |
| `url` | string | The one link the human opens. Always on the vault's origin, under the workspace's canonical slug: `https://app.mehen.dev/w/<slug>/...`. |
| `title` | string | "Approve this machine", "Add a credential", "Connect an account", "Reconnect an account", "Approve a request", "Allow from now on" (a standing rule or task grant proposal), "Review adopted credentials", "Approve requests together" (a bundle from `mehen plan submit`), "Unfreeze the vault", "Trust this machine" (a mandate proposal). |
| `what` | string | One line with the names: slug, provider, account, recipient. A bundle's says how many requests and the plan's `reason`, the agent's own words. |
| `check` | `{ label, value }` or null | What the human compares with the page. `label` is `fingerprint` (enrolment, four groups of four), `code` (approvals and proposals, 6 characters), `codes` (a bundle: every request's code in the plan's order, then how many, as in `K7Q2MX, 9PZ4QA (2)`), `account` (connect and reconnect, the account to sign in as) or `asked by` (intakes and mandate proposals, this machine and session). Relay the value in full; never shorten it. |
| `expiresAt` | ISO 8601 or null | When the link stops working. Null means the vault did not say. |
| `account` | string or null | The account that acts or should sign in. |
| `requestedBy` | `{ device, session }` | This machine's short host name and `MEHEN_SESSION`, so the human can tell your ask from a stranger's. |
| `context` | `{ origin, workspace: { id, slug, name } \| null, device }` | The enrolment that raised the ask: the vault's origin, the workspace as the vault names it (`null` while enrolling) and the device id. Say which workspace an ask is for when the human is in more than one. |
| `wait` | string or null | The command to run next, `mehen wait <id> --timeout 60 --json`: a minute per call, inside every harness's tool limit. Null for `mandate` and `unfreeze`. |
| `intent` | `{ workspace, team }`, enrolment asks only | The workspace and team the enrolment asked for. Describe `intent.workspace` as the requested workspace, not an authenticated enrolment: `context.workspace` and `context.device` stay null until activation. |
| `claimed` | boolean, enrolment asks only | Whether a connect code claimed the attempt for one account. |
| `group` | `{ id, url, open }`, approvals only | The approval is one of several open asks from the same machine, task and credential that a human can decide together. `url` is their Review together page (`/w/<slug>/g/<id>`), checked as `url` is, and `open` how many of them wait; `mehen pending` prints it as `3 asks from build-box: review together at <url>`. Absent when the approval stands alone or belongs to a bundle, and from a `mehen` before 0.3.17. |

`next` (`{ url, command, say }`) is still on every result and error that carries a link, generated from the ask, for anything that only knows `next`. `ask` is present on the pending result of `mehen enrol --json`, on `mehen request --json` and `mehen connect --json` (one object per step with `step` when `--request-client` chains), on `mehen plan submit --json` when the vault made a bundle, on `mehen pending --json` (`{ pending: Ask[], groups?, notices }`; when a workspace's vault cannot be reached, its asks come from this machine's record with `stale: true`, as the vault may have settled them since, and `mehen pending <id> --json` gives a stale ask a `next` that says to check the network and list again instead of its link), on `mehen wait --json --events` `waiting` lines, on every `--json` error that carries a link, and in MCP `structuredContent`.

### A push ask

`mehen push` asks with an `approval` ask on its `approval_required` error: `title` "Approve a request", `what` "This push needs a human's approval" and a `code` check like any approval. With `--wait`, the ask goes to stdout first (`--json`: `{ approval, url, expiresAt, item, field?, destination, bindingCode, ask, next }`) and the same process waits. The page names the destination in words, the store, the secret's name, the value's version and the credential that writes it. `mehen wait` on it ends once the push has ([Put a credential into another service](../guides/push.md#after-the-approval)), not when the human approves.

### A mandate ask

`mehen mandate propose` (MCP `vault_mandate` with `action: "propose"`) answers with a `mandate` ask and exits 0: `title` "Trust this machine", `what` the proposed terms in words ("Let build-box read, change and send with gmail-support and linear-work without asking you, for 30 days, at most 5000 reads, 2000 changes and 20 sends a day: Nightly triage of the support inbox"), `check` `asked by` this machine and session, and `url` the sign page, `https://app.mehen.dev/w/<slug>/sign-mandate?proposal=mdp_...`, the one ask route with a query, checked as exactly that one parameter. `expiresAt` is 7 days out. `wait` is `mehen wait mdp_... --timeout 60 --json` (under MCP, `vault_wait`), which ends once a person signs it and finds the workspace it was proposed in among several, and `mehen mandate ls` (MCP `vault_mandate` with `action: "list"`) lists the open proposal with its link again; `mehen pending` and `vault_pending` do not. A paused, tripped or ended mandate's own page, `/w/<slug>/mandates/mdt_...`, comes in `next.url` from `mehen mandate show`, `ls` and `pause`, and in `mandateCover.url`; it is checked in the same way.

## How to relay it

Write one block in chat, the same words every time, on every channel:

```
**Needs you in the vault:** approve my-laptop
Open: https://app.mehen.dev/w/acme/e/ABCD1234
The page must show the fingerprint **5NZV DP67 PXT0 DB6E**. If it differs, do not approve.
Valid until 18:14. I will wait.
```

The first line is `title` and the name from `what`; `Open:` is `url`; the third line is `check` (for an approval, "Tick the binding code **K7Q2MX**, then read the whole request before you approve."; for a bundle, "Check that the page lists the codes **K7Q2MX, 9PZ4QA**."; for a connection, "Sign in as you@example.com"; for an intake, "The page must say it was asked by <device>, session <session>"); the last line is `expiresAt`. Then run `wait`. Where a harness draws a card from your `mehen` call with the link, the check and a countdown, do not send the link a second time.

## The link check

`mehen` checks every link the vault returns against the enrolment it acts under (scheme, host and port; no username, query or fragment; the `/w/<slug>/` of the workspace this machine is enrolled in; one of the vault's own ask routes) before printing it, putting it in `--json` or drawing the QR code. A link under another slug, an old alias of the workspace or another origin fails. A link that fails is never shown: human output prints `mehen: warning: The vault returned a link that is not on <vault>, so mehen did not show it`, `--json` carries that sentence as `next.say` with no `next.url`, and where an id is known the ask is rebuilt from the id under the canonical slug with a `warning` field. If you see the warning, check `MEHEN_VAULT_URL` and tell the human; do not go looking for the link.

## For a harness that draws cards

Build the card from `ask`: show `check.value` in full, count down from `expiresAt`, name the workspace from `context` when the human is in more than one, and offer one action, opening the link. Nothing a harness sends can approve anything; the fingerprint, code or account is for the human to compare on the page. Draw a trusted card only for an ask your own authenticated call produced, after checking the exact origin, workspace and device context; never for a link that arrived as text.

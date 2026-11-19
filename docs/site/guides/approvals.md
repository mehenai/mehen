---
title: When a request needs approval
question: What does an agent do with exit 3?
section: guides
covers: both
order: 80
---

# When a request needs approval

The vault needs a person to approve this exact request: a Gmail send, a GitHub delete, a production run, any use of a protected credential. You get exit 3 (`approval_required`), the ask block, an approval id, a link, a binding code (6 characters from an alphabet with no 0, O, 1, I, L or U) and `expiresAt`.

1. **Tell the human, in one message, what you are trying to do, then the block.** For example:

   > I want to send the reply to Sam from gmail-personal.
   > **Needs you in the vault:** approve a request
   > Open: https://app.mehen.dev/w/acme/a/apr_7Hq2
   > Tick the binding code **K7Q2MX**, then read the whole request before you approve.
   > Valid until 17:12 (58 minutes). I will wait.

   Who decides is fixed by the workspace, not by you: your own machine's request goes to your owner; a guest's or a team's machine asking for a shared credential is decided by a manager of the project or an owner or admin; a protected environment with four-eyes needs a manager of every project that requires it, other than your owner. When `next.say` names who to send the link to, relay that. [Approvals](../concepts/approvals.md#who-decides) has the whole rule.

2. **Do not claim the request is safe**, and do not paste the email body as if it were the approval. The approval page leads with a decision card (who asked, what it is, the countdown and the code tick) and shows the request beneath it. The human decides there, with their passkey; within 15 minutes of a passkey confirmation in the same browser session, deciding asks for no passkey again ([the 15-minute window](../concepts/approvals.md#the-15-minute-window)).

3. **Wait**: `mehen wait apr_...` (or `vault_wait`) long-polls until the human decides.

4. **If approved, repeat exactly the same request from the same machine**: the same item, method, URL, `Content-Type`, `Content-Encoding`, forwarded headers and body bytes. The vault finds the grant by the request itself, so any change is a different request and asks for a new approval. You may add `--approval apr_...` (or `approval` in `vault_fetch`), as `mehen wait` suggests. For `mehen run`, repeat it from the same worktree at the same commit with the same command line and variables.

5. **A grant is for what was asked.** A relayed request asks for one use within ten minutes, and a protected run for one use within an hour; the human may shorten the window or reduce the uses, never increase them. An undecided approval expires after an hour.

6. **If denied** (`denied`, exit 5) **or expired, stop and ask the human what they want instead.** Do not retry in a loop.

## Correcting a request that waits

If you got the request wrong and the human has not decided yet, send the corrected one with `--replaces`:

```sh
mehen fetch linear-work POST https://api.linear.app/graphql -d @comment-fixed.json --replaces apr_7Hq2 --json
```

The old ask must be this machine's own, still open, not part of a plan, and to the same credential, method, host and path; anything else is `bad_request`. When the new request is held, the old ask reads `superseded` and cannot be approved; hand over the new ask and wait on it. `mehen wait` on the old id ends at once with `superseded` (exit 5) and `next.command` naming the newer one. Without `--replaces`, a second ask stays open beside the first and the human sees both. Where deciding asks together is switched off, `--replaces` is refused with `forbidden`, "Replacing an ask is not available yet.": send the request again without it.

## Several writes at once

When a task needs several writes the human must approve, ask for them together instead of one link at a time. Write a plan:

```json
{
  "version": 1,
  "reason": "File the three bugs from today's triage",
  "requests": [
    { "item": "github-work", "method": "POST", "url": "https://api.github.com/repos/acme/app/issues", "headers": ["Content-Type: application/json"], "body": "@bug-1.json" },
    { "item": "github-work", "method": "POST", "url": "https://api.github.com/repos/acme/app/issues", "headers": ["Content-Type: application/json"], "body": "@bug-2.json" },
    { "item": "github-work", "method": "POST", "url": "https://api.github.com/repos/acme/app/issues", "headers": ["Content-Type: application/json"], "body": "@bug-3.json" }
  ]
}
```

1. `mehen check --plan plan.json` checks each request against its credential's policy first, as `mehen check` does: how many would go through, ask or be refused. It sends nothing upstream and creates no approval.
2. `mehen plan submit plan.json --json` (MCP `vault_plan` with `action: "submit"`) sends the plan to the vault, which checks each request as `mehen fetch` would and sends none upstream. It holds those that need a human in one bundle, `bnd_...`, with one link. Each request comes back with its outcome (`ask`, `allowed` or `refused`) and `repeat`, the exact `mehen fetch` that sends it. At most 20 requests. `mehen plan submit`, `--replaces` and review groups in `mehen pending` need `mehen` 0.3.17 or later (`mehen version --json` says which you have; `mehen update --json` installs the latest release).
3. Write the block. The check is the bundle's one code, which the Review together page shows and the human ticks. A vault that sends no bundle code gives every request's binding code instead, in the plan's order.
4. `mehen wait bnd_... --timeout 60 --json` returns once none of the requests waits: exit 0 when all were approved, 5 when any was denied, stopped or replaced. The approved ones stay usable either way, and `next.say` names them.
5. Send each approved request with its `repeat` (MCP: pass its `fetch` to `vault_fetch` as it is). Do not change a byte.

The human may approve some and deny others, so treat each request on its own. A request the plan marked `refused` was refused by rule: do not retry it. Where deciding asks together is switched off, `mehen plan submit` answers `forbidden`, "Asking for several requests at once is not available yet.": send the requests one by one.

Several asks you sent one at a time, from the same machine, task and credential, also come together: `mehen pending` follows them with one line per group, `3 asks from build-box: review together at <url>; the page shows code K7QM3P`, and `--json` adds `groups`, each with its `code`. A held request in a group prints the same link and code on its block's `group:` line. The human may decide them on that page with one passkey, or one by one. [Approvals](../concepts/approvals.md#deciding-several-together) says what is never decided together.

## The same request again and again

When the same shape of request keeps needing approval, propose a standing rule: `mehen policy propose --from apr_... --reason "<why>" --json` (MCP `vault_policy` `propose`). The human turns it on with their passkey, for 1, 7 or 30 days, and matching requests then go through without asking; sends, payments, sharing, deletes and protected environments always ask. If the vault answers that standing rules are not switched on, or refuses the rule, keep asking for each request. [Standing rules](standing-rules.md) has the procedure.

When the requests differ but are all routine building on one service (filing issues, setting up Workers and their routes), propose a task grant from the held request instead: `mehen policy propose --from apr_... --item <slug> --area <area> --reason "<why>" --json`. It lasts 15 minutes, an hour or four hours. [Standing rules](standing-rules.md#task-grants) has that procedure too.

## Keep it readable

Because the human decides on what the page shows, keep bodies that need approval small and readable: plain JSON or form fields, uncompressed, no padding, no large attachments. The vault refuses to ask for approval of a compressed body, a body over 64 KiB or more than 16 KiB of forwarded headers (`mode_refused`). A body that is not UTF-8 text is shown only as a byte count, so the human cannot inspect it. `mehen check` tells you beforehand whether a request will need approval.

## Production runs

A protected environment such as `prod` only runs when you type `--env prod` literally, the machine is allowed protected environments, its owner holds the protected right on the project, and a human approves the run. The approval page shows the project, environment, command arguments, variable names and which variables receive real values or placeholders. The request digest also binds the submitted remote, worktree and commit, but this page does not display those fields. Check the CLI's resolved context before requesting approval. The approval covers the whole command line: the same command with other arguments needs a new approval. A command line over 4096 characters, or with one argument over 1024, cannot be approved (`mode_refused`); put it in a script and run that.

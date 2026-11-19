---
title: Standing rules
question: How does an agent stop asking for the same request every time?
section: guides
covers: both
order: 85
---

# Standing rules

A **standing rule** lets one shape of request through without asking, for 1, 7 or 30 days. The agent proposes it; a person turns it on with their passkey on the vault page, and nothing changes before that. A rule covers one credential, the one key that asked (the machine's own, or one workload's), one method, one host, one path or path pattern, the same query parameter names and, for GraphQL, the same mutation fields. Every other request on that credential still meets its policy as before.

Standing rules are off until the vault switches them on for your workspace, and never on in a managed workspace. Where they are off, `mehen policy propose`, `preview` and `ls` answer `forbidden`, "Standing rules are not switched on for this workspace yet." (over HTTP the vault's own message is "Policy widening is not available yet."): ask for each request as usual ([When a request needs approval](approvals.md)). The commands on this page need `mehen` 0.3.12 or later, and task grants 0.3.17 (`mehen version --json` says which you have); `mehen update --json` installs the latest release.

## When to propose one

Propose a rule when the same request shape keeps needing approval: the human has approved the same kind of Linear comment three times today and will be asked again. Do not propose one for a request you made once, for a request the human denied, or to get round a refusal.

## Propose a rule

From a request the vault held or approved, by its approval id (from exit 3 or `mehen wait`):

```sh
mehen policy propose --from apr_7Hq2 --reason "Post review comments on Linear issues while this sprint runs" --json
```

The rule serves the context that request was asked in: its project and environment, or none, and whether it came through `mehen fetch` or a `mehen run` placeholder.

From an example request, when there is no approval to point at:

```sh
mehen policy propose --item linear-work --method POST --url https://api.linear.app/graphql --content-type application/json -d @comment.json --reason "Post review comments on Linear issues while this sprint runs" --json
```

The vault checks an example as its relay would check the real request, and sends nothing. Without `--project <prj_id> --env <name>`, the rule covers only requests made outside any project, and `mehen` says so; `--no-context` asks for that explicitly.

- `--path` picks one of the vault's path choices: the request's own path (the default) or a pattern with `*` in place of one id segment.
- `--for 1d`, `7d` or `30d` sets how long it lasts; 7 days is the default.
- `--reason` is required. The person approving reads it as the agent's words, not checked by the vault.

`mehen policy preview` takes the same flags, needs no `--reason` and creates nothing: it prints the terms, the path choices and, when the request cannot become a rule, the reason it asks every time. The MCP tool is `vault_policy` with `action: "preview"` or `"propose"`, and `from`, or `item`, `method` and `url` (with `body` or `bodyBase64`, `contentType` and `context`), plus `path`, `for` and `reason`.

`propose` returns an ask titled "Allow from now on". Write the block as for any ask (the check is the binding code), then `mehen wait <pol_id> --timeout 60 --json`. `mehen policy status <pol_id>` reads it once without waiting, and `mehen policy cancel <pol_id>` withdraws it. A proposal lasts a day. Proposing the same terms with the same reason again while one is pending returns that proposal; a different pending proposal for the same credential is a `conflict`, so cancel it first.

## What the human sees and signs

A person meets a rule in one of two places:

- **The approval page** of a held request, when the request could become a rule, offers **Approve once** and **Approve and allow this from now on**. When the request cannot, a muted line says why ("This request sends mail or a message, so it asks every time.").
- **The proposal page**, `/w/<slug>/p/<pol_id>`, shows the agent's reason quoted under "Written by the agent. The vault does not check it.", with **Approve with passkey** and **Deny**.

Both show the same panel, "From now on, without asking you":

| Line | What it says |
| --- | --- |
| Credential | The slug, and the account it acts as |
| Request | The method and host, and for GraphQL "GraphQL mutation `commentCreate` only" |
| Path | The vault's path choices, narrowest first |
| Who | "This machine, sam-laptop" or "Only task *name* on sam-laptop": always the key that asked |
| Context | The project and environment, when the request named them |
| How long | 1 day, 7 days (the default) or 30 days |
| Still asks | "Anything else on this credential, and any request that sends, pays, shares or deletes" |
| Ends sooner | "if access changes or this credential is replaced, reconnected or edited" |

The vault builds these terms from the request it stored, never from the agent's description. The page checks its copy against the vault's before Approve turns on, and the passkey signs the digest of the terms with the path and duration chosen.

**Narrowing.** The person may pick a narrower path (the exact path in place of a pattern) or a shorter duration than the agent proposed. Neither can be wider or longer than the proposal.

## Who turns it on

The machine's owner approves a rule for their own machine; for a team's machine, anyone who may approve that machine's ask does. An owner or admin never turns a rule on for another member's machine.

**Co-sign.** When the person approving also manages the credential's home (an owner or admin for a workspace credential, a manager of the project for a project's, the owner for a private one), one passkey is enough: Sam approving for their own machine in their own workspace makes the rule at once. When they do not, their approval only proposes it. On the approval page the button reads **Approve once and ask a manager to allow it from now on**: this request is approved once and a proposal opens for the credential's home. A manager of that home, other than the person who approved, co-signs it on the proposal page. `mehen policy status <pol_id>` says which stage your own proposal is at. For one opened from an approval page, `mehen wait <apr_id>` gives its link and code, and names the rule once it is co-signed.

A guest's machine cannot propose a rule, and nobody can make one in a [managed workspace](../concepts/platforms.md), where the platform decides every held request.

## How long it lasts, extending and stopping

A rule ends at its deadline, which is never more than 30 days away. It ends sooner when:

- someone stops it;
- access changes under it: the person who approved or co-signed leaves, changes role or loses the right to decide, the machine is revoked or rescoped, the workload ends, or a protected environment starts to reference the credential;
- the credential is replaced (a new value), reconnected or edited.

The credential's page and the machine's page list rules under "Allowed without asking": who, the request, who approved, uses, last use and end, with **Stop** and **Extend**. Stopping only narrows, so it needs no passkey; the machine's owner, the person who approved or co-signed, any manager of the credential's home, a manager of the project the request was asked in, and an owner or admin may stop a rule, as may a member of the team for a team's machine (never a guest). The agent stops its own with `mehen policy revoke <rul_id>` (MCP `vault_policy` `revoke`); `mehen policy stop` is the old name.

The machine's owner may **Extend** a rule with a passkey, which sets its end to 1, 7 or 30 days from now. When they do not manage the credential's home, a manager of it co-signs the extension, as for a new rule.

## How the agent knows

- A request a rule allowed answers as usual, plus the response header `Mehen-Rule: rul_...`. `mehen fetch` adds "allowed without asking by rule rul_..., ends ..." on stderr; `mehen fetch --json` and `vault_fetch` add `rules: [{ id, endsAt }]`. `endsAt` is null when the vault could not say; `mehen policy ls` has it.
- `mehen policy ls` (MCP `vault_policy` `ls`) lists the rules of the key that asks, live first: the request, the context, which key, the end, uses, last use and status, with an ended rule's reason (`expired`, `revoked`, `access-changed` or `credential-changed`). `--item <slug>` narrows it to one credential, and `mehen policy show <item>` adds that credential's live rules.
- After **Approve and allow this from now on**, `mehen wait <apr_id>` names the rule ("Allowed from now on by rule rul_... until ..."), or the proposal's link and code while it waits for a co-signer.
- When a rule ends between the vault matching it and sending the request, the answer is `conflict`, "The rule that allowed this request has ended; send it again to ask for approval.", and nothing was sent. Send it once more: it is held for approval as usual. Do not retry in a loop.

## What never becomes a rule

The vault refuses a rule, and the request asks every time, when:

- the credential holds a live key (a Stripe `sk_live_` or `rk_live_` secret);
- the request sends mail or a message, pays or moves money, shares or publishes something, changes credentials or access, or sets up something that keeps running. A write whose path names one of these, such as `/messages/send`, `/payments` or `/settings/forwarding`, or a read whose path names sending, publishing or paying, such as `/sendMessage`, is refused except on the catalogue's reviewed routes, such as GitHub issue comments. Creating or changing a calendar event, which can invite and email people, and changing a GitHub repository's settings, which can make it public, cannot become a standing rule either. Nor is a setting that changes who has access ever remembered: a GitHub organisation's settings, its teams, security managers, blocks and rulesets, a repository's branch protection, rulesets and environments, a fork, a copy from a template or a Pages site, and a Vercel project's or team's settings or protection bypass. They all still follow the credential's own policy;
- it deletes or removes something: any `DELETE`, or a GraphQL mutation whose fields name deleting, archiving or revoking, such as `issueDelete`;
- the credential's policy denies it, or the credential's own rules ask for it every time;
- the vault cannot read what it does: its path names something sensitive (a token, a key, a webhook, a member, a role), its body is not sent as `application/json`, or is a batch, a JSON-RPC call, a method override or encoded, its query string cannot be pinned down, or a GraphQL body is not one mutation the vault can prove field by field;
- it goes anywhere but a standard HTTPS address, uses a method other than `GET`, `HEAD`, `POST`, `PUT` or `PATCH`, or reaches wider than the credential's binding lets a rule name.

A rule also never applies to a lease or a reveal, to a protected credential, environment or run, or to anything the policy denies. It only turns a request the policy would hold into one that goes through.

## Task grants

A standing rule pins one request shape. When the requests differ but are all routine building on one service, such as filing issues or setting up a Worker with its routes and KV namespace, a **task grant** fits better: routine work in the areas named, for 15 minutes, an hour or four hours, up to a number of requests. It needs `mehen` 0.3.17 or later, and it is switched on and off with standing rules.

Only a service with a reviewed list can have one: GitHub, Stripe and Cloudflare today. The areas are on [Agent reference](../reference/agent-reference.md#task-grant-areas). Propose it from a request the vault held or approved:

```sh
mehen policy propose --from apr_7Hq2 --item cloudflare-work --area workers,routes,kv --for 1h --uses 50 --reason "Set up the staging Worker, its route and its KV namespace" --json
```

- `--item` names the held request's credential, as a cross-check.
- `--area` takes one area or several, comma-separated or repeated.
- `--for` is `15m`, `1h` (the default) or `4h`; `--uses` is 1 to 200 (50 by default).
- The grant serves the key, the project and environment (or none) and the mode the `--from` request was asked in. `--method`, `--url`, `-d`, `--content-type`, `--project`, `--env`, `--path` and `--no-context` are usage errors with `--area`.
- MCP: `vault_policy` with `action: "propose"`, `from`, `item`, `area` (a list), `for`, `uses` and `reason`.

It returns an ask titled "Allow from now on"; write the block and `mehen wait <pol_id> --timeout 60 --json`. The person sees the areas, duration and uses on the proposal page, read only, and approves with a passkey. When they do not manage the credential's home, the proposal waits for a manager of it to co-sign, as a rule does. A person can also start a task grant without you, from the approval page of a held routine request.

The vault refuses a grant with `forbidden` and says why:

| `areaRefused` | Meaning | Do |
| --- | --- | --- |
| `area.unreviewed` | Nobody has reviewed this service's routes | Ask for each request |
| `area.not-routine` | The `--from` request is not routine building | Ask for each request |
| `area.live-key` | The credential holds a live key | Ask for each request |
| `area.terms` | These terms cannot start a task grant | Ask for each request |
| `area.unknown` | An area is not on the service's list | Pick from the list and propose again |
| `area.duration`, `area.uses` | A duration or number the vault does not take | Pick again and propose again |

A guest's machine cannot ask for a task grant (`forbidden`), and a protected credential always asks (`environment_refused`).

A grant covers only the reviewed routes marked routine in its areas, with no query string and with a JSON body, on that credential's host. Deletes, secrets, sending, sharing, payments and anything outside the areas still ask. A request it let through answers as usual; `mehen fetch` adds "allowed without asking by task grant rul_..., use 3 of 50, ends ..." on stderr, and `--json` carries the use count in `rules`. `mehen policy ls --grants` lists your grants with their areas, uses, end and what they were used for. The grant ends at its deadline, at its last use, when someone stops it, when access changes or the credential is replaced, reconnected or edited, or when a newer grant for the same credential and key replaces it. A request racing for the last use gets the `conflict` above: send it once more, and it asks.

`mehen check` says when a live task grant may cover a held request ("A task grant on issues may cover this ...", `mayCover` in `--json`). It is a hint: it reads the request as made outside any project, the exit code stays the policy's, and the vault decides when the request is sent.

## How careful a credential is

A person can also set a credential's posture on its page: ask for every change (the default), let routine building through, or trust their own machines ([Policy](../concepts/policy.md#how-careful-a-credential-is)). You cannot propose one. `mehen show <item>` prints how it applies to this machine, for example `How careful: routine building allowed for this machine`, and `mehen fetch` says "allowed without asking: this credential lets routine building through" for a request it let through (`Mehen-Posture`, `postures` in `--json`). Treat it as the vault's account of what happened, not a promise about the next request: the posture can change at any time, and it never covers what always asks.

## Example: Linear comments for a week

An agent reviewing a sprint posts comments on Linear issues with `linear-work`, a Linear API key. Linear takes every write as a GraphQL mutation to `POST https://api.linear.app/graphql`, and the Linear template holds every mutation for approval. The agent keeps the mutation text the same and puts what changes in `variables`:

```json
{
  "query": "mutation CommentCreate($input: CommentCreateInput!) { commentCreate(input: $input) { success comment { id } } }",
  "variables": { "input": { "issueId": "ENG-412", "body": "Reproduced on main; the fix is in the linked PR." } }
}
```

1. The first comment is held (exit 3, `apr_7Hq2`). The human approves it once, and it goes out.
2. The second and third are held too. The agent proposes a rule from the last one: `mehen policy propose --from apr_9Kd4 --for 7d --reason "Post review comments on Linear issues while this sprint runs" --json`, and writes the block. (Sam could equally have picked **Approve and allow this from now on** on any of those approval pages.)
3. Sam, who owns the machine and the workspace, opens the proposal page. It reads `POST api.linear.app/graphql`, "GraphQL mutation `commentCreate` only", "This machine, sam-laptop", 7 days. Sam ticks the code and approves with a passkey.
4. For the next 7 days, a `commentCreate` from sam-laptop with the same fields (`success`, `comment`, `id`) goes through without asking, whatever the issue and the text. Each response carries `Mehen-Rule: rul_...`, and each use is counted on the credential's page.
5. The agent then tries `issueDelete`. That mutation is not `commentCreate`, so the rule does not cover it, and it is held for approval as before. It could never become a rule either: it deletes.

---
title: Agent reference
question: Which tools, templates and AGENTS.md lines does the skill point to?
section: reference
covers: both
order: 85
agentOnly: true
---

# Agent reference

The parts of [the skill](https://docs.mehen.dev/skill.md) an agent looks up rather than keeps in mind: the MCP tools and their inputs, what to say when refused, the areas a task grant can name, mandates, push destinations, the templates by group and the routes they deny, the per-agent setup commands and a snippet for a repo's `AGENTS.md`. The rules stay in the skill. The generated pages carry every detail: [MCP tools](https://docs.mehen.dev/reference/mcp.md), [providers and templates](https://docs.mehen.dev/reference/providers.md) and [the ask object](https://docs.mehen.dev/reference/ask.md).

## MCP tools

By default the server lists the six core tools: `vault_status`, `vault_list`, `vault_request`, `vault_fetch`, `vault_env` and `vault_wait`. The rest are in opt-in toolsets: `inspect` (`vault_doctor`, `vault_templates`, `vault_show`, `vault_check`, `vault_pending`), `connect` (`vault_connect`), `writes` (`vault_plan`, `vault_fill`, `vault_push`), `policy` (`vault_policy`, `vault_mandate`) and `adopt` (`vault_adopt_scan`, `vault_adopt_status`). The harness adds them with `mehen mcp --toolsets <names>` or `MEHEN_MCP_TOOLSETS`; `all` serves every tool. A call to a tool the server does not serve is refused `tool_not_served`, naming its toolset, with the `mehen` command that does the same as `next.command`. See [MCP tools](mcp.md).

Every tool except `vault_templates` also takes `workspace?` (a slug or id), needed when this server may use more than one workspace and neither the call nor the checkout decides:

- `vault_status`: `mehen status --json`, every workspace this server may use, each with its `state` and `check` (usable when `state` is `active` and `check.ok` is true; when none is, the top-level `next` is the first failed check's, and `mehen status` exits with its code, its `--json` carrying that check's `error` and `message` on top too) and, when the vault says, this machine's live `mandate` (or `null`) and `mandateProposals` waiting for a signer; before any enrolment it is a success with `next.command`
- `vault_doctor`: `mehen doctor --json`, every check in one call with the next step; before enrolment too
- `vault_templates` (`id?`): each template's id, title, category, kind and hosts and each provider's id, title, category, client template and hosts; with `id`, one in full as `mehen templates <id> --json`. No network
- `vault_list` (`tag?`, `kind?`, `provider?`, `search?`, `offset?`, `limit?`): a short row per item, 100 at a time, with `nextOffset` while more remain; `vault_show` has the rest
- `vault_show` (`item`), with `policySummary`
- `vault_check` (`item`, `method`, `url`, `headers?`, `body?`): advisory; fetches public item metadata, sends nothing upstream and creates no approval
- `vault_request` (`kind`, `name`, `reason`, `provider?`, `tags?`, `hosts?`, `paths?`, `injection?`, `new?`, `home?`, `project?`): `home` defaults to private, which a machine with `scope.privateCredentials` false cannot use; pass `home: "project"` with `project`, or `home: "workspace"`
- `vault_connect` (`provider`, `name`, `reason`, `client?`, `scopes?`, `expect?`, `requestClient?`, `clientTags?`, `new?`, `home?`, `project?`)
- `vault_fetch` (`item` or `run`, `method`, `url`, `headers?`, `body?` or `bodyBase64?`, `approval?`, `replaces?`, `context?` `{ project, environment }`, `select?`, `timeoutSeconds?`; or `approval` alone, with `select?` and `timeoutSeconds?`, to send the request saved when it was held, once): a held answer carries `replay` (`{ saved: true, expiresAt }`, or `{ saved: false, reason }`); `replaces` names this machine's open `apr_` ask to the same place that this corrected request replaces; that ask then reads `superseded`. A result a standing rule, task grant or posture let through says so in `rules` (with a task grant's uses) or `postures`, and one this machine's mandate let through in `mandate` (its `mdt_` id). An ask a mandate's daily cap caused carries `mandate` `{ id, capped }` and its message names the caps reached
- `vault_plan` (`action`: `check` or `submit`, `plan` `{ version: 1, reason?, project?, env?, requests: [{ item, method, url, headers?, body? or bodyBase64? }] }`): up to 20 writes, bodies inline only. `submit` holds those that need a human in one bundle (`bnd_`) at one link; each result has its outcome (`ask`, `allowed` or `refused`) and `fetch`, the `vault_fetch` arguments that send it once approved
- `vault_fill` (`item`, `field`, `cdp`, `selector`, `target?`, `submit?`, `context?`, `approval?`): types a `password-login`'s `username`, `password` or `totp`, a `totp` item's `code`, or the `key`, `token` or `value` of an `api-key`, `bearer-token` or `generic` item into one field of the agent's own browser; never returns the value. [Type a credential into a web page](https://docs.mehen.dev/guides/fill.md) has the whole procedure
- `vault_push` (`item`, `field?`, `to`, `with?`, `reason?`): asks for one secret field to be put into a GitHub, Vercel or Cloudflare secret store, with `to` as the destination's JSON ([Push destinations](#push-destinations)). It hands back `approval_required` with the ask; `vault_wait` with the approval id ends once the push has. It returns a `PushResult` only for the same push done in the last ten minutes, and never the value
- `vault_env` (`env?`, `cwd?`, `check?`): the `cwd`'s `mehen.toml` selects the workspace; one outside what the server may use is `workspace_not_allowed`
- `vault_wait` (`id` of `int_`, `apr_`, `con_`, `enr_`, `adp_`, `pol_`, `bnd_` or `mdp_`, `timeoutSeconds?` up to 600, default 45, `execute?` for an `apr_` id: once approved, send the saved request and answer with its result; a push only waits): finds the id in whichever workspace holds it; sends `notifications/progress` when the call carries a `progressToken`. A bundle is done when none of its requests waits; a denial names the approved ones, which stay usable. A push's approval is done once the push has: `push.state` `done`, or `provider_refused` with `providerStatus`, or `failed`
- `vault_pending`: `{ pending: Ask[], groups?, notices? }`, this machine's own asks in every workspace, each with its `context`; an approval a human can review with others carries `group` (its Review together page, how many of its asks are open and the code that page shows)
- `vault_adopt_scan` and `vault_adopt_status`: names and batch state for `mehen adopt`, never values
- `vault_policy` (`action`, `item?`, `from?`, `method?`, `url?`, `body?` or `bodyBase64?`, `contentType?`, `context?`, `path?`, `for?`, `area?`, `uses?`, `grants?`, `reason?`, `id?`): standing rules and task grants. `show` reads an item's policy and live rules, `ls` lists this key's rules (with `grants: true`, its task grants too), `preview` says what a rule would cover, `propose` (with `reason`, and `from` or `item`, `method` and `url`) returns the ask to hand over, `status` and `cancel` take a `pol_` id, `revoke` a `rul_` id. `propose` with `area` (and `from`, `item` and `reason`) asks for a task grant: `for` is `15m`, `1h` or `4h`, `uses` 1 to 200 (50 when absent). Only the human's passkey turns either on; "Standing rules are not switched on for this workspace yet" or a refusal means ask for each request as usual
- `vault_mandate` (`action`, `note?`, `items?`, `classes?`, `days?`, `caps?`, `schedule?`, `reason?`, `id?`, `since?`, `before?`): this machine's mandates ([Mandates](#mandates)). `propose` (with `note`) returns the ask to hand over, or the same open proposal again with `existing: true`; `vault_wait` with its `mdp_` id ends once a person signs it. `list` gives this machine's open proposals (`proposals`) and its mandates with today's counts, `show` (`id`) one, `uses` (`id`, `since?`, `before?`) lists what went through on trust, newest first, at most 500 at a time (past that it returns `truncated: true` and `next`, to pass as `before`), and `pause` (`id?`, this machine's live mandate here when absent) stops it covering anything now. No action signs, resumes or stops one

Any result or error that hands over a link carries `ask` in `structuredContent` and a `resource_link` in `content`; `isError` stays true for `approval_required`, `needs_reauth`, `client_missing` and `timeout`. No tool opens a link.

`mehen run`, `mehen env set`, `mehen init`, `mehen workspace`, `mehen enrol`, `mehen revoke`, `mehen freeze`, `mehen adopt` beyond `scan` and `status` (`plan`, `submit`, `cancel`, `apply`, `verify`, `retire`, `unretire`, `inventory`), `mehen backup`, `mehen workload`, `mehen setup`, `mehen update` and `mehen guide` are CLI only.

## When refused

- On approval required, say what you want to do and with which account, then the block: "I want to send the reply to Sam from gmail-personal."
- `workspace_mismatch` (exit 2): a flag, `MEHEN_VAULT_URL`, `mehen.toml` or this machine's key names another workspace. Give one selection and fix the other; [`workspace_mismatch`](https://docs.mehen.dev/reference/errors.md#workspace_mismatch) lists every source, and what an enrolment mismatch says.

## Asking less

- **A standing rule** lets one request shape through for 1, 7 or 30 days. Propose it when the same request keeps asking.
- **A task grant** lets routine building in the areas named through for 15 minutes, an hour (the default) or four hours, up to a number of requests (50 by default, at most 200). Propose it from a held or approved request when one kind of work keeps asking: `mehen policy propose --from apr_... --item <slug> --area <area>[,<area>] --reason "<why>" --json`.
- **How careful** a credential is (`mehen show`, `posture` in `--json`) is set by a person: `asks for every change`, routine building allowed for this machine, or this machine trusted. Only a person changes it; there is nothing to propose.
- **A mandate** lets this machine's held requests of the kinds named through without asking, within daily caps, until a date. Propose one for a machine that runs unattended when the same kinds of ask keep coming: [Mandates](#mandates).

A response one of them let through says "allowed without asking" on stderr, with `Mehen-Rule`, `Mehen-Posture` or `Mehen-Mandate` in the headers; `mehen policy ls --grants` lists this key's rules and task grants, and `mehen mandate ls` this machine's mandates. `mehen check` says when a live task grant or the posture may cover a held request (`mayCover`); it is a hint, and the vault decides when the request is sent. No rule, task grant or posture ever covers a send, a payment, sharing, a delete, a change to credentials or access, a protected credential, environment or run, a credential holding a live key, or anything in a managed workspace.

### Mandates

A person signs a mandate once, with their passkey, for one of their own machines. The machine proposes; the person may change any term before signing, and nothing is covered until they do. The proposal link lasts 7 days.

```sh
mehen mandate propose --note "Nightly triage of the support inbox" --items gmail-support,linear-work --classes read,change,send --caps send=10 --schedule "Europe/Paris mon-fri 08:00-19:00" --json
```

- `--note` (required) is what the mandate is for; the person signing reads it. `--reason` says why the machine asks now (the note when absent).
- `--items`: slugs separated by commas; by default the credentials this machine asked for in the last 30 days.
- `--classes`: `read`, `change`, `send` and `delete`; by default `read` and the kinds this machine asked for in the last 30 days. `read` is always included.
- `--days`: 1, 7 or 30 (the default and the most a machine may propose).
- `--caps`: requests a day for a class, such as `send=5,delete=2`; each class left out takes the default, which is also the most a machine may propose: 500 reads, 100 changes, 10 sends, 5 deletes.
- A machine may propose a mandate only for what it asked for, and no wider: the vault refuses a proposal that names every credential (`mandateRefused: "items_all"`), a credential it has not asked for (`item_unasked`), a class besides `read` it has not asked for (`class_unasked`), more than 30 days (`term_too_long`) or a cap above 500 reads, 100 changes, 10 sends or 5 deletes a day (`caps_too_high`). What it may propose is what it asked for (and not rejected) or used under its own mandate: each credential and class of its own held requests that carried a `mandateCover` hint, unless a person rejected that ask, and of the requests its own mandate let through, from the last 30 days up to now, for credentials it can still reach. An ask left to lapse still counts, and so does another ask of the same credential and kind when one is rejected; another machine's never count. A machine can make that history itself, by asking: it narrows a proposal to what the agent has been doing, and the person still decides. The refusal is `forbidden`, names what to drop or lower and what it asked for, and `next.command` proposes the same terms cut to what is allowed, with the same hours (`--schedule`, quoted for a shell). There is no command when there is no valid bounded retry: when it would name more than 200 credentials (choose at most 200 with `--items`), or when an explicit list shares no credential with what was asked for (choose from those with `--items`). A proposal keeps the credential behind each slug it names: deleting a credential closes the open proposals that name it, and signing one whose slug now names another credential is refused. This binds the machine alone: the person who signs may tick any credential and kind, and choose any length and caps, on the sign page, with the passkey as before. With nothing asked for in 30 days, `mehen mandate propose` without `--items` refuses at once (`forbidden`): ask for each request as usual. A cap reached makes that kind of request ask again until the next UTC day, and the ask says which caps ("This machine's mandate has used today's 50 sends."). More than 120 requests beyond reading in a minute trips the whole mandate.
- `--schedule`: only in these hours. The time zone once, then windows separated by `;`, each days and hours: `"Europe/Paris mon-fri 08:00-19:00; sat 10:00-14:00"`. Days are `daily`, or `mon` to `sun` with forward ranges (`mon-fri`) and commas; a window ending earlier than it starts runs past midnight, on the day it started. At any time when absent.

`mehen mandate propose` prints the ask and exits 0: write the block, then `mehen wait <mdp_id> --timeout 60 --json`, and carry on asking for each request as usual until it ends. The wait ends with exit 0 and `mandate` once a person signs it, or signs this machine another mandate first (`state: "expired"` with that `mandate`); exit 1 `expired` when it lapsed unsigned, and nothing changed. A signed proposal is the person's decision, not proof that the next request goes through: the vault decides each request when it is sent. Proposing the same terms and reason while they wait hands back the same link with `existing: true`; at 3 open it is refused (`conflict`) with the newest one's link, and after 10 in a day it is `rate_limited`, with no link. `mehen mandate ls` lists this machine's open proposals first ("Waiting for its signer: <url>, proposed <date>, expires <date>: <reason>"), then its mandates with today's counts (UTC); `mehen mandate show <mdt_id>` reads one; `mehen mandate uses <mdt_id> [--since 1h]` lists what went through on trust; `mehen mandate pause [<mdt_id>]` stops it covering anything now, with no id this machine's live mandate in this workspace. A paused, tripped or ended mandate carries its page in `next.url`: hand it to the person. `mehen status` shows the live mandate with today's counts against its caps (`mandate` in `--json`, `null` for none) and how many proposals wait for a signer (`mandateProposals`). The machine never signs, resumes or stops one: the person who signed it resumes a paused or tripped one from the mandate page, without a passkey when the machine paused it and their access has not changed. "This workspace has no mandates" means they are not switched on there: do not propose one again.

#### When a request asks: `mandateCover`

An `approval_required` to this machine (from `mehen fetch`, `vault_fetch`, and each held request of `mehen plan submit` and `vault_plan`) may carry `mandateCover`: a mandate could let requests like this one through. `classes` are the kinds it would need, `items` the credential the request used (`mehen` adds it), `mandate` and `url` this machine's mandate and its page. Propose only what the hint names: that credential and those classes, never `all`. By `state`:

- `none`: no mandate. When more asks like it will follow (unattended work, or the same kind of ask again), propose one with that credential and those classes, as the `mandate:` line says: `mehen mandate propose --items <slug> --classes <classes> --note "<why>" --json`, leaving the length to the default (the person may shorten it).
- `unticked`: it does not name this kind of request or this credential. When more asks like it will follow, propose its terms again (`mehen mandate show <mdt_id>`) with only that kind and credential added: signing a new mandate ends the old one.
- `paused`, `tripped`: the person who signed it can resume it at `url`; hand them the link, do not propose.
- `ended`: its signer can sign it again at `url`; hand them the link, do not propose.
- `outside_schedule`: it covers its hours only; wait for its hours or let the ask go to the person as usual, do not propose.
- `not_covering`: it is not covering requests right now; hand the person `url`, never guess why, do not propose.

Without `mandateCover`, no mandate would cover the request: do not propose one for it. A cap reached is `mandate` with `capped`, as above.

A mandate never covers minting or reading credentials, webhooks, forwarding, inbox rules, SSO, members, invites, permissions, sharing, publishing, money, a live key, a request Mehen cannot read, a host only a wildcard in the binding admits, a protected credential, environment or run, a workload's request, or anything in a managed or frozen workspace. Those ask every time.

### Task grant areas

A task grant names areas from the reviewed list of the service the credential reaches. Only these services have one; a credential for any other service cannot start a task grant ("Nobody has reviewed this service's routes").

| Service | Host | Areas |
| --- | --- | --- |
| GitHub | `api.github.com` | `issues` |
| Stripe | `api.stripe.com` | `products` (never with a live key) |
| Cloudflare | `api.cloudflare.com` | `workers`, `routes`, `kv`, `r2`, `d1`, `queues`, `pages`, `ai-gateway`, `vectorize`, `workflows`, `dns` |

An area covers only the routes the list marks as routine building in it. Anything else in the same area still asks. Cloudflare's `workers` area also reads Workers Analytics Engine data (`POST` to an account's `analytics_engine/sql`), with one SQL statement as the body, sent as plain text or as a form; any other type asks. It joined the list in version 2, so a grant or posture approved before it does not cover it.

## Several writes at once

`mehen plan submit <plan.json> --json` (MCP `vault_plan`) sends up to 20 requests to the vault, which checks each without sending any upstream and holds those that need a human in one bundle at one link. The ask's check is the bundle's one code, which its page shows (every request's binding code, in order, from a vault that sends none). `mehen wait bnd_... --timeout 60 --json` follows it; then send each request with its `repeat` command. `mehen check --plan <plan.json>` says first how many would go through, ask or be refused.

To correct a request that is still waiting, send the new one with `--replaces apr_...`: the old ask reads `superseded` and the new one is the one to wait on. A vault where deciding asks together is switched off refuses both as `forbidden`; send the requests one by one, without `--replaces`.

`mehen plan submit`, `--replaces` and review groups in `mehen pending` need `mehen` 0.3.17 or later (`mehen version --json` says which you have; `mehen update --json` installs the latest release).

## Pushing a secret into a provider

When a secret belongs in GitHub Actions, a Vercel project or a Cloudflare Worker, ask for a push: `mehen push <item>[#<field>] --to <destination> --reason "<why>" --json` (MCP `vault_push`). Do not lease the value with `mehen run`, or type it into the provider's dashboard with `mehen fill`, to put it there yourself. The vault reads the value and calls the provider; the value never reaches this machine. `mehen push` needs `mehen` 0.3.18 or later.

- A human must first tick "May be put into other services' secret stores" on the credential's page. Until then the push is refused with `mode_refused` and a link to that page: relay it.
- Every push asks a human, every time. No standing rule, task grant or posture covers one, and the human decides it on its own page. Write the block, then `mehen wait <apr_id> --timeout 60 --json`. The wait ends once the push has: exit 0 and `Pushed: ...: created`, `replaced` or `set`; exit 5 `provider_refused` with `providerStatus`; or exit 1 `failed`. Do not repeat the push afterwards: the approval is spent either way.
- `--with <item>` names the GitHub, Vercel or Cloudflare credential that writes it; without it the vault uses the one this machine may use for that provider, or answers `ambiguous` with `choices`.
- Where the vault has not switched pushing on for the workspace, the answer is `forbidden`, "Pushing is not available yet.": tell the human and stop. A managed workspace has no pushing.
- `mehen show <item>` lists where the credential was pushed.

### Push destinations

| Destination | Where it goes |
| --- | --- |
| `github:<owner>/<repo>/<NAME>` | A GitHub Actions repository secret |
| `github:<owner>/<repo>/env/<environment>/<NAME>` | A GitHub Actions environment secret |
| `github:<owner>/<repo>/dependabot/<NAME>` | A GitHub Dependabot secret |
| `vercel:<project>[@<team>]/<production\|preview\|development>/<NAME>` | A Vercel variable for one target |
| `cloudflare:<account id>/<script>/<NAME>` | A Cloudflare Worker secret |

MCP takes the same as JSON: `{ provider: "github", owner, repo, store: "actions" | "environment" | "dependabot", environment, name }`, `{ provider: "vercel", project, team, target, name }` or `{ provider: "cloudflare", account, script, name }`, already in the canonical form `mehen push` prints. Every part is lower case except the secret's name, which keeps its case (upper case for GitHub), and a Vercel `prj_` or `team_` id, which keeps its case. [Put a credential into another service](https://docs.mehen.dev/guides/push.md) has every rule.

## Templates

Kind `api-key`, by group:

- AI: `openai`, `anthropic`, `google-gemini`, `mistral`, `groq`, `openrouter`, `together`, `ollama-cloud`
- Code: `github-pat`, `snyk`, `vercel`, `npm`
- Work: `linear`, `slack-bot`, `notion` (send `Notion-Version` yourself), `gitbook`, `fathom`
- Observability: `sentry`, `posthog`, `betterstack-uptime`
- Infrastructure: `cloudflare-api-token`, `hetzner-cloud`, `scaleway`, `neon`
- Customers and email: `stripe`, `hubspot-private-app`, `intercom`, `resend`, `postmark-server`, `loops`
- Search and media: `brave-search`, `serpapi`, `semrush`, `firecrawl`, `browserbase`, `elevenlabs`, `heygen`

Kind `oauth-client`: `google-oauth-client`, `github-oauth-client`, `microsoft-oauth-client`. OAuth providers for `mehen connect`: `google-gmail`, `google-calendar`, `google-drive`, `github-oauth`, `microsoft-graph`.

`mehen templates` is the live list, grouped the same way, with what each allows, holds and refuses. MCP `vault_templates` lists each template's id, title, category, kind and hosts; with `id` it gives one in full, what it allows, holds and refuses included.

Routes the templates deny, and what to use instead:

- Gmail `drafts/send`: `messages/send` with the whole message.
- Microsoft Graph send, forward or reply of a stored message: `sendMail`.
- Microsoft Graph `$batch`: one request at a time.
- Mail forwarding, filters, delegates and mailbox rules, GitHub deploy keys, webhooks and collaborators: the human does it.

## Setup for one agent

`mehen setup --json` registers every agent it finds: Claude Code, Codex, Cursor, pi, Gemini CLI, OpenCode, VS Code and Claude Desktop. To register only a named client, use its writer; inspect the report and restart that agent:

```sh
mehen setup --agent claude-code --json
mehen setup --agent codex --json
mehen setup --agent pi --json
```

For every MCP tool rather than the core six, run `mehen setup --toolsets all --json` (or name the toolsets wanted) and restart the agent; it writes `MEHEN_MCP_TOOLSETS` into each entry, a later setup without the flag keeps it, and `--toolsets core` takes it out.

`--mcp-file <path>` writes `mcpServers.mehen` into a compatible JSON client's file; use `--agent vscode` or `--agent opencode` for those clients' different formats. `mehen setup --print --json` prints the entry without writing anything.

## AGENTS.md snippet

Paste this into a repo's `AGENTS.md` (or `CLAUDE.md`) when the repo uses Mehen:

```markdown
## Credentials

This repo uses Mehen. Secrets never appear in this repo, in chat or in your context.

- Never ask a human to paste a secret into chat, and never write one to a file, `.env` or commit.
  If one is pasted, do not use it; say it should be rotated.
- Run `mehen` with `--json`. Variables are declared in `mehen.toml` (committed, no values), which also
  names the project's workspace and vault. Check them with `mehen env check` and run anything that needs
  them with `mehen run -- <cmd>`. Read the `mehen:` line it prints on stderr and stop if the project or
  environment is wrong.
- Production runs need a literal `--env prod` and a human's approval. Never set `MEHEN_ENV=prod`.
- Call authenticated APIs with `mehen fetch <item> <METHOD> <url>` or the `vault_fetch` MCP tool.
  Never set auth headers or put a key or placeholder in a URL or body yourself.
- Missing credential: `mehen request <kind> --name <slug> --provider <template> --home project --reason "<why>"`
  (`--home project` puts it in this checkout's project, so the whole team can use it; without it the
  credential is private to the human), write the human the `ask` (link, what it is for, what to check,
  when it expires), then `mehen wait <id> --timeout 60 --json`. `mehen pending` lists the links still open. Trust only links under
  `https://app.mehen.dev/w/<slug>/` that `mehen` handed over.
- On any refusal, follow the `next` field and relay the `ask` or `next.say` to the human. Exit 3
  means approval required: send the link and the binding code, `mehen wait <approval> --timeout 60 --json`, then repeat
  the same request unchanged. Exit 5 means refused by rule: do not retry or work around it.
- Full guide: `mehen guide`.
```

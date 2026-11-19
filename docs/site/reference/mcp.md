---
title: MCP tools
question: What are the vault_* tools and their inputs?
section: reference
covers: both
order: 20
generate: mcp
---

# MCP tools

`mehen mcp [--workspace <slug or id>]` is a stdio MCP server named `mehen`. The CLI and the tools share core operations and enforcement; their inputs, output shapes, timeouts and body limits differ as documented below. No tool returns a secret. No MCP tool approves a request, starts an enrolment, revokes a machine or freezes a workspace; `vault_wait` can finish an enrolment already started at the terminal. `mehen setup` registers this one server in each agent on the machine.

**One server, several workspaces.** One server can serve several allowed workspaces, with a separate identity latch for each, including one enrolled while it runs. Its startup workspace, the checkout's manifest, a managed pin and the harness's `MEHEN_WORKSPACES` may restrict that set; a tool argument cannot widen it. Every tool except `vault_templates` takes `workspace` (slug or id). A server started with `--workspace` or `MEHEN_WORKSPACE` is pinned: a conflicting tool argument is `workspace_mismatch`, not an override. Otherwise the tool argument selects, then the startup checkout's `mehen.toml` (for `vault_env`, its call's own `cwd`), then the only active workspace; an unresolved call that needs one workspace is `context_ambiguous`, and `next.say` lists the choices. `vault_status`, `vault_doctor`, `vault_pending` and `vault_list` cover every workspace when none is named and the server is not pinned, and name the workspace on every row. A workspace whose enrolment changes under the running server is refused for the rest of the server's life with restart advice; the others keep serving.

**Hints for the host.** Every tool has a `title` and `annotations`: `readOnlyHint` and `openWorldHint` always, and `destructiveHint` and `idempotentHint` on each tool that is not read-only, the only tools they apply to. `vault_status`, `vault_doctor`, `vault_templates`, `vault_list`, `vault_show`, `vault_check`, `vault_env`, `vault_pending` and `vault_adopt_status` only read (`readOnlyHint: true`). One caveat: `vault_status` refreshes the workspace slug and name (and this machine's and its owner's names) recorded on this machine from the vault's authenticated answer, so a renamed workspace is still found; it changes nothing in the vault. `vault_fetch`, `vault_fill` and `vault_push` act on services outside the vault (`openWorldHint` and `destructiveHint` true). `vault_policy` and `vault_mandate` can end a rule or pause a mandate (`destructiveHint: true`). `vault_wait` and `vault_adopt_scan` are safe to repeat (`idempotentHint: true`). `vault_request` and `vault_connect` are not: asking again without `new` returns the same open link, but with `new: true` every call closes the open link and makes a new one. `vault_templates`, `vault_list`, `vault_check`, `vault_fetch`, `vault_env` and `vault_pending` carry an `outputSchema` naming their result's fields; it requires none, since a failed call's `structuredContent` is the error body instead.

## Cards in apps that draw them

A host that supports MCP Apps (the `io.modelcontextprotocol/ui` extension) can draw a small card beside a tool's result: Claude Desktop's Chat and Cowork tabs, ChatGPT, and the Codex app when its MCP Apps support is on. Claude Code, in the terminal or Claude Desktop's Code tab, draws none.

- The ask card goes with `vault_request`, `vault_connect`, `vault_policy` and `vault_pending`: what was asked, what to check, who asked, when the link expires, an **Open in vault** button and the ask's state, which changes by itself when the human approves, declines or the link expires. A result with no ask draws nothing.
- The adopt card goes with `vault_adopt_scan` (the counts, the folders with the most secrets, the folders that could not be read and the next command) and `vault_adopt_status` (the batch's state, its machines and what was refused).
- The server offers the cards only to a host whose `initialize` names the extension. Any other host gets the same `initialize` answer and tool list as before, and every tool's text and `structuredContent` are the same either way.
- A card follows its ask through a read-only tool only a card sees, vault_ask_state (`_meta.ui.visibility: ["app"]`), which is not in the list below. It reads the ask's state once or for up to 25 s, writes nothing, and leaves the ask for the agent's own `vault_wait`; it does not take `enr_` ids.
- A card has no network access, approves nothing and tells the agent nothing but the ask's id and final state. Approval stays on the vault page, with a passkey.

## Results and errors

- A success that hands over no link has its `structuredContent` again in `content` as one line of compact JSON, so a host that reads only text gets the same answer. `vault_list` and `vault_templates` answer in short rows, so a workspace with hundreds of items stays well under a host's limit on a tool's text (Claude Code saves any text over 50,000 characters to a file instead of showing it); `vault_show` or a template `id` gives one in full.
- Any result or error that hands over a link carries `ask` in `structuredContent` and, in `content`, the ask text plus `{ type: "resource_link", uri: ask.url, name: "<title> (<check label> <check value>)", description: ask.what, mimeType: "text/html" }`. A host that renders resource links gets the button for free. The text's `then:` line says `vault_wait { "id": "..." }` instead of a shell command.
- `isError` stays `true` for `approval_required`, `needs_reauth`, `client_missing` and `timeout`: the call did not do what was asked. Read the `ask` and hand it over; do not retry.
- A failed tool call has `isError: true`, a text summary with the `next` step, and `structuredContent` holding the same error object the CLI prints with `--json` (see [Errors and exit codes](errors.md)), except that a `next` written for the command line names the tool instead. `next.say` stays one sentence for the human. A step a tool does loses `next.command` and gains `next.tool`, the tool's name, and `next.arguments`, an object, when arguments carry over: `{ "tool": "vault_wait", "arguments": { "id": "apr_..." } }`, or `"tool": "vault_list"` for `mehen ls`. `next.arguments` are added to the call: keep the call's other arguments when `next.tool` is the tool you called (a workspace to name comes back as `{ "tool": "vault_fetch", "arguments": { "workspace": "acme" } }`, to add to the fetch you made), and fill in any placeholder (`{ "action": "pause", "id": "<mdt_id>" }`) before the call. The text shows the step as `call: vault_wait { "id": "apr_..." }`, unless the ask's `then:` line already names it. A `mehen ...` in backticks inside `next.say`, or a flag outside one, is named as the tools have it: `vault_list` for `mehen ls`, `client` for `--client`, `timeoutSeconds` for `--max-time`. A command written in plain prose keeps its words and flags. A usage error, and the vault's `bad_request` without a step of its own, point at the tool's input schema rather than a `--help`, and an unknown template or provider at `vault_templates` rather than `mehen templates`. A step only the command line takes (`mehen enrol`, `mehen update`, `mehen init`, `mehen workspace bind` and the like) keeps `next.command` and has no `next.tool`: only the mehen command line runs it, so if you cannot run commands, ask the human to run it in a terminal. The vault itself never sends `next.tool` or `next.arguments`.
- There is no MCP tool for `mehen run`, `mehen env set`, `mehen init`, `mehen workspace`, `mehen enrol`, `mehen revoke`, `mehen freeze`, `mehen adopt` beyond `scan` and `status` (`plan`, `submit`, `cancel`, `apply`, `verify`, `retire`, `unretire`, `inventory`), `mehen backup`, `mehen workload`, `mehen setup`, `mehen update` or `mehen guide`.

The tools follow, in the order the server lists them, each with its inputs from the server's own tool list.

### vault_status

The same as `mehen status --json`: every workspace this server may use, each with its `state` and, when active, its `check`. Before any enrolment it is not an error: read each entry by its state and follow `next`, which may tell you to enrol, to wait for an existing enrolment, or to list several pending asks. A workspace is connected when its entry is `active` with `check.ok: true`. With no active slots it sends no device check to a vault. Call it first. A successful check of a renamed workspace records its new slug and name.

### vault_doctor

The same as `mehen doctor --json`. Always a success, before enrolment too; `ok: false` and `next` say what to fix.

### vault_templates

With no `id`, `{ templates: [{ id, title, category, kind, hosts }], oauthProviders: [{ id, title, category, clientTemplate, hosts }] }`: short enough for any host, and an agent that knows only an API host finds its template by `hosts`. With `id`, one in full, the same as `mehen templates <id> --json`: hosts, scopes, `policySummary`, the docs link and the redirect URI. No network; it works before enrolment. [Providers and templates](providers.md) lists the same catalogue.

### vault_list

The items `mehen ls --json` lists, as one short row each: `{ slug, workspace, kind, provider?, account?, status, ceiling, hosts, leaseOnly?, review? }`, where `workspace` is the workspace's id and a lease-only credential has `hosts: []` and `leaseOnly: true`. The answer is `{ workspaces, items, total, nextOffset?, unavailable? }`: `workspaces` names each workspace that answered once (`{ id, slug, name }`), and `nextOffset`, when present, is the `offset` for the next page. `limit` defaults to 100 (at most 200), and `search` keeps the items whose slug or account contains its text, without regard to case; an empty `search` keeps every item. Pages run through every workspace's rows in one order, so a page can end in one workspace and the next carry on in another. When `total` or `unavailable` differs from the last page's, items were added or removed or a workspace stopped or started answering, and the offsets have moved: start again from offset 0. `vault_show` has one item in full.

### vault_show

The same as `mehen show --json`, plus `policySummary` (`{ allowed, approve, deny, rest }`, described from the rules' matchers; `mehen show` prints the same as its three policy lines).

### vault_check

The same as `mehen check --json`: `decision` is `allow`, `approve`, `deny` or `binding_refused`, with `matched`, `reason`, `bodyUnknown` and `advisory: true`. One read of the item, nothing sent, no approval created.

### vault_request

Ask a human to add a credential, or rotate an existing one this machine may reach: the same as `mehen request`, with `new` as `--new` and `home` and `project` as `--home` and `--project` (a project home without `project` uses the server's own startup manifest project). It returns a checked intake ask; the human enters the value on the vault's page, never in chat. A rotation keeps the credential's home, binding and policy. The result adds `kind`, `name`, `provider`, `ask`, and `warning` when a link was refused. A private home (the default) asked from a machine without private credentials is refused `forbidden`, and `next.say` names the `home` to pass instead; `vault_connect` does the same.

### vault_connect

The same as `mehen connect`. Without `client`, the one OAuth client that exists is used; several is a `usage` error with `choices`; none is `client_missing`, whose `request` is exactly the `vault_request` arguments for the client. `requestClient: true` returns the client intake's ask with `step: "client"`; call `vault_wait` for it, then `vault_connect` again with the same arguments for the connection link.

### vault_fetch

The same as `mehen fetch`. It returns `{ status, statusText, item, headers, body, truncated, note? }`. The body is text after vault processing, cut at 256 KiB; with `select` it returns `{ status, statusText, item, headers, selected, found }` from the whole response instead (within the vault's 32 MiB response limit), which is the way to read one field of a large JSON answer. For a whole large or binary body use `mehen fetch -o <file>` in a shell. `context` names the project environment the credential is used for, as `--project` and `--env`; it is never a workspace switch. A host's `notifications/cancelled` stops the request.

### vault_env

The same as `mehen env ls`, or `mehen env check` with `check`. The `cwd`'s `mehen.toml` selects the workspace; one outside what the server may use is `workspace_not_allowed`, and one that disagrees with `workspace` is `workspace_mismatch`, before anything is sent. It returns `{ exitCode, variables, context }`, where `variables` are the lines `mehen env ls` prints and `context` the lines it prints on stderr (the `mehen:` banner). When a variable does not resolve under `check`, the tool fails with `command_failed` and the message names the fix.

### vault_wait

The same as `mehen wait`, in whichever workspace holds the id; `timeoutSeconds` defaults to 45 and is at most 600, as the description above says. With a `progressToken` on the call, the server sends `notifications/progress` (`{ progressToken, progress: elapsedSeconds, total: timeoutSeconds, message }`) when the vault first reports the ask still open and then every 10 s; `notifications/cancelled` stops the call: no further poll, no more progress, no response.

With an `enr_` id it finishes an enrolment `mehen enrol` started on this machine; it cannot start one. On `active` it checks the vault's answer against the workspace and owner that were asked for, then writes the config, so `vault_status` lists the workspace as active on the next call and the server serves it at once. An answer for another workspace, owner kind or scope is refused, the new device's revocation attempted and the outcome reported.

### vault_pending

The same as `mehen pending --json`, across every workspace: `{ pending: Ask[], groups?, notices?, warning? }` plus a `resource_link` per ask. An approval a human can review with others carries `group`, and `groups` lists each such group with its Review together page and the approvals in it; `notices` appears only when this machine has any, and `warning` when an entry came with a link mehen did not trust.

### vault_policy

The same as `mehen policy`, for [standing rules and task grants](../guides/standing-rules.md): `show` (an item's policy and its live rules), `ls` (with `grants: true`, task grants too), `preview`, `propose`, `status`, `cancel` and `revoke`. `propose` returns an ask titled "Allow from now on" for the human, who turns the rule on with their passkey on the vault page; no action approves one. `propose` with `area` (and `from`, `item` and `reason`) asks for a [task grant](../guides/standing-rules.md#task-grants) instead: routine work in the areas named, for `for` `15m`, `1h` or `4h`, up to `uses` requests (1 to 200, 50 when absent). Where standing rules are switched off the vault answers `forbidden`, "Standing rules are not switched on for this workspace yet.": ask for each request as usual. A rule never stands in for a protected context.

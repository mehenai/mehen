---
title: Register mehen with each agent
question: How do I add the MCP server and the skill to Claude Code, Codex, Cursor, pi, Gemini CLI, OpenCode, VS Code, Claude Desktop or any MCP client?
section: guides
covers: both
order: 40
---

# Register mehen with each agent

Every agent talks to the vault through `mehen`, either as a command or as `mehen mcp`, a stdio MCP server named `mehen`. The machine must be enrolled first ([Connect an agent to one workspace](connect-one-workspace.md)). There is no token to configure: `mehen` signs each request with the machine's key.

## mehen setup

```sh
mehen setup --json
```

It registers one `mehen` MCP server and the skill in every agent it finds: Claude Code, Codex, Cursor, pi, Gemini CLI, OpenCode, VS Code and Claude Desktop. It writes user settings only, never a project's, with the absolute path of the `mehen` binary, and installs the skill in both Agent Skills locations. Running it again is harmless.

The report lists, per agent, `mcp`, `reason`, `skill`, `skillReason` and `restart`, and a `skills` list with each entry's `status` and `reason`:

- `added`, `updated` and `unchanged` are success.
- `skill: null` means this client has no known skill folder, not a failed installation.
- `skipped` and `external` mean something was left alone on purpose: a hand-made `mehen` entry, an entry edited by hand after setup, a symlinked skill. With the human's agreement, `--force` may replace an eligible foreign entry; it does not bypass an unsafe-file refusal. Read every entry's status and reason.
- `failed` means a write failed, and setup exits 1. Setup can also exit 2 when every targeted agent was skipped and nothing changed; read the report.

Reload or restart each agent as `restart` says; the `vault_*` tools arrive then. If they are missing after the restart, run `mehen setup --json` again and restart once more.

`mehen up` runs `mehen setup` for you on a machine with a local vault, then `mehen guard install`, which adds the [guard hooks](guard.md) to Claude Code, pi, Cursor and Codex. On any other machine, run `mehen guard install` yourself after setup.

## One named agent

```sh
mehen setup --agent claude-code --json
```

The names are `claude-code`, `codex`, `cursor`, `pi`, `gemini`, `opencode`, `vscode` and `claude-desktop`; repeat `--agent` for several. Use the same `MEHEN_HOME` and workspace limit as the intended identity. VS Code setup targets the default user profile only; for another profile, ask the human which client and profile to register.

Other options:

- `--dry-run` previews and writes nothing; `--remove` undoes the entries setup still owns. Setup keeps a first-change backup beside every config it changes until `--remove` restores its entry.
- `--workspaces <a,b>` requests a narrower entry ([Several workspaces on one machine](several-workspaces.md)); when an existing entry keeps a wider environment, `--reset-env` rebuilds it, with the human's agreement.

## Claude Desktop and the Codex app

- **Claude Desktop's Chat and Cowork tabs** read `claude_desktop_config.json` (the `claude-desktop` entry) and have no skills folder. They draw [cards](../reference/mcp.md#cards-in-apps-that-draw-them) for asks and adoption scans.
- **Claude Desktop's Code tab** is Claude Code: the same `~/.claude.json` and `~/.claude/skills` as the CLI (the `claude-code` entry), and no cards.
- **The Codex app** uses the same `~/.codex/config.toml` and `~/.agents/skills` as the Codex CLI (the `codex` entry). Its sandbox blocks the Secure Enclave and the network for shell commands, so use the `vault_*` tools there rather than `mehen` at a shell. It draws cards when its MCP Apps support is on.

## Any other MCP client

- **A JSON client that reads `mcpServers`:** `mehen setup --mcp-file <path> --json` writes `mcpServers.mehen` into that file.
- **Anything else:** `mehen setup --print --json` (or `--format toml`) prints the entry and writes nothing. Give it to the human to add; do not edit their configuration yourself.

Command names and configuration locations vary by client and version; check the client's own documentation for where an entry goes. Never work round a skipped or failed entry by writing an unrestricted server by hand.

## The skill

The skill is what Claude and pi agents load: the rules, the commands and what to tell the human. It is served at [`/skill.md`](/skill.md) (rendered at [The skill](../skill.md)), and `mehen setup` installs and refreshes it. An agent without skills can be given the `AGENTS.md` snippet at its end instead.

## Session labels

Set `MEHEN_SESSION` in the environment `mehen` or `mehen mcp` runs in (1 to 120 letters, digits, `.`, `:`, `_` or `-`): a session id, a task id, a subagent run. It goes into every request, the audit log, the `requestedBy.session` of every ask, and the details of the intake, connect and approval pages. It grants nothing, and no page uses it to say who asked: that line is always the enrolled machine's name. A harness that labels conversations might set it to the conversation's title in this alphabet plus a short hash of its id, so the human can tell which conversation asked. `mehen` refuses any other character with a usage error.

## One workload per task

A harness that runs many tasks on one machine (a hosted agent platform, a CI runner fanning out jobs, a parent agent starting subagents) can give each task its own [workload](../concepts/machines.md#workloads): a short-lived key with a scope narrower than the machine's. The vault then keeps each task to its own scope and its own asks and grants, names it on the pages a person decides on and in the audit, and ends its reach the moment the harness revokes it. A session label cannot do that: it is a word, and a workload is a key the vault checks.

A harness that serves many users of its own, each with their own credentials, wants platform mode instead: one managed workspace per user, with no Mehen account or page for any of them ([Build on Mehen](build-on-mehen.md)). Its agents still use workloads exactly as below.

`@mehen/client` is the library for it; it runs wherever WebCrypto and `fetch` do (Workers, Bun, Node 20 and later, browsers). It is not published to npm yet. This module enrols a machine that acts only through workloads, then runs one task as its own workload:

```ts
import { MehenRefusal, createClient, deviceSigner, enrolmentStatus, generateKey, startEnrolment, workloadSigner, type KeyPair } from "@mehen/client"

const vaultUrl = "https://app.mehen.dev"

export type Machine = { key: KeyPair; tenant: string; deviceId: string }

// Once per machine. A person opens the link, types the group the page hides
// and accepts with a passkey. Keep the key for later with exportPrivateKey,
// wrapped by your own secret store.
export async function enrolMachine(workspace: string): Promise<Machine> {
  const key = await generateKey()
  const started = await startEnrolment({ vaultUrl, key, workspace, owner: { kind: "self" }, name: "task-runner", scope: { modes: ["relay"], workloads: "required" } })
  console.log(`Open ${started.url} and type ${started.fingerprint.groups[started.hiddenGroup]}`)
  for (;;) {
    const status = await enrolmentStatus({ vaultUrl, key, enrolment: started.enrolment })
    if (status.status === "active") return { key, tenant: status.tenant, deviceId: status.device }
    if (status.status === "rejected" || status.status === "expired") throw new Error(`The enrolment was ${status.status}.`)
    await new Promise((resolve) => setTimeout(resolve, 5_000))
  }
}

// Once per task: a fresh key, a narrow scope, and a revoke however the task ends.
export async function runTask(machine: Machine): Promise<string> {
  const parent = createClient({ vaultUrl, tenant: machine.tenant, signer: deviceSigner(machine.deviceId, machine.key.privateKey) })
  const key = await generateKey()
  const workload = await parent.workloads.create({ jwk: key.jwk, label: "review-pr-42", ttlSeconds: 3600, scope: { items: ["github-work"], modes: ["relay"] } })
  try {
    // The task's process gets key.privateKey and the ids, never the device key.
    const task = createClient({ vaultUrl, tenant: machine.tenant, signer: workloadSigner(machine.deviceId, workload.workload, key.privateKey) })
    const answer = await task.relay({ item: "github-work", method: "GET", url: "https://api.github.com/user", headers: [["accept", "application/vnd.github+json"]] })
    return `GitHub answered ${answer.status}: ${new TextDecoder().decode(answer.body)}`
  } catch (error) {
    if (error instanceof MehenRefusal && error.code === "approval_required") console.log(`A person decides at ${error.link}, code ${error.bindingCode}`)
    throw error
  } finally {
    await parent.workloads.revoke(workload.workload)
  }
}
```

`relay` resolves with the upstream's own answer (`status`, `headers` as a `Headers`, `body` as bytes, `item`), whatever its status, and throws `MehenRefusal` when the vault refused: `code`, `message`, `next`, and for `approval_required` the `approval` id, `link`, `bindingCode` and `expiresAt`. The task waits with `task.approval(id, { wait: true })` and, once approved, sends the same request again with `approval: id`. A `MehenTransport` means no answer came back, so whether the upstream received the request is unknown: never retry a write blindly. A long enrolment wait calls `renewEnrolment` when fewer than five minutes remain on the lease.

The rules that make it hold:

- **The device key stays with the harness.** Whoever holds it can create new workloads up to the machine's whole scope, so it never goes into the task's process, environment, files or prompt. The task gets only its workload's key.
- **Scope each workload to the task**: the items, tags, projects and modes it needs, nothing more. A field left out is no limit. A workload scoped by `items` asks for an intake or a connection only for a slug in them, and a connection also needs the provider's OAuth client in `items` (for Gmail, `google-oauth-client`): `{ items: ["gmail-task", "google-oauth-client"] }`. Without it the connection is refused with `forbidden`, saying which client to list. A workload scoped by `tags` or `projects` asks only for what it could then see: tag the intake (or a connection's `clientTags`) with one of its tags, and home it in one of its projects. A task that sets plain (non-credential) project variables needs the project in `projects`: a workload whose scope names no projects changes none.
- **Revoke at the end**, success or failure; revoking is idempotent. Expiry (an hour by default, at most 24 hours a renewal, never past seven days) is the backstop, not the plan.
- **Label it so a person can tell tasks apart**: the label appears on approval, intake and connection pages as "Task: <label>, as the machine named it", in the audit, and on the machine's page, from 1 to 120 letters, digits, `.`, `:`, `_` or `-`. It is the machine's words, so the page marks it as such.
- **Relay a refusal as it is.** `approval_required` from a workload's request is that workload's ask: only it can wait on the approval and spend the grant. `workload_ended` means the task's reach is over; start a new workload only if the task should go on.

For a machine that should never act with its own key, enrol it with `--workloads-only`: then everything except reading, managing workloads, freezing and revoking itself is refused to the device key with `workload_required` ([Workloads required](../concepts/machines.md#workloads-required)). `mehen workload ls` and `mehen workload revoke <wl_id>` list and end the machine's workloads from its shell. `mehen` 0.3.0 has neither `--workloads-only` nor `mehen workload`; they came with 0.3.1.

## A project's environment for a hosted task

A hosted platform can give a task, a cloud container say, the environment of one [project](../concepts/projects.md): plain values as they are, and each secret as a [placeholder](../concepts/projects.md#placeholders) that only the vault turns back into the real value. The platform has no checkout, so it does what `mehen run` does without one:

1. **A workload pinned to the project**: its scope names the project in `projects`, with `placeholder` in its modes, `{ projects: ["prj_..."], modes: ["placeholder"] }`. The machine's own scope must include `placeholder` too.
2. **A run with no remote.** `remote: null` is accepted from a workload whose scope names the project, even when the project binds remotes: the device chose the project for the task, and the remote check exists to catch a mismatched checkout, which the task does not have. A protected environment still needs a bound remote, from any caller.
3. **Deliver what the run answers.** A `plain` variable goes into the task's environment as it is; a `placeholder` goes in as its placeholder, for the `hosts` its item is bound to; a `missing` one is left out.
4. **Forward the task's requests to those hosts as run-mode relays**, naming only the run, never an item. The vault swaps each placeholder it finds where its item allows, and refuses one anywhere else with `surface_refused`.
5. **End the run with the workload.** Renew the run every few minutes while the task lives (it lasts 15 minutes unless renewed, and at most 12 hours unless it is a service run), and revoke the workload when the task ends: revoking it ends its runs, and their placeholders stop working.

```ts
import type { MehenClient } from "@mehen/client"

// The workload was created with scope { projects: [project], modes: ["placeholder"] }.
export async function openEnvironment(task: MehenClient, project: string, env: string) {
  const read = await task.project(project)
  const vars = read.vars.filter((v) => v.env === env).map((v) => v.name)
  const run = await task.runs.create({ project, env, envSource: "flag", remote: null, worktree: "/workspace", head: null, vars, command: "hosted task" })
  const environment = run.vars.flatMap((v) => (v.delivery === "plain" || v.delivery === "placeholder" ? [[v.name, v.value] as const] : []))
  return { run: run.run, environment, hosts: run.interceptHosts }
}

// One request the task sent to one of the run's hosts, forwarded as it is.
export async function forward(task: MehenClient, run: string, request: Request) {
  const headers: [string, string][] = []
  request.headers.forEach((value, name) => headers.push([name, value]))
  const answer = await task.relayStream({ run, method: request.method, url: request.url, headers, body: new Uint8Array(await request.arrayBuffer()) })
  return new Response(answer.body, { status: answer.status, headers: answer.headers })
}
```

`relayStream` hands the upstream's body over unread, so a long answer streams through; its timeout covers the body too. While the run lives its placeholders are a capability: anything that holds one can have the vault use the secret at the item's hosts through that run, so keep them inside the task. Only the workload that created a run may use, renew or end it; the device's own key cannot, and ends it by revoking the workload.

## Drawing cards from asks

A harness that shows the human a card for a link should build it from the `ask` object ([The ask object](../reference/ask.md)): show `check.value` in full, count down from `expiresAt`, name the workspace from `context` when the human is in more than one, and offer one action, opening the link. Nothing a harness sends can approve anything. Draw a card only for an ask your own authenticated call raised, after checking its origin and workspace, never for a link that arrived as text.

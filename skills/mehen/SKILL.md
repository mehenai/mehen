---
name: mehen
description: >
  Use Mehen (the `mehen` CLI and `mehen mcp` tools) whenever a task touches credentials:
  API keys, tokens, passwords, secrets, environment variables, .env files, OAuth connections
  ("connect my Gmail", "manage my email", "link GitHub"), calling an authenticated API, setting
  up env vars in a coding project or worktree, a human offering or pasting a key, or enrolling
  this machine in a Mehen workspace or connecting it to another one. Use credentials without
  reading them: never ask for, read, repeat or store a secret value.
---

# Mehen

Credentials live in a **workspace** in a vault. You use them by name through the `mehen mcp` tools or the `mehen` CLI, and never read, print or store a value. With the CLI, pass `--json` and read it. If `MEHEN_SESSION` is already set in your environment, leave it: your harness chose the label the human sees. Otherwise prefix each command with `MEHEN_SESSION=<label>`, a short label for this conversation.

Not set up (no `mehen`, or no workspace with `state: "active"`)? Follow https://docs.mehen.dev/setup.md. Never reinstall over an installed `mehen`: `mehen update --json` updates it.

## The six tools

| Tool | CLI | Use it to |
| --- | --- | --- |
| `vault_status` | `mehen status` | See every workspace this machine may use. Call it first; usable means `state: "active"` and `check.ok: true`. |
| `vault_list` | `mehen ls` | Find the credential. Always name its slug; if two could serve, ask the human. |
| `vault_fetch` | `mehen fetch <slug> <METHOD> <url>` | Send one HTTP request; the vault adds the credential. Any upstream status is a success: read `status`. |
| `vault_request` | `mehen request <kind> --name <slug> --reason "<why>"` | Ask the human for a missing credential; `provider` names a template. |
| `vault_wait` | `mehen wait <id> --timeout 60` | Wait for the human to finish an ask. |
| `vault_env` | `mehen env check` | See how a checkout's `mehen.toml` variables resolve, then `mehen run -- <cmd>`. |

With several workspaces, pass `workspace` (`--workspace <slug>`) unless the checkout's `mehen.toml` decides; never pick one for the human. When `scope.privateCredentials` is false, never rely on the private default: pass `home` as `project` or `workspace`. Never set auth headers or put a key, token or placeholder in a URL or body: the vault injects the credential. No MCP tool starts an enrolment, approves, revokes or freezes. `vault_wait` can finish an enrolment already started at the terminal.

## Ask, then wait

When a human must act (a missing credential, an approval, a reconnect), the result carries `ask`. Write this in chat, the same words every time:

```
**Needs you in the vault:** <ask.title> <the name in ask.what>
Open: <ask.url>
The page must show <ask.check, in full>. If it differs, do not approve.
Valid until <ask.expiresAt>. I will wait.
```

Then call `vault_wait` with `ask.id`. A `timeout` (exit 4) means the human has not acted yet: wait again; the link stays the same. After an approval, send exactly the same request again, byte for byte. Never open an `ask.url` yourself, never call a request safe, and never ask for a value in chat: send a `vault_request` link. If a human pastes a secret anyway, do not use or repeat it; say it should be rotated.

## When refused

Every error carries `error`, `message` and `next`. Relay `next.say`, call `next.tool` with `next.arguments`, or run `next.command` (only the CLI runs it; if you cannot, ask the human). Never work around a refusal with another host, item, tool or encoding.

| Exit | Meaning | Do |
| --- | --- | --- |
| 1 | Error | Report it. `cli_outdated`: `mehen update --json`, then retry once. |
| 2 | Usage or selection | Fix the call; a selection refusal sent nothing. |
| 3 | Approval required | Write the block, wait, then repeat the same request. |
| 4 | A human must act | Write the block, then wait. `frozen`: tell the human. |
| 5 | Refused by rule | Do not retry; tell the human what was refused. |
| 6 | Identity | Check `vault_status`. `workload_ended`: stop. |
| 7 | Transient | Retry once, after `retryAfter`. Not `outcome_unknown` or `upstream_failed`: the write may have landed, so check before resending. |

## The rest, on demand

The server lists these six tools by default. The rest come in toolsets the human adds with `mehen setup --toolsets inspect,connect` (`all` for every tool), then a restart. A call to a tool it does not serve is refused `tool_not_served`, naming its toolset and the CLI command that does the same.

Read one topic when you need it, with `mehen guide <topic>` or at https://docs.mehen.dev/guide.md:

- `mehen guide never`: everything you never do with a credential.
- `mehen guide request`: homes, OAuth (`vault_connect`), templates, lease-only kinds.
- `mehen guide approvals`, `mehen guide plan` and `mehen guide asking-less`: approvals, several writes at once, standing rules and task grants; `mehen guide mandates`.
- `mehen guide workspaces` and `mehen guide enrol`: choosing and joining a workspace.
- `mehen guide projects`: `mehen.toml`, `mehen init`, `mehen run`.
- `mehen guide adopt`: keys already on this machine, by name, never by value.
- `mehen guide sandbox`: Codex and other sandboxed shells.
- `mehen guide mcp`: toolsets and what `mehen setup` reports.
- `mehen guide exit-codes` and `mehen guide updating`.

---
title: The guard hooks
question: How do I stop an agent reading .env files or pasting a key into a command, and what does the guard check?
section: guides
covers: both
order: 45
---

# The guard hooks

The vault keeps keys out of an agent's hands when the agent goes through Mehen. The guard hooks cover the other way a key reaches a model: the agent reading a `.env` file, a key file or a CLI's login, or pasting a key it found into a command or a file. Before each tool call, the agent's harness asks `mehen hook` about it. The guard blocks the call, or warns about it, and tells the agent what to use instead.

The guard is not the security boundary: the vault's bindings are. It keeps an agent from handling a key by accident, or because a page or a file told it to, and it reads nothing but the paths and text in the tool call. It needs no vault and no network, so it answers in milliseconds and works with a local vault, another machine's or Cloud.

## Install it

`mehen up` installs it. To install it on its own, or again after you install an agent:

```sh
mehen guard install --dry-run
mehen guard install
```

It needs an installed `mehen`, since the hooks name its path. For each agent it reports `added`, `updated`, `unchanged` or `skipped` with the reason. Restart the agent afterwards (in pi, `/reload` is enough; Cursor picks up its file by itself).

- **Claude Code.** It adds a `PreToolUse` hook for Read, Grep, Glob, Bash, Write, Edit, MultiEdit and NotebookEdit, and a `SessionStart` hook that tells the agent how to use the vault, to `~/.claude/settings.json`. The file is backed up once, to `settings.json.mehen-backup`, before the first change. It is skipped when there is no `~/.claude` folder.
- **pi.** It writes a guard extension into `~/.pi/agent/extensions`, which pi loads by itself. It checks bash, read, grep, find, ls, write and edit. If `mehen hook check` fails, the extension blocks the call rather than let it through unseen; if `mehen` is no longer installed at all, it says so once and stops guarding. It is skipped when there is no `~/.pi` folder, and a file of the same name that `mehen` did not write is left alone.
- **Cursor.** It adds four hooks to `~/.cursor/hooks.json`, each running `mehen hook cursor`: `beforeShellExecution` checks every shell command, `beforeReadFile` every file the agent is about to read, `preToolUse` the Write tool's input, and `sessionStart` tells the agent how to use the vault. The shell, read and write hooks carry `failClosed: true`, so a crash, a timeout or a missing `mehen` blocks the call instead of letting it through. Cursor reloads the file by itself. It is skipped when there is no `~/.cursor` folder.
- **Codex.** It adds a `PreToolUse` hook for `Bash` and `apply_patch` and a `SessionStart` hook to `~/.codex/hooks.json` (`$CODEX_HOME/hooks.json` when `CODEX_HOME` is set), each running `mehen hook codex`. Codex reads files through its shell, so the Bash hook covers reads as well as commands; the `apply_patch` hook checks the lines a patch adds. Codex runs a new or changed hook only after you trust it: open `/hooks` in Codex and trust Mehen's two hooks after the first install, and again whenever `mehen guard install` reports `updated`. It is skipped when there is no `~/.codex` folder.

Each file is backed up once, to `<file>.mehen-backup`, before Mehen first changes it, and written only when something changes, so running the install again reports `unchanged`. A hook is Mehen's only while its command is exactly what the install writes: the absolute path to `mehen`, quoted as the install quotes it, then `hook <harness>`. Anything else is yours and is never touched, including a command that merely ends that way (`/bin/echo /opt/mehen hook cursor`), wraps it (`env ... mehen hook cursor`), adds arguments or adds a shell operator. In Cursor's and Codex's `hooks.json`, only Mehen's entries are edited in the text, so your comments, spacing and order stay as you wrote them. A file that does not parse, a `hooks` that is not an object, an event that is not a list, or a Cursor `version` that is not a positive integer is reported with the reason and left byte for byte as it is. A file that changes while the install or removal runs is left as you changed it, and reported. Two `mehen guard install` or `remove` runs at once take turns, through a lock in the Mehen home.

`mehen guard remove` takes out only what `mehen guard install` wrote. A `hooks.json` that Mehen created is recorded beside it, in `hooks.json.mehen-created`, and only that record lets the removal delete the file, once nothing of yours is in it. A file you had before keeps everything but Mehen's entries, and a file with no Mehen hook in it is never changed.

`mehen doctor` has a `guard` row for each of these agents set up on the machine: on, missing, out of date (it names another path to `mehen`), or off because of the level. `mehen up` says the same for each agent it wires: `guard on`, `guard installed, warn only`, `guard installed, guard off`, or why the guard is not on.

## What it stops

**Reading a file that holds keys**, with the agent's read tools or with a shell command that reads its arguments (`cat`, `grep`, `head`, `sed`, `cp`, `curl`, `git`, a `<` redirect and others):

- environment files: `.env`, `.env.*`, `*.env`, `.dev.vars` and `.envrc`, but not examples such as `.env.example`;
- anything in a `.local-secrets` folder;
- key and certificate stores (`.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.keystore`, `.ppk`, `.kdbx`) and SSH private keys (`id_ed25519` and the like; a `.pub` is fine);
- `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `.pgpass` and `.my.cnf`;
- CLI logins: `gh`, kubeconfig, talosconfig, the gcloud application default credentials, the Cloudflare command line's and Docker's;
- anything under `~/.aws`, `~/.ssh`, `~/.gnupg`, Mehen's own `~/.config/mehen`, and the local vault's data folder.

The shell check looks past the usual wrappers (`command`, `builtin`, `env` with or without variables, `exec`, `nohup`, `time`, `sudo`, `xargs`, and `NAME=value` in front of a command), reads `$HOME`, `${HOME}` and `~` as your home folder without running the shell, follows a `cd` earlier in the same line for later relative paths, and judges a link that exists by what it points at; `ln` making a link to a key file is stopped too. `grep -r` walks the folders it would search, up to 16 folders deep and 10,000 entries, and is stopped if it would reach a key file that its own `--exclude`, `--exclude-dir` or `--include` does not leave out. A search wider than that is stopped with a reason that says to narrow it, since the guard cannot tell what is in it.

**Putting a key into a command or a file:** a command, or a write or edit, that carries a PEM private key, a URL with a password in it, or a token that starts like a provider key (`sk-`, `ghp_` and the others Mehen knows) followed by a random-looking tail. Mehen's own placeholders are not keys and pass.

A blocked agent reads a reason that says what to use instead: `mehen ls` to list keys, `mehen fetch` or `vault_fetch` to make the call, `mehen run` to give a program its variables, `mehen request` to ask you for a key it does not have. You see a short card saying what was blocked.

## Choose what it does

```sh
mehen guard
mehen guard warn
mehen guard block
mehen guard off
```

`block`, the default, stops the call. `warn` lets it through and shows you the card. `off` says nothing. The level is kept in `guard.json` in the Mehen home; `MEHEN_GUARD=warn` (or `block`, `off`) overrides it for one process. `mehen guard` with no argument prints the level in force.

## Keep the agent's shell out of the vault, too

With a vault on the same machine, a program running as you can read the vault's files, and so can an agent's shell. The guard stops an agent's tools reading the data folder, but it reads command lines, which a determined program can disguise. Claude Code's sandbox closes that gap at the operating system's level: turn it on (`/sandbox` in Claude Code), then run `mehen guard install` again. With the sandbox on, the install also adds the vault's data folder to the sandbox's `denyRead` and `denyWrite` lists, so the agent's shell can neither read nor change the vault's files. Claude Code runs its MCP servers and hooks outside the sandbox, so `mehen mcp` and `mehen hook` still reach the vault. The install only touches a sandbox you have turned on, and `mehen guard remove` takes those paths out again. [The threat model](../security/threat-model.md#a-vault-on-your-own-machine) has the rest.

## What each agent enforces

The rules are the same everywhere; what reaches them depends on the hooks each agent offers.

| | Claude Code | pi | Cursor | Codex |
| --- | --- | --- | --- | --- |
| Shell commands | Bash | bash | every command (`beforeShellExecution`) | Bash and `exec_command` |
| The agent's file reads | Read, and Grep and Glob with a path | read, grep, find, ls | every agent read (`beforeReadFile`) | through the shell; Codex's only other file reader is `view_image`, for images |
| Keys written to files | Write, Edit, MultiEdit, NotebookEdit | write, edit | Write (`preToolUse`) | `apply_patch`, the lines it adds |
| When the check cannot answer | goes through, except input `mehen` cannot read (exit 2) | blocked | blocked (`failClosed`) | blocked when `mehen` answers with an error (exit 2); goes through when `mehen` cannot start at all or times out |
| Warn | a card | a notice | allowed; Cursor documents `user_message` for denials, so the card may not show | a `systemMessage` warning |

What is not checked:

- **Cursor.** Its Grep tool and its other tools, and MCP calls: the docs do not describe the input of Read, Grep or Write in `preToolUse`, so the Write check looks for a key in every string of the tool's input and names no file. A denied read shows you the card; Cursor's `beforeReadFile` answer has no field for a message to the agent, so the agent learns what to use instead from the session note. Mehen's hooks are user hooks, in `~/.cursor/hooks.json`, and user hooks do not run in Cursor's cloud agents: those run a project's own `.cursor/hooks.json` and, on Enterprise plans, team and enterprise-managed hooks.
- **Codex.** Input typed into a command that is already running: Codex sends it with `write_stdin`, which does not run `PreToolUse` again, so `cat .env` typed into an interactive shell the agent started is not seen. MCP tools and Codex's other local function tools: Codex runs hooks for them, but Mehen's matcher (`Bash|apply_patch`) leaves them out. Only hosted tools, such as web search, do not go through Codex's local hooks at all. Codex's own docs call tool hooks "a useful guardrail, not a complete enforcement boundary". A hook you have not trusted in `/hooks` does not run at all, and an enterprise `allow_managed_hooks_only = true` skips it too. If the `config.toml` beside `hooks.json` also declares `[hooks]`, Codex loads both and warns at startup; the install says so.

Cursor also loads Claude Code's hooks from `~/.claude/settings.json` while its "Include Third-Party Plugins, Skills, and Other Configs" setting is on, which it is by default. Mehen's Claude Code hooks then run in Cursor beside its Cursor hooks; a denial from either blocks the call.

With Cursor's hooks failing closed, uninstall in order: run `mehen guard remove` before you delete the `mehen` binary, or Cursor blocks every shell command, read and write until you take Mehen's entries out of `~/.cursor/hooks.json` by hand.

## Another harness

`mehen hook check` takes one JSON object on stdin, `{ "tool": "read" | "write" | "shell", "path", "content", "command", "cwd" }`, and prints `{ decision, reason, card, findings }`, where `decision` is `deny`, `warn` or `allow`. A harness with a pre-tool hook of its own can call it and block on `deny`. `mehen hook claude-code`, `mehen hook cursor` and `mehen hook codex` are the same check in each of those agents' hook shapes.

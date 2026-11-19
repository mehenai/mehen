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

It needs an installed `mehen`, since the hooks name its path. For each agent it reports `added`, `updated`, `unchanged` or `skipped` with the reason. Restart the agent afterwards (in pi, `/reload` is enough).

- **Claude Code.** It adds a `PreToolUse` hook for Read, Grep, Glob, Bash, Write, Edit, MultiEdit and NotebookEdit, and a `SessionStart` hook that tells the agent how to use the vault, to `~/.claude/settings.json`. The file is backed up once, to `settings.json.mehen-backup`, before the first change. It is skipped when there is no `~/.claude` folder.
- **pi.** It writes a guard extension into `~/.pi/agent/extensions`, which pi loads by itself. It checks bash, read, grep, find, ls, write and edit. If `mehen hook check` fails, the extension blocks the call rather than let it through unseen; if `mehen` is no longer installed at all, it says so once and stops guarding. It is skipped when there is no `~/.pi` folder, and a file of the same name that `mehen` did not write is left alone.

`mehen guard remove` takes out only what `mehen guard install` wrote.

## What it stops

**Reading a file that holds keys**, with the agent's read tools or with a shell command that reads its arguments (`cat`, `grep`, `head`, `sed`, `cp`, `curl`, `git`, a `<` redirect and others):

- environment files: `.env`, `.env.*`, `*.env`, `.dev.vars` and `.envrc`, but not examples such as `.env.example`;
- anything in a `.local-secrets` folder;
- key and certificate stores (`.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.keystore`, `.ppk`, `.kdbx`) and SSH private keys (`id_ed25519` and the like; a `.pub` is fine);
- `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `.pgpass` and `.my.cnf`;
- CLI logins: `gh`, kubeconfig, talosconfig, the gcloud application default credentials, the Cloudflare command line's and Docker's;
- anything under `~/.aws`, `~/.ssh`, `~/.gnupg`, Mehen's own `~/.config/mehen`, and the local vault's data folder.

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

## Another harness

`mehen hook check` takes one JSON object on stdin, `{ "tool": "read" | "write" | "shell", "path", "content", "command", "cwd" }`, and prints `{ decision, reason, card, findings }`, where `decision` is `deny`, `warn` or `allow`. A harness with a pre-tool hook of its own can call it and block on `deny`. `mehen hook claude-code` is the same check in Claude Code's hook shape.

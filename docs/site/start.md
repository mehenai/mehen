---
title: Run Mehen on your machine
question: How do I set up Mehen on my own machine, in one command?
section: start
covers: local
order: 10
---

# Run Mehen on your machine

Mehen is open source and runs on your own machine. One command installs it, starts a vault here, makes your passkey, enrols this machine and wires your agents. From then on an agent uses your API keys without ever receiving them.

```sh
curl -fsSL https://mehen.dev/install | sh && mehen up
```

With Node.js, the same in one command:

```sh
npx @mehenai/cli up
```

or `npm create mehen`. Both run the same installer the first time, then `mehen up`; from then on `mehen` updates itself from signed releases, however it was installed.

You need macOS, or Linux with glibc (WSL included), on arm64 or x64. Windows is not supported yet. The installer checks the binary's SHA-256 and puts `mehen` in `~/.local/bin`. Mehen is not on Homebrew, and the npm package called `mehen` is an unrelated tool: Mehen's are `@mehenai/cli` and `create-mehen`.

Would you rather your agent ran it? [Let your agent do it](#let-your-agent-do-it).

## What `mehen up` does

### 1. It starts the vault

The vault runs on this machine at `http://localhost:7787`, bound to the loopback address, so nothing else on your network reaches it. It answers only requests addressed to `localhost:7787` or `127.0.0.1:7787`, which stops a web page from pointing a name of its own at it.

`mehen up` installs it as a service that starts again when you log in and restarts it if it stops: a LaunchAgent (`dev.mehen.vault`) on macOS, a systemd user unit (`mehen-vault.service`) on Linux. Where neither is available, in a container for example, the vault runs as a background process until the machine restarts, and `mehen up` says so; run it again after a restart.

Its data folder is `~/Library/Application Support/Mehen/vault` on macOS and `~/.local/share/mehen/vault` on Linux (under `$XDG_DATA_HOME` when that is set). It holds the vault's database, its keys and its log, `serve.log`. `mehen up` makes the folder open to you alone, and refuses one that another user owns, can open, or can replace through a folder above it. `--port` and `--data` choose another port or folder.

### 2. It opens a page for your passkey

`mehen up` opens `http://localhost:7787/signup#<code>` in your browser. The code lets the first person sign up to this vault, and it is gone once your account exists. On the page you:

- choose a name and make a passkey: Touch ID, your phone, a security key, whatever your browser offers. There is no password.
- save the recovery codes it gives you. They are the way back in if you lose the passkey.
- create your workspace, with a name and a slug.

The terminal waits while you do this, for up to 15 minutes (`--timeout <seconds>` changes that), and carries on by itself. On a machine with no display, no browser opens: open the link it prints.

Over SSH, the link is on the other machine's loopback, so your own browser cannot open it directly. `mehen up` sees the SSH session and prints the tunnel to run on your own computer, such as `ssh -L 7787:localhost:7787 devbox`; with it running, open the link in your browser as printed. The passkey you make belongs to `localhost`, so approve through the same tunnel later. Keep the same port at both ends, since the vault answers only requests addressed to its own port; if your own computer already runs a Mehen vault on 7787, give this one another with `mehen up --port <port>`.

### 3. It enrols this machine

It enrols this machine in your new workspace, named after its host name, and opens the machine's page. The terminal shows the machine's fingerprint, four groups of four characters. The page shows three of the groups and hides one: check that the three match, type the hidden one from the terminal, and accept with your passkey. `mehen pending` shows the fingerprint again if you need it.

### 4. It wires your agents

It registers Mehen with every agent it finds on this machine: an MCP server called `mehen` and the Mehen skill, in Claude Code, Codex, Cursor, pi, Gemini CLI, OpenCode, VS Code and Claude Desktop ([Register mehen with each agent](guides/harnesses.md)). Then it installs the guard hooks in Claude Code, pi, Cursor and Codex, which check for `.env` and other key files or keys pasted into commands and files, and tell the agent what to use instead ([The guard hooks](guides/guard.md)). On a fresh machine with no saved guard level, `mehen up` starts the guard in `warn` mode so your existing `.env` repos keep working until you move their keys into Mehen; pass `--guard block` to block immediately, or run `mehen guard block` once your keys are in the vault. Restart each agent so it picks Mehen up. In Codex, open `/hooks` and trust Mehen's two hooks; Codex runs a new or changed hook only once you do. `--no-agents` leaves the agents alone.

### 5. It says what is next

It ends with `Done.` and one next step: `mehen adopt scan`, which finds the keys already on this machine.

Run `mehen up` again whenever you like. It finds what is already in place and picks up where it stopped, so an interrupted run, a missed browser tab or a restart is fixed by running it again. With `--json` it writes one JSON object per line (`vault`, `ask`, `workspace`, `machine`, `agents`, then `done`), for a program or an agent to read.

## Move your existing keys in

Your keys are probably in `.env` files, service files and CLI logins today. `mehen adopt scan` finds them, and [Bring a machine's credentials into Mehen](guides/adopt.md) brings them into the vault in one batch you approve with one passkey. For a single key, [Move existing keys in](guides/existing-keys.md) is quicker.

## What your agent does now

Once you restart it, your agent has the `vault_*` tools and the `mehen` command.

- **It needs a key it does not have.** It asks Mehen for an intake link and gives it to you. You type the key into the vault's page, never into the chat, and the agent gets the credential's name back ([Ask a human for a credential](guides/request-a-credential.md)).
- **It calls an API.** It asks Mehen to make the call. The vault adds the key on the way out, only to the hosts the key is bound to, and scrubs it from the response, so the agent sees the result and never the key ([Find a credential and call an API](guides/call-an-api.md)). A program can run under `mehen run` instead, with placeholders in place of the keys ([Project variables with mehen run](guides/projects.md)).
- **A request needs you.** Writes, sends and anything a credential's policy holds wait for your passkey on the vault's page ([When a request needs approval](guides/approvals.md)).

## Let your agent do it

Paste this into your agent. It follows [the setup procedure](setup.md): it installs `mehen` if it is missing, runs `mehen up` and gives you each link to open:

```prompt
Follow https://docs.mehen.dev/setup.md to set up Mehen on this machine. I will make the passkey and accept the machine in my browser; never ask me for a key, password or secret.
```

## Stop it, or take it off

`mehen up --remove` stops the vault and removes its service. The data folder stays, so `mehen up` brings the same vault back. [Remove Mehen from a machine](guides/remove.md) takes everything off.

## Where next

- [Run it on another machine](start/another-machine.md): keep the vault on a machine you own and enrol your laptops in it.
- [Use it with a team](start/team.md): Mehen Cloud, for shared workspaces. Invite only for now.
- [Local or Cloud](start/local-or-cloud.md): where the keys are in each, who can reach them, and how to use both.
- [The threat model on one machine](security/threat-model.md#a-vault-on-your-own-machine): what a vault on your own machine protects, and what it does not.

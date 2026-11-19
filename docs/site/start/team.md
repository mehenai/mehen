---
title: Use it with a team
question: How do I use Mehen Cloud with other people, and connect my agent to a shared workspace?
section: start
covers: cloud
order: 40
---

# Use it with a team

Mehen Cloud, at `https://app.mehen.dev`, is the same vault run for teams: shared workspaces, members with roles (owner, admin, member, guest), teams of members, projects shared with people or teams, and approvals from any device, your phone included. It is invite only for now. To ask for an invitation, write to [hello@mehen.dev](mailto:hello@mehen.dev). If someone has already invited you, read on.

## Before you start

- **An invite.** A workspace owner or admin invites you by email, and the invitation is for that one address. The link asks you to verify exactly that address, with Google or, with no Google account, with a six-digit code Mehen emails to it; neither signs you in. Where the workspace asks for a Google Workspace account for your role, the page offers only Google and says so. You then choose a name (filled in from the Google account when you used one, which you can change) and create a passkey (there is no password). If your passkey syncs through a password manager, such as iCloud Keychain or Google Password Manager, it already gets you back in if you lose this device, and you go straight on. Otherwise you save the recovery codes it gives you somewhere safe, with no second passkey prompt. You are then in the workspace straight away, unless whoever invited you chose to confirm you themselves, or invited you as an owner, in which case an owner or admin confirms your membership first. A guest may instead be invited by a link that names no email, and is always confirmed.
- **The workspace's slug.** It is the `<slug>` in `https://app.mehen.dev/w/<slug>/`. The Connect an agent page prints it.
- **An agent on macOS or Linux.** Claude Code, Codex, Cursor, pi, Gemini CLI, OpenCode, VS Code, Claude Desktop, or another client that runs a stdio MCP server. Setup time depends on your device and any provider set-up.

## 1. Copy the prompt

Once your membership is active, Mehen opens the workspace's **Connect an agent** page for you; later, open the workspace and go to **Connect an agent**. It writes a prompt like this. The Connect an agent page fills in the slug and, when available, a connect code, which routes the machine to your own Needs you. Without a code, your agent gives you the exact enrolment link:

```prompt
Follow https://docs.mehen.dev/setup.md to connect this machine to Mehen workspace <slug> at https://app.mehen.dev. I will approve it in my browser; never ask me for a key, password or secret.
```

## 2. Paste it into your agent

The agent follows [the setup procedure](../setup.md): it installs or updates `mehen`, starts the enrolment, registers Mehen with the agents on the machine and waits for you. It never needs a key, a password or your passkey, and it should never ask for one.

## 3. Approve the machine

The agent gives you a link and a fingerprint, four groups of four characters. Open the link (it is on `https://app.mehen.dev`, under `/w/<slug>/e/`), sign in, and check:

- the page shows three of the four groups, and they match what the agent gave you;
- the machine's name, when and from where it asked, and the scope it will get are what you expect.

If anything differs, do not accept. Otherwise type the hidden group from the agent's message, then check the tick **It may use my private credentials**. With it, your agent can ask for and use credentials only you can see, which is where an ask goes unless it names a project or the workspace. It is on by default for your own machine (off for a guest's). Untick it on a shared or untrusted machine: your agent then asks in a project you can edit instead. Turning it on later is a proposal and an acceptance on the machine's page, two passkey prompts ([privateCredentials](../concepts/machines.md#scope-and-reach)). Then accept with your passkey. A guest's machine also needs admission by someone who manages its projects; a team's machine is admitted by a workspace owner or admin.

## 4. Restart the agent

The agent tells you which agents need a restart so the `vault_*` tools appear. From then on it asks you for credentials through links, and you fill them in on the vault's pages. [Ask a human for a credential](../guides/request-a-credential.md) shows what that looks like from the agent's side. Already have keys in `.env` files? [Move existing keys in](../guides/existing-keys.md), or bring them all in at once with [Bring a machine's credentials into Mehen](../guides/adopt.md).

## If you prefer a terminal

On a machine with no `mehen`:

```sh
curl -fsSL https://mehen.dev/install | sh
mehen enrol --workspace <slug>
mehen wait <enr_id>
mehen setup
mehen guard install
```

`mehen enrol` prints the link and the fingerprint and exits; `mehen wait` finishes once you accept. `mehen guard install` adds the [guard hooks](../guides/guard.md) to Claude Code and pi. [Connect an agent to one workspace](../guides/connect-one-workspace.md) explains each step.

## A local vault and Cloud on one machine

One machine can be enrolled in a vault on your own machine and in Cloud workspaces at the same time: it keeps one key per vault and workspace, and the one `mehen` MCP server serves them all. If you already ran `mehen up`, the steps above add the Cloud workspace beside your local one; nothing is moved or replaced. When more than one workspace could serve a request, the agent names one with `--workspace <slug>` ([Several workspaces on one machine](../guides/several-workspaces.md)). [Local or Cloud](local-or-cloud.md) says what each holds.

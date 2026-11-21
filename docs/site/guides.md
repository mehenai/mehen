---
title: Guides
question: Which guide do I need?
section: guides
covers: both
order: 0
---

# Guides

Each guide answers one question, in the order you would meet it. Setting Mehen up is in [Start here](start.md): [on your machine](start.md) with `mehen up`, [on another machine you own](start/another-machine.md) with `mehen serve`, or [with a team](start/team.md) on Mehen Cloud.

## Connecting

- [Connect an agent to one workspace](guides/connect-one-workspace.md): how do I install or update `mehen`, enrol this machine and register the agents?
- [Several workspaces on one machine](guides/several-workspaces.md): how does one machine serve a personal and a work workspace?
- [A second identity on the same machine](guides/second-identity.md): when and how do I give an agent its own `MEHEN_HOME`?
- [Register mehen with each agent](guides/harnesses.md): how do I add the MCP server and the skill to Claude Code, Codex, Cursor, pi, Gemini CLI, OpenCode, VS Code, Claude Desktop or any MCP client?
- [The guard hooks](guides/guard.md): how do I stop an agent reading .env files or pasting a key into a command, and what does the guard check?

## Using credentials

- [Ask a human for a credential](guides/request-a-credential.md): how does an agent get a new key into the vault without seeing it?
- [Connect Gmail, GitHub or Microsoft](guides/oauth.md): how do OAuth connections work from the agent's side?
- [Find a credential and call an API](guides/call-an-api.md): how does an agent list, check and use a credential?
- [When a request needs approval](guides/approvals.md): what does an agent do with exit 3, and how does it ask for several writes at once?
- [Standing rules](guides/standing-rules.md): how does an agent stop asking for the same request, or the same kind of routine work, every time?
- [Agents that work on their own](guides/unattended-agents.md): how do I let an agent carry on without asking me for every request, and what does it still ask for?
- [Type a credential into a web page](guides/fill.md): how does an agent sign in to a page, or paste a key into a dashboard, without seeing the value?
- [Put a credential into another service](guides/push.md): how does an agent get a secret into GitHub Actions, Vercel or a Cloudflare Worker without seeing the value?
- [Project variables with mehen run](guides/projects.md): how do I give a coding project its variables without a `.env`?
- [Which programs work with mehen run](guides/run-compatibility.md): which runtimes and HTTP clients work with placeholders, which do not, and what do I use instead?
- [Move existing keys in](guides/existing-keys.md): I already have keys and `.env` files; how do I move them into Mehen?
- [Bring a machine's credentials into Mehen](guides/adopt.md): I have `.env` files across my repos and services; how do I bring them all in at once?
- [Back up a machine before adopting](guides/backup.md): how do I keep my own encrypted copy of every file `mehen adopt` reads?

## Running it

- [A CI runner or a shared machine](guides/ci.md): how do I enrol a machine a team owns, and what can it reach?
- [Keep a service running with mehen run](guides/services.md): how do I run a long-lived process under `mehen run` with launchd or systemd, and what do its exit codes mean?
- [A machine or a key is compromised](guides/incident.md): what do I do, in what order?
- [Remove Mehen from a machine](guides/remove.md): how do I take Mehen off a machine, and what does each step undo?

## Building a product on Mehen

- [Build on Mehen](guides/build-on-mehen.md): how do I use Mehen to keep my users' credentials, as a business?

## Adding a service

- [Add a service](guides/add-a-service.md): how do I add a template for a service Mehen does not know yet, or use that service without one?

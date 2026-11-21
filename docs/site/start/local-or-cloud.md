---
title: Local or Cloud
question: Should my keys live on my own machine or in Mehen Cloud, and can I use both?
section: start
covers: both
order: 50
---

# Local or Cloud

The vault is the same engine in every case: the same bindings, policies, approvals, audit chain, `mehen` command and MCP tools. What changes is where it runs, and so where the keys are and who can reach them.

| | On this machine (`mehen up`) | On another machine you own (`mehen serve --origin`) | Mehen Cloud (`https://app.mehen.dev`) |
| --- | --- | --- | --- |
| Where the keys are | In the vault's data folder on this machine, encrypted under a root key kept in the same folder | In the vault's data folder on that machine, the same way | In Mehen Cloud on Cloudflare, each workspace in its own store, encrypted under keys derived from the operator's root key |
| Who can reach the vault | This machine only, at `http://localhost:7787` | Every device that can open its https name: your tailnet or your network | Anyone on the internet; using it needs a member's passkey or an enrolled machine |
| Who could read the stored keys | A program running as you on this machine | A program running as the vault's user on that machine | Whoever can deploy the vault's code, and the host ([the threat model](../security/threat-model.md#whoever-can-deploy-the-vault)) |
| Where you approve | In this machine's browser | On any device that reaches it, your phone included | On any device, your phone included |
| Backups | A daily dump of each workspace in the data folder, on the same disk: copy the folder elsewhere to survive losing it | The same, on that machine | Kept by the operator: daily dumps and 30-day point-in-time recovery |
| Price and availability | Open source, free, available now | Open source, free, available now | Invite only for now: write to [hello@mehen.dev](mailto:hello@mehen.dev) |

## What only Cloud has

- **Other people by email.** Members invited by email, with roles, teams and projects shared with them, and Google identity checks on members. A local vault sends no email and has no Google sign-in, so it cannot verify an email address and refuses an invitation bound to one. It invites by link instead, which is useful on a vault others can reach (`mehen serve --origin`): a guest invitation, with at least one project shared, that anyone with the link may use. An owner or admin confirms whoever joins, and can then change their role.
- **Building a product on Mehen.** Platforms and managed workspaces ([Build on Mehen](../guides/build-on-mehen.md)).

## Using both

One machine can be enrolled in a local vault and in Cloud workspaces at once. It keeps one key per vault and per workspace, so the two never share a key, and the one `mehen` MCP server serves every workspace the machine is in.

- Run `mehen up` for your own keys, then follow [Use it with a team](team.md) to join a Cloud workspace from the same machine, or the other way round.
- `mehen status` lists every workspace this machine may use, with the vault each one is on.
- When more than one workspace could serve a request, name one: `--workspace <slug>` on the command line, the `workspace` argument on a tool. A checkout's `mehen.toml` names its own ([Several workspaces on one machine](../guides/several-workspaces.md)).
- `MEHEN_WORKSPACES` in an agent's entry limits which workspaces that agent may use, for a work agent that should never touch your personal keys ([A second identity on the same machine](../guides/second-identity.md) goes further).

A credential lives in one workspace; nothing copies keys between a local vault and Cloud. To move one, add it again in the other workspace.

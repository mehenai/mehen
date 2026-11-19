---
title: The model in one page
question: What are the pieces, and how do they fit?
section: concepts
covers: both
order: 0
---

# The model in one page

Two ideas run through all of it. **Use credentials without reading them:** a credential lives in the vault, the vault makes the call or hands a program a placeholder, and the credential goes only where a human said it may go. **A machine never does more than the person or team that owns it.**

## The pieces

- **An account** is one human: their passkeys, recovery codes and sessions. It belongs to any number of workspaces.
- **A workspace** is where everything else lives, isolated from every other workspace:
  - **People**: members with a role (owner, admin, member, guest), and **teams** of members.
  - **Credentials**: each one an item with a destination (its binding), rules (its policy) and a home (the workspace, one project, or one member privately).
  - **Machines**: enrolled devices, each owned by a member or a team, each with a scope that can only narrow what its owner may do.
  - **Projects**: coding projects with environments and variables, shared with people or teams at a level.
  - **Asks and approvals**: the links a human opens, and the decisions they sign with a passkey.
  - **Mandates**: what a person lets one of their machines do without asking, within caps, until a date.
  - **The audit chain**: a hash-linked record of what happened.
- **`mehen`** is the command line on each machine, with `mehen mcp` for agents that speak MCP and `mehen run` for project variables.
- **A platform** is a business that serves its own users through Mehen: it creates one **managed workspace** per user, provisions a device per agent, adds keys its users type into its own pages and decides held requests with its own signature, and its users never see Mehen.

A request from an agent goes through the same steps every time: the machine signs it with its own key, the vault checks the machine's owner and scope, the credential's binding and policy, and the environment's protection, then either makes the call, asks a human, or refuses with the next step.

## The concept pages

- [Workspaces and people](concepts/workspaces.md): what is a workspace, and who is in it?
- [Machines](concepts/machines.md): what is a machine, and what may it do?
- [Credentials](concepts/credentials.md): what is a credential, and where may it go?
- [Policy](concepts/policy.md): what decides whether a request goes through?
- [Intakes and connections](concepts/intakes-and-connections.md): how does a credential get into the vault?
- [Approvals](concepts/approvals.md): who approves what, and how?
- [Mandates](concepts/mandates.md): how does a machine carry on without asking, and what stops it?
- [Needs you and asks](concepts/needs-you.md): what is an ask, and where does it show up?
- [Projects, environments and runs](concepts/projects.md): how do projects, environments, variables and `mehen run` work?
- [Audit, review and freeze](concepts/audit.md): what is recorded, and how do I stop things?
- [Platforms and managed workspaces](concepts/platforms.md): how does a business serve its own users through Mehen, and how do the pieces fit?

## The rules

Ten rules shape every page here; [What Mehen protects, and what it does not](security.md#the-rules) lists them.

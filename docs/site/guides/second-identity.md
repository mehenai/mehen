---
title: A second identity on the same machine
question: When and how do I give an agent its own MEHEN_HOME?
section: guides
covers: both
order: 30
---

# A second identity on the same machine

Usually one identity per machine is right: one `MEHEN_HOME`, several workspaces, and `MEHEN_WORKSPACES` limiting which ones each agent may use ([Several workspaces on one machine](several-workspaces.md)).

A **separate identity** is for a work agent and a personal agent that must be different machines to the vault: separate keys, separate enrolments, separate Machines cards. Do it only when the human asks for it.

## What it is, and what it is not

A separate `MEHEN_HOME` selects a separate local identity store. Mehen commands using one home do not discover the other's slots, and the vault sees two machines. This is identity organisation, not isolation from another process running as the same OS user: both homes are files that user can read.

Harness registrations and skills remain per OS user, and installation and update state sits beside the executable, so separate homes do not create separate MCP profiles or separate updater installations.

## How

Prefix every command for the second identity, including setup, with the same absolute home:

```sh
MEHEN_HOME="$HOME/.config/mehen-work" mehen enrol --workspace <slug> --json
MEHEN_HOME="$HOME/.config/mehen-work" mehen wait <enr_id> --json
MEHEN_HOME="$HOME/.config/mehen-work" mehen setup --agent <name> --json
```

That registers a new agent entry for this identity. To switch an existing entry to it instead:

```sh
MEHEN_HOME="$HOME/.config/mehen-work" mehen setup --agent <name> --reset-env --json
```

This replaces that entry's environment, so do it only with the human's agreement, and add `--force` only if the entry is foreign or was edited after setup. One agent entry uses one home: switching it replaces its previous connection rather than adding a second one. Restart that agent and confirm its workspace with the same `MEHEN_HOME`:

```sh
MEHEN_HOME="$HOME/.config/mehen-work" mehen status --json
```

A changed `HOME` without `MEHEN_HOME` is another default home, for the same reason.

## Managed hosts

An agent launcher that pins each agent to one workspace is different: its owner provisions the pinned slot and pin map, and an agent never changes that pin or its launch environment to escape a refusal. A `pin_outdated` or `workspace_mismatch` there means relay `next.say` and stop.

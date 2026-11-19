---
title: A CI runner or a shared machine
question: How do I enrol a machine a team owns, and what can it reach?
section: guides
covers: both
order: 100
---

# A CI runner or a shared machine

A machine that several people drive (a CI runner, a shared agent on a chat platform) should belong to a **team**, not to one person. A team's machine reaches only what the projects shared with the team reference, and never anyone's private credential.

## Enrol it as the team's

```sh
mehen enrol --workspace <slug> --team <team-slug> --name build-box --backend software --json
```

It prints a link that a workspace owner or admin opens and admits with their passkey; nobody accepts a team's machine on their own behalf. CI runners use the `software` key backend. The enrolment keeps its key across attempts, and `mehen wait <enr_id>` finishes it from any shell; `--wait --no-renew` waits without renewing the link in that invocation, and a later `mehen wait` renews normally. There is no unattended enrolment: a human always admits the machine.

## What it can reach

- Only the projects shared with the team, at the level of that share.
- A project's own credentials, by name.
- A workspace credential only through a project environment that references it, named with `mehen fetch --project <prj_id> --env <name>` (MCP `context`), never on its own.
- Never a private credential, and never the private-credentials tick.
- A protected environment only if its scope allows protected environments and an eligible human approves each run.

An owner or admin narrows or widens its scope with a passkey.

## Running jobs

A cron job, a CI step or a shell script runs `mehen fetch` and `mehen run` as an agent does. Most commands take `--json` (not `mehen run`, `mehen env set` or `mehen mcp`), Mehen's own outcomes use [the documented exit codes](../reference/errors.md#exit-codes) (a started `mehen run` returns its child's exit code), and errors are shaped `{ error, message, next, ask?, ... }`. Pass `--no-qr` to the standard commands, or set `MEHEN_QR=0` for every command including `mehen run`, where a QR code in a log would be noise (it is drawn only on a terminal anyway). `mehen wait <id> --json --events` streams `waiting`, `settled` and `error` lines, so a pipeline can show the countdown.

Where an approval is needed (a protected run, a write the policy holds), the job stops with exit 3 and the ask; someone has to relay the link and approve it. Design deployment jobs so that the step that needs approval is small and run on purpose.

## What a shared machine means

A shared machine's capability belongs to everyone who can drive it. Mehen authenticates the machine and caps it at the team's shares, not the person behind the message or the commit, and removing that person from Mehen does not remove their access to the machine. Keep a team machine's shares as narrow as its jobs need.

## Agents on one host with different identities

Where agents on one host must be different machines to the vault, give each its own `MEHEN_HOME` and enrol and register it under that home ([A second identity on the same machine](second-identity.md)). A managed host is different: its owner provisions a pinned slot per agent, and an agent never changes that pin or its launch environment to escape a refusal.

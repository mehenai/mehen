---
title: Remove Mehen from a machine
question: How do I take Mehen off a machine, and what does each step undo?
section: guides
covers: both
order: 115
---

# Remove Mehen from a machine

Removing Mehen from a machine is three separate things: ending its enrolments, unregistering it from the agents, and deleting its files. A machine that also runs a vault has a fourth: [stopping the vault](#a-vault-on-this-machine). Do them in that order, while `mehen` is still installed. Deleting the files alone is not revoking: the machine stays listed, and active, on each workspace's Machines page until someone revokes it there.

## Before you start

- **Programs that get their values from Mehen** (`mehen run`, a service unit or a `mehen.toml` in a repo) stop getting them. Give them their values another way first.
- **Files `mehen adopt retire` moved** are in a quarantine folder under `~/.config/mehen/adopt/`, which step 3 deletes. To put them back where they were, run `mehen adopt unretire --all` first ([Bring a machine's credentials into Mehen](adopt.md#8-retire-when-you-are-sure)).
- **A second identity** (`MEHEN_HOME` set for one agent) is a separate home: run step 1 again with the same `MEHEN_HOME` prefix, and delete that home in step 3. Step 2 needs no repeat: setup writes one `mehen` entry per agent and keeps its record in `~/.config/mehen`, whatever `MEHEN_HOME` is.

## 1. Revoke the machine in each workspace

```sh
mehen workspace list --json
mehen revoke --workspace <slug> --json
```

`mehen revoke` revokes this machine's key in the workspace named and removes that workspace's slot (its key, config and ledger) once the vault confirms. Run it once per workspace: a machine has one key per workspace, and the others stay. A mandate the machine held lapses with it, and its grants and standing rules become unusable.

When the vault cannot be reached, `mehen workspace forget <slug>` retires the slot on this machine only (with `--slot <path>` for a duplicate or unreadable one). The machine then stays listed until its owner, an owner or an admin revokes it on the workspace's Machines page with a passkey; do that too. `mehen workspace forget` also drops an enrolment that was never accepted.

## 2. Unregister it from the agents

```sh
mehen setup --remove --dry-run --json
mehen setup --remove --json
```

It undoes only what `mehen setup` added and still owns: each agent's `mehen` MCP entry, which it puts back as the backup had it (the whole file when nothing else changed), and the Mehen skill once no entry remains. An entry that changed since setup wrote it is left alone with its `reason`; read each agent's `mcp`, `skill` and `reason`, and remove those by hand. Restart or reload each agent afterwards. [Register mehen with each agent](harnesses.md) lists the files.

## 3. Delete the files

- **The state:** `~/.config/mehen`, and each `MEHEN_HOME` a second identity used. Each holds its workspaces' slots with the machine's key (a Secure Enclave key is a blob only this Mac's enclave can use), the ledger of asks, the run log and what `mehen adopt` keeps. Setup's record, `setup-state.json`, is always in `~/.config/mehen`, whatever `MEHEN_HOME` is. Apart from files `mehen adopt retire` quarantined, which are your own `.env` files, none holds a credential's value.
- **The binary:** the `path` the installer printed, by default `~/.local/bin/mehen`, and the `.mehen.` files beside it (`.mehen.env`, `.mehen.sha256`, `.mehen.previous`, `.mehen.previous.json` and the update files `.mehen.update.json`, `.mehen.update.lock` and `.mehen.update.log`).
- **The shell line:** the installer added one line ending `# mehen`, which reads `.mehen.env`, to `~/.zshenv` (zsh), or to `~/.bashrc` and your login file (bash). Delete that line.

A repo's `mehen.toml` holds references and names, never a value; keep it or delete it.

## A vault on this machine

If `mehen up` started a vault here, take the guard hooks out and stop the vault too, before step 3:

```sh
mehen guard remove --json
mehen up --remove --json
```

`mehen guard remove` takes out only the hooks and sandbox paths `mehen guard install` wrote. `mehen up --remove` stops the vault and removes its LaunchAgent or systemd unit. Neither deletes the vault's data folder (`~/Library/Application Support/Mehen/vault` on macOS, `~/.local/share/mehen/vault` on Linux), which holds every credential stored there, its root key and its daily dumps. Keep it if you might start the vault again, or move the credentials to another workspace first; deleting it deletes them for good.

## What stays in the vault

Removing the machine removes nothing from any workspace: credentials, projects, the audit chain and the machine's history stay. A credential the machine leased reached it, so rotate it if the machine is going somewhere you do not trust ([A machine or a key is compromised](incident.md)).

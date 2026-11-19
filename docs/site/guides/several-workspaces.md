---
title: Several workspaces on one machine
question: How does one machine serve a personal and a work workspace?
section: guides
covers: both
order: 20
---

# Several workspaces on one machine

One computer can be in your personal workspace and your work workspace at once. Each enrolment is a separate device with its own key and scope, kept in its own slot under the same `MEHEN_HOME`, and nothing crosses between them.

## Add another workspace

Repeat the enrolment with the other slug, then confirm it:

```sh
mehen enrol --workspace acme-personal --json
# relay the ask, then:
mehen wait <enr_id> --json
mehen status --workspace acme-personal --json
```

No second MCP server is needed and nothing is moved, revoked or deleted: the one `mehen` server serves every workspace its entry allows, including one enrolled while it runs. `mehen status --json` lists them all when neither `--workspace` nor `MEHEN_WORKSPACE` selects one.

The workspaces can be on different vaults: a vault on this machine from `mehen up`, one you run on another machine, and Mehen Cloud. A new enrolment goes to Mehen Cloud unless `MEHEN_VAULT_URL` names another vault, for example `MEHEN_VAULT_URL=https://vault.example.com mehen enrol --workspace home --json`; once enrolled, the machine remembers each workspace's vault. The machine keeps one key per vault and workspace, so nothing is shared between them ([Local or Cloud](../start/local-or-cloud.md)).

## Which workspace acts

Every command picks a workspace before it signs or sends anything ([Machines](../concepts/machines.md#workspaces-on-a-machine) has the full rules):

- `--workspace <slug or id>` on the command line, or the `workspace` argument on an MCP tool;
- otherwise `MEHEN_WORKSPACE`;
- otherwise the checkout's `mehen.toml` (`workspace` and `vault`);
- otherwise the only workspace there is.

There is no default workspace. With several and nothing deciding, a command that needs one is `context_ambiguous`, and `next.say` lists the choices. Name the workspace; never pick one on the human's behalf. `mehen status`, `mehen doctor`, `mehen ls`, `mehen pending` and `mehen workspace list` cover every workspace instead, and `mehen wait` finds its id wherever it is. A slug is unique only within its workspace, so pass `--workspace` on single-item commands when results span more than one.

A checkout whose `mehen.toml` names no workspace, on a machine enrolled in several, is `workspace_unbound`: run `mehen workspace bind` in it, which writes the one enrolled workspace that holds the project and refuses when none or several do.

## Some agents limited to some workspaces

`MEHEN_WORKSPACES` is the set of workspaces a process may use: comma-separated slugs, `tn_` ids or `<vault>/<slug>`. It only narrows; anything outside is `workspace_not_allowed` (exit 2), and nothing inside a process widens it. An allowed workspace not joined yet shows as `absent` with the enrolment to run.

With the human's agreement, rebuild one agent's entry with a narrower limit:

```sh
mehen setup --workspaces acme --agent claude-code --reset-env --json
```

Inspect the report and restart that agent. Setup can only narrow what the current shell may use, and it writes the shell's own limit into every entry it adds, so a restricted shell never writes an unrestricted server. Only the human, through the harness, widens a limit.

The limit is an accident control, not an identity boundary: an environment variable can be edited. For two agents that must be different machines to the vault, see [A second identity on the same machine](second-identity.md).

## Managing the slots

```sh
mehen workspace list           # every workspace on this machine, without the network
mehen workspace list --check   # and ask each vault whether the enrolment still works
mehen workspace show           # which workspace this directory selects, and why
mehen workspace forget acme    # retire one on this machine only
```

`forget` retires one slot on this machine only, without the vault; the device stays on the Machines page until someone revokes it there. `mehen revoke --workspace <slug>` revokes the device with the vault and then removes the slot; the machine's other workspaces' keys stay.

After a workspace is renamed, `mehen status` reports the new slug but does not record it; `mehen workspace list --check --json` and a successful `vault_status` record the new slug and name for the slot. Restart the agent before handing over further links, and never forward a link under an old slug.

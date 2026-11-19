---
title: mehen.toml
question: What goes in the project manifest?
section: reference
covers: both
order: 60
---

# mehen.toml

The project manifest, committed at the repo root. It holds names and ids, never a secret.

```toml
# Mehen project manifest. No secrets, ever.
project = "prj_3kQ9..."
workspace = "tn_aeAL..."       # the workspace id; selects a workspace, grants nothing
vault = "https://app.mehen.dev"
default_env = "dev"            # a protected environment can never be the default

[vars]
OPENAI_API_KEY = "vault"       # comes from the vault; delivery decided by the vault
LOG_LEVEL = "info"             # plain, committed, not secret
```

| Key | Meaning |
| --- | --- |
| `project` | The project id (`prj_...`). Required. |
| `workspace` | The workspace id (`tn_...`) the project lives in. It selects which of this machine's enrolments acts; it grants nothing. |
| `vault` | The vault's origin. Together with `workspace` it picks the enrolment. |
| `default_env` | The environment used when there is no `--env` and no `MEHEN_ENV`. Never a protected one. |
| `[vars]` | One line per variable: `"vault"` for one the vault delivers, or a plain non-secret value committed as is. |

## Rules

- **It expresses intent only.** Which environments are protected, which credentials back which variables, who the project is shared with and how each variable is delivered live in the vault. Editing the manifest widens nothing.
- **How it is found.** `mehen` walks up from the current directory to the nearest `mehen.toml`, stopping at the git worktree root; outside a repo it looks only in the current directory. No manifest, no project.
- **Workspace selection.** A manifest without `workspace` keeps working on a machine enrolled in one workspace; with several, it is `workspace_unbound` until `mehen workspace bind` writes `workspace` and `vault`. A manifest naming a workspace this machine is not enrolled in is `workspace_unknown`; one that disagrees with `--workspace`, `MEHEN_WORKSPACE` or `MEHEN_VAULT_URL` is `workspace_mismatch`.
- **The remote.** Every run sends the checkout's normalised `origin` remote with the project id, and the vault refuses with `remote_mismatch` unless that remote is bound to the project.
- **Who writes it.** `mehen init` writes a new one, with the `[vars]` entries as commented examples to fill in; in a checkout whose remote is already a project this machine may use, it names that project and declares every variable the project defines as `"vault"`. `mehen workspace bind` fills `workspace` and `vault` into an existing one. `mehen env set` changes the vault's side of a variable, not the file.

[Project variables with mehen run](../guides/projects.md) is the walkthrough; [Projects, environments and runs](../concepts/projects.md) is the model.

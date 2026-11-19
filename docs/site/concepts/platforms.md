---
title: Platforms and managed workspaces
question: How does a business serve its own users through Mehen, and how do the pieces fit?
section: concepts
covers: cloud
order: 100
---

# Platforms and managed workspaces

A **platform** is a business that builds its own product on Mehen. Its users never meet Mehen: they sign in to the platform, type their keys into the platform's pages and connect their accounts from there, and the platform's agents use those credentials through Mehen without ever reading them. Mehen keeps each user's credentials in a **managed workspace** of their own, which the platform creates and runs on that user's behalf.

Everything on the rest of these pages still holds inside a managed workspace: a credential has a destination and a policy, an agent's machine acts through short-lived workloads, a held request waits for a decision, and every action is in a hash-linked audit. What changes is who stands where a person with a passkey would: the platform, signing with its own key.

## The ladder

```text
Platform              a business registered with Mehen, holding its own key
  Managed workspace     one per user of the platform, kept apart like any workspace
    (its subject)       the platform's own name for that user
    Device              one per agent the platform runs, provisioned by the platform
      Workload          one per task: a grant, a computer; a key whose scope only narrows
        Run             a project's environment for one task, with placeholders
```

- **The platform** is registered by Mehen's operator with the public half of its key. It has a status, limits and defaults, and sees only its own workspaces.
- **A managed workspace** holds one user's credentials, projects, approvals and audit, under its own encryption key, in its own store. Nothing in it is shared with any other workspace.
- **The subject** is the platform's opaque name for that user. Mehen never interprets it.
- **A device** stands for one of the platform's agents. The platform provisions it with the agent's public key; no page asks anyone to accept it.
- **A workload** is a task's own key, made by the device for one grant or one computer, with a scope that can only narrow the device's ([Workloads](machines.md#workloads)).
- **A run** gives one task a project's environment: plain settings as they are, and a placeholder for each key that only Mehen turns back into the key on its way to the key's own host ([Runs](projects.md#runs)).

Nothing crosses a workspace sideways. A device, a workload, a credential, a project, an approval or an audit row belongs to exactly one workspace; only the platform's own limits and defaults come down from above, read-only.

## The words

- **Platform**: a business the operator registered, with an id (`plt_...`), a short name, a display name, a status, limits and defaults.
- **Platform key**: a P-256 key the platform holds. The operator registers its public half and gives it an id (`pky_...`). A platform may have two at once while it rotates.
- **Platform proof**: the platform's signature over one request, in the `Mehen-Platform-Proof` header ([Keys, proofs and signing](../security/keys-and-signing.md#platform-proofs)).
- **Subject**: the platform's name for one of its users, 8 to 128 letters, digits, `_` or `-`, unique within its platform only.
- **Managed workspace**: the one workspace for one subject of one platform. Its single member stands for the subject; nobody signs in as it.
- **Device**: an agent's key, provisioned by the platform, limited to relaying and placeholders, acting only through workloads ([Machines](machines.md)).
- **Workload** and **run**: as everywhere in Mehen.
- **Defaults**: what the platform sets once for all of its workspaces: which services its users may add, OAuth scopes asked by default, tags for new credentials, extra rules that make policies stricter, and whether keys with no template may be read without a hold.
- **Decision**: the platform's approval or denial of one held request, bound to that request's digest, for one use.
- **Operator**: whoever runs Mehen itself. The operator registers, suspends, retires and removes platforms, from their own machine or the operator console in Mehen's web app, and never acts inside a managed workspace.
- **Platform admin**: a person at the platform with a Mehen account and passkey, whom the operator added to the platform. An admin manages that one platform in Mehen's web app ([Platform admins](#platform-admins)).

## Beside people's workspaces

| In a workspace people share | In a managed workspace |
| --- | --- |
| an account and its passkeys | none: the platform's own sign-in stands for its user |
| a workspace an invited account creates | a workspace the platform creates for one subject |
| members with roles | one member that stands for the subject; nobody signs in as it |
| a machine enrolled through a page its owner accepts with a passkey | a device the platform provisions, for relay and placeholders, acting only through workloads |
| workloads and runs | the same, unchanged |
| credentials added on Mehen's intake page | credentials typed into the platform's own page, sealed in the user's browser |
| connections through Mehen's pages, with an OAuth app in the workspace | connections through the platform's page and callback, with the user's own OAuth app in their workspace |
| approvals on Mehen's page with a passkey | decisions by the platform, bound to the request's digest, one use |
| a policy per credential, changed by a person with a passkey | the catalogue's policy, plus the platform's defaults, which only make it stricter; never changed per credential |
| Needs you, notices, Mehen's pages | none |
| the audit, read by members | the audit, read by the platform; every row names it |
| freeze by anyone, unfreeze by an owner | freeze by the platform or a device, unfreeze by the platform |

Two rules make a managed workspace safe to hand to a platform. **A credential's destination is fixed**: its binding, how it is sent and its ceiling never change once it is stored, so using a credential can never become reading it. **A managed device never leases, mints, signs or reveals**, so no value ever leaves the vault through one.

## What the umbrella gives

1. **Ownership and reach.** Every managed workspace belongs to one platform from the moment it is made, and is reached only through that platform: by its proofs naming the subject, and by the devices and workloads it provisioned there. Another platform naming the same subject reaches its own workspace or none, and every miss answers `not_found`, exactly as if nothing were there. No account, page or invitation can name a managed workspace, and Mehen's own people never see one.
2. **Inherited settings.** The platform's limits and defaults are set once, at the platform, and every workspace beneath it reads them live, never a copy. A change reaches every workspace within 30 seconds, with no call to each one.
3. **Platform-wide controls.** Suspension, limits, key rotation, and deleting one user or every user act at the platform, across all of its workspaces at once.
4. **The operator's view.** The operator sees one platform, from their own machine or in the web app's operator console: its status, its keys' public halves, its limits, its subjects with each workspace's status and dates, and the last day's activity in counts (devices made, credentials added and deleted, decisions, refusals). No operator command shows what is in a workspace or acts in one; what whoever runs Mehen could see of any workspace's storage, ciphertext and metadata but no value without a root key, is in [the threat model](../security/threat-model.md#the-operator).
5. **An audit that names the platform.** Every row in a managed workspace names its platform, whoever caused it: the platform, a device, a workload or the vault itself. The chain's first link binds the platform and the workspace, so a chain copied from one workspace can never pass for another's.

## Platform admins

A platform can have admins: Mehen accounts the operator adds to it, and removes, with a passkey each time. An admin has a Platforms area in Mehen's web app that lists only the platforms they administer, and for each one shows its status and limits, its subjects counted by status, the last day's usage, its events, its keys and its defaults. With their own passkey for each change, an admin edits the defaults (with the same rules as the platform's own), adds a key with an overlap, revokes a key but never the last live one, and deletes one subject by the name the platform knows. Each change is recorded in the platform's events with the admin's account.

An admin never registers, suspends, resumes, retires or removes the platform, changes its limits or adds admins; those stay the operator's. Like the operator, an admin never sees or acts inside a managed workspace through the web app. A key the operator or an admin adds is the platform, though: until it is revoked, whoever holds its private half can do everything the platform can in every one of its users' workspaces, so adding one needs the slug typed back and tells the operator and the platform's other admins. [Build on Mehen](../guides/build-on-mehen.md#your-platform-in-mehens-web-app) is the platform's view of it, and [the threat model](../security/threat-model.md#a-platform-admin) says what a stolen admin account can do.

## Removing a platform

The operator can remove a platform so that it can be registered again from scratch. It is retired at once; every subject's workspace is deleted and then purged through the same lifecycle as any deleted subject, without waiting for the audit retention, since no one can read that audit once the platform's keys are revoked; then its slug is free. The cron runs every 15 minutes and deletes and purges up to 50 subjects a run, so a platform with 50 subjects or fewer has its slug free after two runs, within 30 minutes. What stays is the record: the platform's registration under a reserved name with the slug it had, its keys' public halves (revoked), its events, and for each subject only the hash of its name and its audit chain's last link.

## Why each user has a workspace of their own

One shared workspace holding every user's credentials would be simpler to picture and worse in every way that matters:

- **A small blast radius.** Each workspace has its own encryption key and its own store. A wrong scope, a bug or a stolen device key reaches one user, never all of them.
- **Clean deletion.** When a user leaves, their workspace is erased as a whole. In a shared one, their audit rows would sit in a chain with everyone else's, so erasing them would break it and keeping them would keep their history.
- **No neighbours.** Names, freezes, limits and audits are per workspace, so one user's incident never stops another user, and nobody can learn that another user's credential exists.
- **Load and failure.** Each workspace handles its own requests, so one busy user never queues behind another.

## What a platform's users see

Their platform: its pages, its name and its cards. When they connect Gmail or GitHub they see their own OAuth app at the provider, the one they made with the platform's guidance, never a Mehen screen or link. Mehen does not yet offer apps the platform itself owns at a provider; every connection is through the user's own app. What a platform tells its users about Mehen is its own business; Mehen asks nothing of them.

## Where next

- [Build on Mehen](../guides/build-on-mehen.md): the platform's guide, from onboarding to deleting a user.
- [Platform API](../reference/platform.md): every route, its body, its answer and its refusals.
- [Threat model: a platform](../security/threat-model.md#a-platform): what a platform can and cannot do, and what it can do if it turns hostile.

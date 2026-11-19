---
title: Workspaces and people
question: What is a workspace, and who is in it?
section: concepts
covers: both
order: 10
---

# Workspaces and people

## Accounts

An **account** is one human: their passkeys, recovery codes, web and app sessions, linked identities (Google, see [the identity gate](#the-identity-gate)) and a security epoch. Accounts are created by invitation only; the deployment's operator issues the first invite. On a vault you run yourself, that first invite is the one-time sign-up code `mehen up` opens for you. Recovery (a recovery code, an older passkey, or the operator's break-glass procedure when every factor is lost) is an account matter: no workspace role can reset another person's factors. Before an account joins or creates a workspace it needs a way back in that does not depend on one device: unused recovery codes, a second passkey, or a passkey that syncs through a password manager. Whether a passkey syncs is what its authenticator says at each sign-in and passkey confirmation, so one that stops syncing stops counting from then on; nobody is signed out, but the next join or new workspace asks for recovery codes or a second passkey first.

## Workspaces

A **workspace** is where credentials, projects, machines and people live: a person's own, a company's, a client's. It has a stable id (`tn_...`, the `tenant` the CLI carries), a name, and a canonical **slug** that addresses it at `https://app.mehen.dev/w/<slug>/` (a few words such as `api`, `app`, `w` and `docs` are reserved). A workspace can be renamed; the old slug becomes a permanent alias that redirects, up to five of them, and the id never changes. An account belongs to any number of workspaces, each by a **membership** with a role. Any account can create workspaces, as many as it wants, unless the deployment's operator has turned that off for the account; creating one needs a passkey confirmation and recovery set up first, and makes the account its owner. A workspace has no cap on its members or open invitations.

Each workspace has its own isolated store under its own key; nothing is shared across workspaces. Each workspace's key-encryption key is derived from the root key with the workspace id in the derivation, so a ciphertext copied into another workspace fails to decrypt. Not a credential, not a project, not a machine's key crosses that wall: the same upstream key wanted in two workspaces is added to each through its own intake.

The workspace's own store decides who may do what inside it. Every request, human or machine, goes through the vault's one access check, run against the live members, teams, shares, projects and devices after the last step, so a removal, suspension, expired share or narrowed scope applies to the next request.

**Managed workspaces.** A [platform](platforms.md), a business that serves its own users through Mehen, creates one managed workspace for each of its users. It is isolated exactly like any other workspace, but nobody signs in to it: its one member stands for the platform's user, the platform acts there with its own signature, and no account, membership, invite or page can reach it. Everything below about accounts, roles, invites, teams and the identity gate applies to workspaces people share, not to managed ones.

The account directory (accounts, workspaces and their slugs and aliases, memberships, passkeys, sessions, recovery codes, invite codes, pending enrolments; no secrets, every code and token hashed) is how a sign-in finds its workspaces. The workspace's own store evaluates workspace rights, using live workspace state and the directory's identity and security information. Whoever can write the directory has an operator's takeover power, not an untrusted metadata capability; [the threat model](../security/threat-model.md#whoever-can-deploy-the-vault) says so.

## Roles

A **member** is an account in a workspace, with one of four roles:

| Role | May |
| --- | --- |
| `owner` | Everything an admin may, plus change the workspace's name and slug, invite or promote owners, unfreeze. Setting an identity rule, leaving and deleting a workspace are not available yet. A workspace keeps at least one owner; the last cannot leave, be demoted or be removed. |
| `admin` | Invite, confirm, suspend, reinstate and remove members (not owners); create and manage teams; manage every project; create, rotate, re-home and delete workspace credentials; narrow or revoke any machine; admit team machines and guests' machines; deny any ask. |
| `member` | See the workspace's people and credentials; use, edit or manage the projects shared with them; create projects; hold private credentials; accept their own machines. |
| `guest` | See only the projects shared with them, their own private credentials and the credentials those projects make visible; hold private credentials and unprotected overrides; accept their own machines, which then also need an insider's admission. Never people, teams or anyone else's asks. A workspace credential reaches a guest only through an authorised project environment that references it, never merely because the guest belongs to the workspace. |

Members never authenticate with a password and agents never act as members. Anything that widens access needs a passkey step-up bound to the workspace; [Approvals](approvals.md#what-needs-a-passkey) lists what needs one. After a passkey confirmation in the browser, actions that cannot widen access do not ask again in that browser session for 15 minutes ([The 15-minute window](approvals.md#the-15-minute-window)).

## Invites

Owners and admins invite (an owner for an owner). An invite carries terms: the role, the email it is bound to (a guest invite may be open instead, and must come with at least one project share), teams to join, projects to share and an expiry of seven days. The link is `/signup#<code>`, so the code sits in the fragment and never reaches a server log; it is used once. For an invite bound to an email, Mehen can email the link to that address as it makes the invite ("Email the link to them", ticked by default); the vault keeps only a hash of the code, so it can never send it again, and an open link is never emailed (asking for that is refused). One inviting account sends at most 10 invite emails an hour and 30 a day, and one address receives at most 3 a day across every inviter and workspace; past either, or when the send fails, the invite is still made and the page shows the link to send yourself. The workspace's audit log records each link emailed, with the address, never the link. A bound invite is redeemed only after the invitee proves the email, with Google or with a six-digit code emailed to that address and typed back in the same browser within ten minutes. The code proves the mailbox, not a company identity, so it never satisfies an identity rule: a role the rule covers still needs Google. The terms also say what happens on joining, inside what the inviter's passkey signs: an email-bound member, admin or guest invite lets the person straight in unless the inviter ticked "Confirm them myself when they join". Redeeming such an invite, with that email proved and the inviter still allowed to invite that role, makes the membership `active` at once with its teams and shares; the log shows the join and the inviter's confirmation, and the inviter gets a notice in Needs you saying who joined and as what. Otherwise, and always for an owner invite or an open link, redeeming makes the membership `unconfirmed`; an owner or admin who could grant every term confirms it, and only then is it `active`. Invites made before this choice existed wait for confirmation.

Memberships can be `suspended` and reinstated, and removed. Removal deletes the member's private credentials, revokes their machines, voids every approval they decided and records which credentials they had been exposed to, for rotation, in one transaction. Suspension stops their machines at once and keeps everything for reinstatement.

## Teams

**Teams** are flat groups of members, never guests, managed by owners and admins. A team is something a project can be shared with, and something that can own machines (CI, a shared agent). A team has no rights of its own: its members get what its shares give, and its machines reach only the projects shared with the team: a project's own credentials by name, and the workspace credentials its environments reference inside that environment, never a workspace credential on its own and never anyone's private credential.

## The identity gate

A workspace may have an **identity rule**: a provider (Google), one to five domains, and the roles it covers. Setting one is not available yet. Google is an identity check, never a sign-in on its own: an account links a Google identity by proving it through Google's OpenID Connect against the vault's own client, a passkey still authenticates every session and signs every step-up, and Google never recovers an account.

A member in a covered role must have a verified Google identity on one of the domains, checked when a session enters the workspace, when a machine is accepted or admitted, when a scope is widened and when a bound invite is redeemed. A covered member whose check is missing, or older than twelve hours for anything that widens, gets `identity_required` and is sent to the workspace's verify page; a rule change, a promotion into a covered role or an unlinked identity re-gates every session. A web or app session otherwise keeps its role for up to 30 days, 7 idle.

Enrolled machines are not gated in this release, so removing someone from the workspace is the immediate cut-off. Whoever administers the Google domain can pause a covered member at their next check but cannot sign in as them or take a role.

An agent meets the gate only through its human: a covered owner who has not verified cannot accept the machine, approve the run or widen the scope, and the error that reaches the agent is `identity_required` (exit 4), which nothing but the human's sign-in clears.

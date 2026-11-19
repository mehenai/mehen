---
title: Approvals
question: Who approves what, and how?
section: concepts
covers: both
order: 60
---

# Approvals

An **approval** is a request held for a human: it is shown on a page (`/w/<slug>/a/<id>`) and decided by an eligible human with a passkey. Approvals are created by `approve` policy rules, by runs in protected environments, and by any item-mode use of a protected credential. A held request through a run's placeholder is asked as one naming the credential is, and its grant serves only a placeholder in that run's environment. An undecided approval expires after an hour, and a machine may have at most 20 open asks of every kind.

## Who decides

Your agent asks you. Whoever decides, the vault computes it when the page is viewed and again inside the decision:

- **Your own machine's asks** go to you, within your own current rights: you must yourself be able to use the credential in that context, and hold the protected right for a protected one.
- **A private credential's ask** is decided by its owner only, a guest's as much as a member's. Its full request is readable by its owner only; an owner or admin may deny it from a minimal stop view.
- **A guest's or a team's machine** asking for a shared credential is decided by a manager of the project, or an owner or admin, never by the guest.
- **Four-eyes**: where a protected environment has it, the deciders are the managers of every project whose four-eyes applies, other than the machine's owner.
- **Denying** is open to more people: owners, admins, the machine's owner, for a shared credential the project's managers, and for a team's machine the team's members.

**Approving and reading are separate rights.** An active member who can see the relevant credential or project may be able to read the full request even when they cannot approve it. Someone with only a right to deny, and no right to read the detail, sees a minimal stop view (workspace, machine, credential slug, status). Private-credential detail stays with its owner.

The eligible deciders' names travel with the refusal, so the agent can say who to send the link to. A decider's identity gate, cooling-off after an account recovery or pending account change suspends their right to approve. Every decision records who decided and on what basis; when that basis goes (a share expires, a role changes, a protected reference is added), the decisions, grants and runs that rested on it are stale.

## What the agent sees

1. The call returns HTTP 409 with `error: "approval_required"`, the approval id, a **binding code** (6 characters from an alphabet without 0, O, 1, I, L or U), `expiresAt`, and `next` with the link, `mehen wait apr_...` and a sentence for the human. `mehen` exits 3 and prints the ask.
2. The agent relays the ask: the link, what it is, the code and when it expires. The same code shows on the approval page, so with several approvals pending the human can match them. The approval itself never travels through the chat, which an agent could forge.
3. The human decides on the page with a passkey.
4. `mehen wait <approval>` returns the status: `pending`, `approved`, `denied`, `expired`, `used` or `superseded` (a newer request from the same machine replaced it; wait on that one instead).
5. The agent repeats exactly the same request. Any change to the item, method, URL, content type, content encoding, forwarded headers or body is a different request and needs a new approval. [When a request needs approval](../guides/approvals.md) is the agent's procedure.

## What the human sees

The page leads with a **decision card**: the service's tile, "An agent on my-laptop wants to" (the machine's name its owner accepted at enrolment, never the agent's session label), with a quieter "Task: <label>, as the machine named it" when one of the machine's [workloads](machines.md#workloads) asked (the label is the machine's words, not checked by the vault), the title, and the lines a person decides on (for an email: To with an `outside <domain>` mark on each external recipient, Cc, Bcc, Subject, From, attachments), then a countdown, the terms in words, the binding-code tick and a bar with Deny and Approve with passkey.

**A protected run.** The approval page shows the project, environment, command arguments, variable names and which variables receive real values or placeholders. The request digest also binds the submitted remote, worktree and commit, but this page does not display those fields. Check the CLI's resolved context before requesting approval.

Under it is the **request**. The approval is bound to hashes of the exact request. The page shows its method, URL, content type and encoding, forwarded headers and a presentation of its body: valid JSON is formatted unless formatting would change a number in it (then it is shown exactly as sent), forms are decoded, decoded email content is drawn out where it is recognised, and a body that is not UTF-8 text is represented only by a byte count and cannot be inspected there. It is not a lossless view of the original bytes. Do not approve a request whose contents you cannot verify. Requests that need approval must be uncompressed, with a body no larger than 64 KiB and forwarded headers no larger than 16 KiB; otherwise the vault refuses with `mode_refused`.

**Deceptive characters are marked.** Hidden and text-direction characters become markers that name them where they sit, such as `[RLO U+202E]`, and control characters are shown as `\u00XX`; either adds a red warning, and Deny becomes the primary button. Only markers the vault generated are styled; a marker an attacker typed stays plain text. The page checks what it shows against the approval before Approve appears.

## Grants

Approving creates a **grant** for that machine and that exact request, or, when a workload asked, for that workload alone. You may shorten the requested window or reduce its uses, never increase them: a relayed request asks for one use within ten minutes, and a protected run for one use within an hour. A matching request from the same machine (the same workload, for a workload's grant) spends one use; the grant is found by the request itself, so the approval id a request may carry is optional. A grant can end earlier when the approval expires or the authority behind the decision changes, and when the machine's owner loses the project the grant is dead at its next use.

**Allowing it from now on.** Where standing rules are switched on and the request could become one, the page offers the machine's owner, or an approver of a team machine's ask, **Approve once** beside **Approve and allow this from now on**. The second approves this request and makes a [standing rule](../guides/standing-rules.md) for the same shape of request, from the same key, for 1, 7 or 30 days; the passkey signs the rule's terms with the decision. When the approver does not manage the credential's home, the button reads **Approve once and ask a manager to allow it from now on**: the request is approved once and a manager of the home must co-sign the rule. A rule rests on the approver's decision basis, as a grant does, and ends when that basis goes; in an identity-gated workspace it rests on the approver's live standing under the gate. It never covers a request that sends, pays, shares, changes credentials or access, sets up something that keeps running or deletes.

**Letting the agent carry on.** Where standing rules are on and the request is routine building on a service with a reviewed list, the same people are also offered a panel, "Carry on without asking you", and a third button, **Approve, and let this agent carry on with** the areas ticked **for** the duration chosen. It approves this request and starts a [task grant](policy.md#task-grants) for the same key and credential: routine building in those areas, for 15 minutes, an hour or four hours, up to 25, 50, 100 or 200 requests. When the approver does not manage the credential's home, it reads **Approve once and ask a manager to let it carry on**, and a manager of the home co-signs on the proposal page. When the request cannot start one, a muted line says why.

**Letting the machine carry on.** Five things let a held request through without anyone deciding it: a standing rule, a task grant, a posture, the workspace's [Let it work](#how-often-mehen-asks) and a [mandate](mandates.md), read in that order. A mandate is the only one that covers sends and deletes and services nobody has reviewed: its signer lets one of their own machines carry on with the credentials and kinds of request named, within daily caps, until a date. Where mandates are on, an ask from your own machine that a mandate could cover offers "Let my-laptop carry on with requests like this", which opens the sign page for that machine on the narrowest terms; when the machine's mandate is paused or tripped, it says so and links to the mandate instead. An ask that a mandate would have let through but for a cap says which: "This machine's mandate has used today's 50 sends."

**Asks from a workload.** An approval, intake, connection or run a workload asks for belongs to it: only that workload may poll it, wait on it, cancel it or spend its grant. Its machine's own key sees its workloads' asks in its pending list but cannot cancel or spend one; to clean up, it revokes the workload, which ends every open ask the workload owns. Another workload of the same machine gets `not_found`. A harness that gives each subagent or task its own workload ([One workload per task](../guides/harnesses.md#one-workload-per-task)) gets grants that serve that task and nothing else.

**Decided by a platform.** In a [managed workspace](platforms.md) nobody signs in, so the platform decides: it reads the held request, checks it against what its user agreed to, and approves or denies with the approval's digest, signed with its own key. A platform's approval always serves one use, for at most 15 minutes, by the workload that asked, and the audit records the platform, its key and its own reference. A refusal there carries no link and no deciders, only the approval and its binding code.

## How often Mehen asks

An owner or admin chooses, on the workspace's Settings page, how often Mehen asks a person. Where this setting is not switched on, and in a managed workspace, every workspace is at **Ask on writes**.

- **Ask on writes**, the default. A person decides every request a credential's rules hold, which for most services means its writes. Standing rules, task grants, postures and mandates apply as above.
- **Let it work.** Nothing is asked. A held request goes through where the credential's [posture](policy.md#how-careful-a-credential-is) at trust would let it through: on a machine whose owner manages the credential's home, for a routine building route or a route nobody reviewed that a standing rule could name, on a service with a reviewed list. It reads that list as Mehen updates it, so choosing Let it work is choosing to trust Mehen's reviewed service templates as they change. A request that already carries an approval a person gave is still used. Anything else that would have asked is refused with `forbidden`, the reason and a link to the credential, and nothing waits on a person.

Let it work never covers:

- protected environments, which still need a person;
- browser fill, which still needs a person;
- pushes into other services, which still need a person;
- machines trust does not reach, such as team machines and guests' machines, whose held requests are refused, not asked;
- anything the floor holds (sends, payments, sharing, changes to credentials or access, deletes), unless the machine's own mandate covers it.

It never widens a binding, a credential's ceiling, a machine's scope or what reveal and lease allow. Moving to Let it work needs a passkey, which signs both levels; moving back to Ask on writes needs none, even while the workspace is frozen. Every change is in Activity with the level before and after.

## Pushes

A [push](../guides/push.md) asks to put a credential's value into another service's secret store: GitHub Actions, a Vercel project or a Cloudflare Worker. The vault sends the value itself once a person approves, and the machine never holds it. Its card says where the value goes, with what the provider said about that place before anyone decided (whether the secret is already there, whether a repository is public or a fork, and **New destination** for an owner this workspace has never pushed to), the store and the secret's name, the value's version, the credential that writes it, and who can read it there. The request under it is `PUSH` with the destination's canonical address and the hash of what the push binds: both credentials, their versions and settings, the field and the destination.

A push is always decided by a person, on its own page, as asked. The page offers no **Allow this from now on**, no task grant and no change of terms; no standing rule, task grant, posture or mandate ever covers a push, and **Review together** sends it to its own page. Approving queues that one push, and the approval is spent whatever happens next, even when the provider refuses it. The reason is what a push does: the copy in the provider outlives every later decision in Mehen, which cannot take it back, so each one needs a person who has read the exact destination. Who may approve is whoever may approve the machine's other requests for the credential, narrowed to its owner when the provider credential is private; a credential a four-eyes environment uses needs a second person.

An ask still waiting goes stale when either credential's value or settings change, the push allowance included. An approved push is checked again just before it is sent and is not sent if anything it rests on changed.

## Deciding several together

Where the vault has switched it on for the workspace, a person can decide several asks with one passkey. The asks come together in two ways:

- **A review group** is every open ask from one machine, one task (or none) and one credential. Needs you shows it as one row with **Review together**, and `mehen pending` prints its link for the agent.
- **A bundle** is the held requests of one `mehen plan submit`: up to 20 writes an agent asked for at once, with its reason. The agent hands over one link and every request's binding code.

Both open the **Review together** page, `/w/<slug>/g/<id>`. The vault sorts each ask into one of four sections:

| Section | What is in it | On the page |
| --- | --- | --- |
| Ready | Requests no floor holds | Ticked at first |
| Look at these first | Requests that send email, move money, share access, change a credential, set up something that keeps running or cannot be read for safety, and any use of a protected credential | Unticked, with the request open, each marked with why |
| Decide on its own page | A protected run, an ask that needs a second person (four-eyes), one that carries a warning, and one that needs a fresh look | Cannot be ticked; a link to its own page |
| You can only deny these | Asks this person may deny but not approve, including private requests they may stop but not read | Deny only |

The person ticks rows, ticks "I checked the codes against the agent's message" and presses **Approve 3 with passkey** or **Deny ticked**. One passkey covers up to 25 decisions. It signs a sorted list in which each entry is exactly what that ask's own page would sign: the ask, the digest of what the page shows, approve or deny, and the uses and window it asked for. The vault then decides each entry in its own transaction, with every check a single decision makes, and reports each one: approved, denied, or skipped because it expired, was decided or replaced meanwhile, changed, or must be decided on its own page. Unticked rows stay waiting.

A batch never shortens a grant, never makes a standing rule or a task grant, and never decides a run, four-eyes or warned ask: "To shorten a grant or allow it from now on, open its own page." While a person's account is cooling off after a recovery, a batch goes through only when every entry denies. A managed workspace has none of this; its platform decides each ask. Where it is off, `mehen plan submit` and `mehen fetch --replaces` are refused with `forbidden`, and each ask is decided on its own page.

Not built: grants scoped to a session label, approvals of a pattern of sends or payments ("Gmail sends to `*@example.com`, at most 5, for an hour"), budgets per binding, and receipts attached after execution.

## What needs a passkey

A **step-up** is a passkey confirmation of one exact action. The server rebuilds the action from what it is about to do, never from what the page claims, and binds it to the workspace, so what the human saw is what they signed. Everything that widens access needs one:

- storing or rotating a credential from an intake, and starting an OAuth connection;
- accepting your own machine, admitting a guest's or a team's machine, and accepting a wider scope for your machine;
- narrowing or revoking a machine, and revoking one of its workloads;
- deciding an approval, or up to 25 together; approving, co-signing or denying a standing rule or task grant proposal, and extending a rule (stopping a rule or a task grant needs none);
- setting how careful a credential is;
- signing a mandate, and resuming one after a trip, a lapse or an owner's or admin's pause (pausing or stopping one needs none, nor does its signer resuming one that they or the machine paused);
- changing a credential's binding, policy, ceiling, tags, description, the web pages it may be typed into or whether it may be put into other services' secret stores, re-homing it or deleting it, and pushing it again to the places it went before;
- setting a variable, protection, four-eyes, fences or a bound repository from the browser, and choosing a personal override;
- creating, sharing, configuring or deleting a project;
- inviting, confirming, changing the role of, suspending, reinstating or removing a member;
- changing teams;
- the workspace itself: renaming and unfreezing (the pages do not offer setting an identity rule, leaving or deleting a workspace yet);
- your account: passkeys, recovery codes, linked identities, deleting it.

Pulling the brake (freezing) needs no passkey. While an account is cooling off after a recovery, or has a security change pending, only tightening actions are allowed: narrow, deny (one ask or a batch in which every entry denies), set a credential back to asking for every change, revoke a machine or one of its workloads, freeze, and cancel the recovery. During a recovery, only a sign-in with a passkey from before it can end other sign-ins; cancelling the recovery ends the new ones. [Keys, proofs and signing](../security/keys-and-signing.md#step-up) has the exact challenge and the action table.

### The 15-minute window

After a real passkey confirmation in the browser, further confirmations in the same browser session do not ask for the passkey again for 15 minutes, for actions that cannot widen access. The account page says "Passkey confirmed, no need to confirm again until 14:32". The window does not slide: a confirmation inside it does not extend it, and only another real passkey confirmation starts a new 15 minutes. Everything else about a step-up stays as it was: the vault rebuilds the exact action, each confirmation is used once, and the cooling-off, pending account change and identity checks still apply.

**Inside the window, without the passkey:** deciding an approval once, or up to 25 together; denying a standing rule or task grant proposal; setting a credential back to asking for every change; storing a credential from an intake; starting an OAuth connection; approving adopted credentials when no project variable is repointed; pushing a credential again, restoring it or deleting it; creating a project; creating, renaming or deleting a team; leaving a workspace, once the pages offer it; narrowing or revoking a machine, turning down a wider scope and revoking a workload; renaming a workspace and creating one; resuming a mandate an owner or admin paused.

**Always a fresh passkey,** because each can widen who can act, how someone proves who they are or what a credential is exposed to, or relax a protection:

- your passkeys, recovery codes and linked identities, and deleting your account;
- unfreezing a workspace, and, once the pages offer them, deleting one and setting its identity rule;
- inviting, confirming, changing the role of, suspending, reinstating or removing a member, and a team's members;
- sharing, configuring or deleting a project, and choosing a personal override;
- changing a credential's binding, policy, ceiling, tags, description, web pages or push allowance, a project's variables, protection, four-eyes, fences or bound repository, and moving a credential to another home;
- adding or removing a backup key;
- accepting or admitting a machine, and widening one;
- **Approve and allow this from now on**, approving or co-signing a standing rule or task grant, and extending a rule;
- setting how careful a credential is to anything but asking for every change;
- approving adopted credentials that repoint a project variable;
- signing a mandate, and resuming one after a trip or a lapse.

**One browser session.** The window belongs to the browser session that confirmed. Another browser or a new sign-in starts without one. An app that opens the vault's pages in an in-app browser, such as a Safari view on iPhone, decides there like any browser: its confirmations follow that view's session, window included. Only the vault's native app route, which decides one approval with the app's own passkey prompt (`POST /app/v1/stepup`, then `/app/v1/w/<slug>/approvals/<id>/decide`), never offers the window, so a confirmation through it always asks.

**It ends early** when that session signs out or is ended, when the account's security changes, as a recovery changes it, when the passkey that confirmed is removed or waiting to be removed, when the account starts cooling off or has a security change pending, and when the account is suspended. **Ask every time** on the account page ends it at once, with no passkey.

A confirmation inside the window is marked as one in the audit, with the time of the passkey confirmation it rested on. Where the vault has the window switched off, every confirmation asks for the passkey.

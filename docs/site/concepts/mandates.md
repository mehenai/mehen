---
title: Mandates
question: How does a machine carry on without asking, and what stops it?
section: concepts
covers: both
order: 65
---

# Mandates

A **mandate** (`mdt_...`) lets one machine send its held requests without asking anyone. A person signs it once, with their passkey, for one of their own machines. It names which credentials, which kinds of request (read, change, send, delete), how many of each a day, and an end date at most 90 days away. It can also be limited to certain hours. While it is active, the vault lets what it covers through on the machine's own key, keeps a receipt of each request ("went through on trust") and counts it against the day's caps.

It is the only standing approval that covers sends and deletes, and the only one that works on services nobody has reviewed. A [standing rule](policy.md#standing-rules) covers one request shape, a [task grant](policy.md#task-grants) a burst of routine building on a reviewed service, and a [posture](policy.md#how-careful-a-credential-is) a reviewed service's routine routes. A mandate is for a machine that works while nobody watches it, such as an agent on its own server, or a person's own agent that they trust while they watch. [Agents that work on their own](../guides/unattended-agents.md) is the procedure for both.

## Switched on per workspace

Mandates are switched on workspace by workspace. Where they are off, every mandate route answers `not_found` as an unknown route does, `mehen mandate` says "This workspace has no mandates: they are not switched on here, or this vault is older than them.", machine pages have no **Carry on without asking** card and no ask carries `mandateCover`. Every held request asks as usual. A managed workspace has none: its platform decides what each machine may do without asking, and a mandate request there is refused with `forbidden`. In a frozen workspace, proposing, signing and resuming are refused with `frozen`, and nothing is covered.

## What a mandate names

| Term | What it is | Default on the sign page |
| --- | --- | --- |
| Machine | One machine, owned by the person signing | The machine the page was opened for |
| Credentials | Credentials ticked one by one, or every credential the machine can use whose home the signer manages, now and later | None ticked; choosing every credential is done on the page, never by its address |
| Kinds | `read`, `change`, `send` and `delete`; read is always included | Read alone |
| Caps | Requests a day for each kind ticked, counted per UTC day | 500 reads, 100 changes, 10 sends and 5 deletes, for a fresh form and a kind newly ticked; at most 50000, 10000, 500 and 200 by a deliberate edit |
| How long | 1, 7, 30 or 90 days | 30 days |
| When | At any time, or up to seven windows of days and hours in one time zone | At any time |
| What it is for | A note of up to 200 characters, seen by everyone who can see the machine | "Routine work on" and the machine's name |

A request may be in more than one kind: posting a message is a change and a send. Every kind it is in must be ticked, and each counts once against its cap, however many credentials the request uses. A cap counts requests, not amounts or recipients: 50 sends a day is 50 requests that send, to any number of people. Once a kind reaches its cap, those requests ask as they would with no mandate until the next UTC day, and the others carry on. The ask says which cap: "This machine's mandate has used today's 50 sends." More than 120 requests beyond reading in any minute **trips** the whole mandate: nothing goes through until its signer resumes it with a passkey, and the signer, owners and admins are told.

Choosing every credential includes credentials the machine can use later, and covers each one only while the signer manages where it lives. A schedule window runs from its start up to its end; one ending earlier than it starts runs past midnight and counts on the day it started. Outside every window, requests ask.

## What a mandate never covers

Whatever is ticked, these ask every time:

- minting or reading credentials, webhooks, forwarding, inbox rules, SSO, members, invites, permissions, sharing and publishing;
- money, and anything on a credential holding a live key;
- a request Mehen cannot read, and a method other than `GET`, `HEAD`, `POST`, `PUT`, `PATCH` or `DELETE`;
- anything the credential's policy refuses, or a destination that is not standard HTTPS;
- a host that only a wildcard in the credential's binding admits: the request's host must be one the binding names exactly;
- a protected credential, environment or run;
- a workload's request (a machine that acts only through workloads gets nothing from a mandate);
- anything in a managed or frozen workspace;
- reveal, lease, fill, push, connect and enrolment, which a mandate is never asked about.

A mandate is also only one of four things that let a held request through, and the last asked. A standing rule, task grant or posture that covers a request comes first, and that request is not a mandate use. When a request uses several credentials and one of them is covered by nothing, the request asks and nothing is spent.

### What "never" means on a service nobody has reviewed

On GitHub, Stripe and Cloudflare, Mehen has read the routes one by one, so the list above is a guarantee there. On a service nobody has reviewed, Mehen can only judge a request by its method, its path, its query parameter names and the floor's checks on its body: it asks for what those name and lets the rest through. A route that sends money but whose path says nothing about money, on a service Mehen has never read, would go through as a change. The sign page says this in those words before the passkey: "On services nobody has reviewed, Mehen can only judge a request by its method, address and shape: it asks for what those name and lets the rest through." Choose the credentials and kinds with that in mind. Receipts name the service's reviewed route where there is one, and "on a service nobody has reviewed" where there is not.

## Who signs, pauses, resumes and stops

- **Sign:** only the person who owns the machine, a member who is not a guest, with a passkey that is always fresh (the [15-minute window](approvals.md#the-15-minute-window) never covers a signature). Each credential listed must be one they manage the home of and the machine can use. A team's machine or a guest's cannot have one yet: a team machine gets mandates signed by two people in a later version, and until then its routine work goes through a task grant. A machine has at most one live mandate (active, paused or tripped); signing a new one stops the old one in the same step.
- **Pause:** the signer, an owner or admin who can see the machine, or the machine itself (`mehen mandate pause`), any of its workloads included. No passkey: a pause only narrows. Pausing a paused or tripped mandate changes nothing, except that an owner's or admin's pause takes over one by the signer or the machine.
- **Resume:** the signer only, never the machine. When the signer or the machine paused it and nothing has changed since they signed, resuming needs no passkey. After an owner's or admin's pause it needs the signer's passkey, which the 15-minute window may cover. After a trip, or once it has lapsed (below), it needs a fresh passkey every time.
- **Stop:** the signer, or an owner or admin who can see the machine, with no passkey. Stop is final: to let the machine carry on later, someone signs a new one.

A mandate ends on its own at its end date. Three days before, its signer is told, and the page offers **Renew**; every ended mandate the signer could sign again offers **Sign again with these terms**, however long ago it ended. Either opens the sign page on the narrowest terms with the old ones in words; pressing **Use these terms** fills them in.

## When the signer's standing changes

A mandate does not depend on the browser session that signed it: signing out, another browser or an expired session leave it as it was. At every use the vault checks again that the signer still stands where they stood when they signed: the same account and security, the same role, no cooling-off or pending account change, the machine still theirs and active, and the credential's home still one they manage. A mandate never reaches further than its signer could approve at that moment.

When that standing goes, the mandate **lapses**: it stays active on paper and covers nothing. Account recovery or another change to the signer's account security, such as signing out everywhere, a role change, a suspension, an identity rule change, losing the machine, the machine's scope widened, or losing management of a credential's home each lapse it. A lapse is sticky: undoing its cause, such as reversing a demotion, does not restore it. Only the signer resuming it with a fresh passkey does. The signer gets a notice once per lapse ("The mandate you signed for build-box covers nothing now"), the machine's page and the mandate's page say it covers nothing until they resume it, and the home shows "1 machine needs you to resume its mandate". The machine is told only that the mandate is not covering requests, never why.

**Sign out everywhere** on the account page lapses every mandate the person signed until they resume each with their passkey. Their machines stay enrolled. The confirmation says so before they press it.

## How a machine asks for one

The machine proposes; a person decides. `mehen mandate propose --note "<what it is for>"` (MCP `vault_mandate` with `action: "propose"`) prints an ask titled "Trust this machine" and exits 0. Nothing is covered by proposing. The link opens the sign page on the proposed terms, which the person may change before signing. A proposal lasts 7 days.

By default the proposal names the credentials and kinds this machine asked for in the last 30 days (`GET /v1/mandates/asked`), with `read`, for 30 days, at low caps: 500 reads, 100 changes, 10 sends and 5 deletes a day. A machine may propose a mandate only for what it asked for, and no wider: the vault refuses a proposal that names every credential (`mandateRefused: "items_all"`), a credential it has not asked for (`item_unasked`), a class besides `read` it has not asked for (`class_unasked`), more than 30 days (`term_too_long`) or a cap above 500 reads, 100 changes, 10 sends or 5 deletes a day (`caps_too_high`). What it may propose is what it asked for (and not rejected) or used under its own mandate: each credential and class of its own held requests that carried a `mandateCover` hint, unless a person rejected that ask, and of the requests its own mandate let through, from the last 30 days up to now, for credentials it can still reach. An ask left to lapse still counts, and so does another ask of the same credential and kind when one is rejected; another machine's never count. A machine can make that history itself, by asking: it narrows a proposal to what the agent has been doing, and the person still decides. The refusal is `forbidden`, names what to drop or lower and what it asked for, and `next.command` proposes the same terms cut to what is allowed, with the same hours (`--schedule`, quoted for a shell). There is no command when there is no valid bounded retry: when it would name more than 200 credentials (choose at most 200 with `--items`), or when an explicit list shares no credential with what was asked for (choose from those with `--items`). A proposal keeps the credential behind each slug it names: deleting a credential closes the open proposals that name it, and signing one whose slug now names another credential is refused. The sign page opens an open proposal on its own terms only, whatever its address says; a proposal that is closed, signed, expired or from before Mehen kept its credentials opens on the narrowest terms, its terms in words behind **Use these terms**. Every unsigned open proposal made before Mehen kept those credentials closes on upgrade, with a note on its page that the machine can propose again; it shows what it named as text and preselects nothing. Signed mandates are untouched. Renewing a mandate, or copying another machine's, opens the form on the narrowest terms too: the old terms are shown in words, and only pressing **Use these terms** puts them in the form. This binds the machine alone: the person who signs may tick any credential and kind, and choose any length and caps, on the sign page, with the passkey as before. A vault upgraded to this starts from the held asks with a hint it still keeps, about the last two days, and the uses of each machine's own mandates in the last 30 days.

- Proposing the same terms with the same reason while they wait hands back the same link with `existing: true`, and does not count against the limits.
- A machine may have 3 open proposals and make 10 a day. At 3 open, the refusal says how many and carries the newest one's link; at 10 a day it is `rate_limited` until tomorrow.
- `mehen mandate ls` lists the machine's open proposals first, each with its link, then its mandates. The person sees them on the mandates page under **Waiting for you**, and on the machine's page.
- Signing a mandate closes every other open proposal of that machine; a closed proposal's page says a mandate was signed since and links to it.

### The cover hint

When the vault holds a request from a machine whose owner could sign a mandate, and a mandate could cover that kind of request, the refusal carries `mandateCover`: the kinds a mandate would need, a state, and this machine's mandate and its page when it has one. A guest's or a team's machine never gets one, nor a workload.

| State | Meaning | What the agent does |
| --- | --- | --- |
| `none` | The machine has no mandate | The third time the same kind of ask carries it, propose one with those kinds |
| `unticked` | Its mandate does not name this kind or this credential | The third time, propose wider terms |
| `paused`, `tripped` | Its mandate is paused or tripped | Hand the person the page; its signer can resume it |
| `ended` | Its mandate has ended | Hand the person the page; its signer can sign it again |
| `outside_schedule` | It is outside the mandate's hours | Wait for its hours, or let the ask go to the person as usual |
| `not_covering` | It is not covering requests right now, and the vault does not say why | Hand the person the page |

An ask that only a cap held carries `mandate` with the caps reached instead. The person sees the same on the ask page: their own machine's ask offers "Let build-box carry on with requests like this", which opens the sign page for that machine on the narrowest terms, or a link to the mandate when it is paused or tripped.

## What people see

- **The sign page** (`/w/<slug>/sign-mandate`) offers each term, then, before the passkey, a summary of what is being signed in plain words, with the two sentences about reviewed and unreviewed services.
- **The mandates page** (`/w/<slug>/mandates`) lists proposals waiting, then live mandates, then ended ones. **Pause all** pauses every active mandate there the reader may pause, after a confirmation that gives the count; it needs no passkey, and says how many it could not pause, if any.
- **A mandate's page** shows its terms, today's counts against its caps, Pause, Resume and Stop for those who may press them, and **Went through on trust**: every request it let through, newest first, kept for 30 days. Its signer sees **Sign the same for** each of their other machines, which opens the sign page for that machine on the narrowest terms, with this mandate's terms in words behind **Use these terms**; pressing it fills them in, keeping only the credentials that machine reaches and whose homes the signer manages. There is no signature for several machines at once.
- **A machine's page** has the **Carry on without asking** card: its mandate with its controls, or **Trust this machine** for its owner.
- **The home** says "1 machine is carrying on without asking" while any mandate is active and its signer stands behind it, and how many need the reader to resume theirs.

Owners and admins are told when a mandate is signed. Its signer, owners and admins are told when one trips. Only the signer is told when one is about to end or has lapsed. Notices name the machine, the signer, the kinds and the end date, never a credential.

Everyone who may read a mandate sees its terms, state and counts. Each reader sees only the credentials they can see now, with "and 2 credentials you cannot see" for the rest. A receipt for a credential the reader cannot see says "a credential you cannot see" with the time, kinds and method, and nothing else.

## What the machine sees

A response a mandate let through carries `Mehen-Mandate: mdt_...`. `mehen fetch` adds "allowed without asking by this machine's mandate mdt_..." on stderr, and `mehen fetch --json` and `vault_fetch` carry `mandate`. `mehen status` shows the live mandate with today's counts against its caps, such as `mandate: mdt_...: active, change 3/200, send 1/50, ends 6 Feb`, and how many proposals wait for a signer. `mehen mandate show` reads one, and `mehen mandate uses` lists what went through on trust. A paused, tripped or ended mandate carries its page in `next.url`, for the agent to hand to the person. [Agent reference](../reference/agent-reference.md#mandates) has every flag and field.

## What is recorded

The audit records each proposal, signature, pause, resume, stop, trip and expiry, by machine and kind, never with a path. Each use on a shared credential is also recorded as `mandate.use` with the method, host and reviewed route; for a member's private credential, the receipt on the mandate's page is the record, and the audit keeps its usual private form.

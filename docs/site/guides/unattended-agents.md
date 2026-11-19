---
title: Agents that work on their own
question: How do I let an agent carry on without asking me for every request, and what does it still ask for?
section: guides
covers: both
order: 86
---

# Agents that work on their own

An agent that runs overnight on a server, or that you leave working while you do something else, stops at every held request until someone approves it. A [mandate](../concepts/mandates.md) lets its machine carry on: you sign once, with your passkey, which credentials and kinds of request it may send without asking, how many a day, for how long and, if you like, only in certain hours. This guide is for the two common cases: an agent on its own server, and your own agent that you trust while you watch it.

Mandates are switched on workspace by workspace, and never in a managed workspace. Where they are off, `mehen mandate` says "This workspace has no mandates: they are not switched on here, or this vault is older than them.", no ask carries `mandateCover`, and every held request asks as usual: use [standing rules](standing-rules.md) for repeated requests, or approve each one.

## Before you start

- **The machine must be yours.** A mandate is signed by the member who owns the machine, for that machine alone. A machine a team owns, such as a CI runner or a chat bot shared by a team, cannot have one yet; for its routine work, [propose a task grant](standing-rules.md#task-grants). A guest's machine cannot have one either.
- **The machine's own key does the work.** A request from a [workload](../concepts/machines.md#workloads) is never covered, so a machine enrolled with `--workloads-only` gets nothing from a mandate. Run the unattended work as the machine itself.
- **Know which credentials it needs.** A mandate covers a credential only while you manage where it lives, and only when the machine can already use it. It never widens what the machine can reach.

## An agent on its own server

Say `build-box` is a server you enrolled as your own machine, running an agent that triages the support inbox each night and files issues.

1. **Let it ask first.** Run the work once with no mandate. Each held request comes to you as an ask; approve or deny them as usual. An ask a mandate could cover carries `mandateCover` with state `none` to the agent, and its page offers you "Let build-box carry on with requests like this".
2. **The agent proposes.** The third time the same kind of ask carries `mandateCover` with state `none` or `unticked`, an agent following the Mehen skill proposes a mandate with the kinds the hint names:

   ```sh
   mehen mandate propose --note "Nightly triage of the support inbox" --items gmail-support,linear-work --classes read,change,send --caps send=20 --days 30 --schedule "Europe/Paris daily 01:00-05:00" --json
   ```

   It prints an ask titled "Trust this machine" and exits 0. Nothing is covered yet. Proposing the same terms again hands back the same link.
3. **You review and sign.** Open the link, or **Waiting for you** on the mandates page. The sign page starts on the proposed terms and you may change any of them. Untick what it does not need: if triage never deletes, leave delete off. Keep the caps near what a night's work takes, so a runaway agent hits a cap before it does much. Before your passkey, the page says in plain words what you are signing. Signing always asks for your passkey.
4. **Read what went through.** The mandate's page lists every request it let through, newest first, under **Went through on trust**, with today's counts against the caps. The agent can read the same with `mehen mandate uses <mdt_id> --since 12h`.

Without a proposal, open the machine's page and press **Trust this machine**. The sign page then starts with all four kinds ticked at their default caps, 90 days and no credential ticked, so you choose each credential yourself.

## Your own agent, while you watch

Say you work alongside an agent on your laptop all day and approve most of what it asks. A mandate for that machine saves the approvals, and you keep the brake in reach.

- **Keep it short.** 1 or 7 days, and renew it when it ends. Three days before the end, you are told, and the mandate's page offers **Renew**.
- **Limit the hours.** A schedule such as `Europe/London mon-fri 09:00-18:00` means nothing goes through on trust in the evening or at the weekend, when you are not watching. Outside those hours, its requests ask as usual.
- **Pause when you step away.** **Pause** on the mandate's page or the machine's page stops it at once, with no passkey, and so does `mehen mandate pause` on the machine. You resume it from the same page; when you or the machine paused it and nothing about your access has changed, resuming needs no passkey.
- **Several machines:** on the mandate's page, **Sign the same for** opens the sign page for another of your machines on the same terms. Each machine gets its own signature. **Pause all** on the mandates page pauses every active mandate you may pause at once.

## What it still asks for

Whatever you tick, a mandate never covers minting or reading credentials, webhooks, forwarding, inbox rules, SSO, members, invites, permissions, sharing, publishing, money, a live key, a request Mehen cannot read, a host only a wildcard in the binding admits, a protected credential, environment or run, a workload's request, or anything in a managed or frozen workspace. Those ask every time, and the agent hands you the link as usual.

**What that promise is worth depends on the service.** On GitHub, Stripe and Cloudflare, the routes on their reviewed lists and the floors their templates name hold route by route; any other route there is judged as on a service nobody has reviewed. On a service nobody has reviewed, Mehen can only judge a request by its method, address and shape: it asks for what those name and lets the rest through. A route that moves money but whose path and body look like an ordinary change goes through as a change. The sign page says this in those words. So on a service nobody has reviewed, tick only the credentials and kinds you would be content to see used in ways nobody predicted, with caps that bound the damage. That is still more than an agent reading the same key from a `.env` file gets, which has no floor at all.

## When it stops covering

| What happened | What the agent sees | What you do |
| --- | --- | --- |
| A kind reached its cap for the day | Those requests ask, with "This machine's mandate has used today's 20 sends."; the other kinds carry on | Approve the asks, or wait for the next UTC day |
| More than 120 requests beyond reading in a minute | The mandate trips; everything asks, with `mandateCover` state `tripped` and the mandate's page | Find out why, then resume it with your passkey, or stop it |
| You, an owner or an admin paused it | Everything asks, state `paused` | Resume it when you are ready; after an owner's or admin's pause, with your passkey |
| Your standing changed: account recovery, signing out everywhere, a new role, losing the machine or a credential's home | Everything asks, state `not_covering`, with no reason given | You are told once; resume it with your passkey from its page, where it says it covers nothing |
| It reached its end date | State `ended` | Sign it again from its page, or let the agent propose new terms |
| It is outside its hours | State `outside_schedule` | Nothing; it carries on when its hours begin |

The agent never resumes, stops or signs a mandate. For a paused, tripped or ended one, it hands you the mandate's page.

## Related

- [Mandates](../concepts/mandates.md): every term, who may do what, and what people and the machine see.
- [Agent reference](../reference/agent-reference.md#mandates): the flags, the `mandateCover` states and the fields an agent reads.
- [Threat model](../security/threat-model.md#a-prompt-injected-agent): what an injected agent can do under a mandate.

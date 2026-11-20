---
title: Policy
question: What decides whether a request goes through?
section: concepts
covers: both
order: 40
---

# Policy

A request that passed the [binding](credentials.md#bindings) meets the item's policy, which says `allow`, `approve` (wait for a human, see [Approvals](approvals.md)) or `deny`.

## The shape

```ts
type Policy = {
  default: "allow" | "approve" | "deny"
  rules: {
    action: "allow" | "approve" | "deny"
    methods?: string[]
    paths?: string[]
    body?: BodyMatcher
    note?: string
  }[]
}
```

Rules combine as **deny over approve over allow**, never first match wins, so adding a rule cannot silently open something. If no rule matches, `default` applies. A rule may name a **body matcher** for requests whose meaning is in the body rather than the path, such as GraphQL, or a JSON request that names a remote MCP server or a webhook the provider would call itself, or asks it to publish the output at a public URL or upload it to a URL the request names. Matchers fail closed: a body they cannot read in full (empty, not UTF-8, invalid JSON, a repeated JSON key, a batch) is treated as the risky case, so it is held or refused, never let through.

**What counts as GraphQL.** Before a standing rule, task grant, posture or mandate stands in for a person, a GraphQL body needs a proof the vault can read field by field. A JSON body counts as GraphQL when it has `query`, `operationName`, `extensions`, `documentId` or `doc_id` at any depth, a `variables` that is an object, or an `id` together with `variables`. On a path with a segment naming `graphql` or `gql`, an `id` or a `variables` of any kind is enough. Any other JSON object is read as ordinary JSON, so a REST create that names its own `id`, such as creating a Cloudflare AI Gateway, is no longer unreadable. The other side of that: a persisted GraphQL query sent as `{ "id": ... }` alone, to a path that does not name GraphQL, also reads as ordinary JSON.

Policy, not intent, decides. Some reads and narrowly allowed writes run without asking, and a human may change a credential's policy from its page with a passkey. Three things let a request the policy holds through without asking, and only a person's passkey sets any of them: a [standing rule](#standing-rules) for one request shape, a [task grant](#task-grants) for a short burst of routine building, and [how careful](#how-careful-a-credential-is) the credential is. Requests in protected environments also need an approval ([Projects, environments and runs](projects.md#protected-environments)).

A [workload](machines.md#workloads)'s request meets the same binding and policy as its machine's would, inside the workload's narrower scope. When the policy says `approve`, the approval and the grant it makes belong to that workload: only it can wait on the approval and spend the grant, and the page names its task under the machine ([Approvals](approvals.md#grants)).

## What templates allow, hold and refuse

Provider templates fail closed. For an item made from a template:

- **Reads are allowed** (`GET`, `HEAD`), except a read that hands back another secret: a database password or connection string, a decrypted environment variable, a stored secret, a mail server's details. Those need an approval.
- **Every other method needs a human's approval by default**, except a few narrow everyday writes the template allows explicitly: model calls for an AI provider, searches and scrapes for a search API, read-only queries.
- **Sends and money movements are pinned to an approval**, so no later allow rule can open them: email and messages, payouts and refunds, anything billed, and root access to a server.
- **The worst routes are denied outright**: anything that sends mail or data elsewhere for good (forwarding, filters, mailbox rules, delegates, webhooks, destinations, log drains), gives someone else access (SSH and deploy keys, collaborators, members, invitations, roles, app registrations), mints or revokes tokens, or cannot be shown honestly on an approval card; and deleting a whole project, team or organisation.

`mehen templates <id>` prints a template's rules as three lines (without a human, needs approval, refused), and `mehen show <item>` shows an item's policy. [Providers and templates](../reference/providers.md) lists every template's three lines. Do not look for a way round a denied route; use the alternative:

| You try to | The vault | Do this instead |
| --- | --- | --- |
| Send a saved Gmail draft by id (`drafts/send`) | Denies it (`policy_denied`) | A draft can change after the send is approved, so the approval could not show what is sent. Send the whole message with `POST .../messages/send` and a `raw` body; the approval shows it. |
| Send a stored Microsoft Graph message by id, or forward or reply to a stored message | Denies it | The same reason. Send the whole message with `sendMail`. |
| Use Microsoft Graph `$batch` | Denies it | A batch carries requests the vault cannot check one by one. Send each request on its own. |
| Change mail forwarding, delegates, filters, mailbox rules or settings; add SSH or deploy keys, webhooks, collaborators or app registrations | Denies it | These give lasting access to someone else. Ask the human to do it themselves, outside the vault. |
| Mint or revoke an API token, invite a member, add a webhook, log drain or event destination, or delete a whole project or organisation | Denies it | The same reason, and a deleted project does not come back. Ask the human to do it in the provider's own console. |
| Read a Fathom recording's summary or transcript | Holds it for approval | That route can post the text to any URL named in its query, which no rule can see. List meetings with `GET /meetings?include_transcript=true` instead. |
| Call Notion | Needs a `Notion-Version` header | The vault adds only the secret; send `Notion-Version` yourself on every request. |
| Reach a scoped npm package (`@scope/name`) | Refuses it as an ambiguous path | Its name travels as `@scope%2fname`, an encoded slash. Unscoped packages work; ask the human to publish a scoped one. |
| Run a GitHub GraphQL request | Allows a read-only query that a strict matcher can read in full; holds anything else for approval | Prefer a plain query, or the REST endpoint. |

## Credentials without a template

A credential stored without a template (an agent proposed its binding) fails closed as well: its policy is `approve` by default with no rules, so every request waits for a human. The intake page offers one tick, unticked, to let reads (`GET`, `HEAD`, `OPTIONS`) through without asking; the passkey signs that choice with the rest of the form. A rotation keeps the item's policy, and a template's intake takes the template's. Only a human can widen a policy afterwards, from the item's page with a passkey.

## In a managed workspace

In a [platform's](platforms.md) managed workspace a credential keeps no policy of its own. Each time it is used, the vault takes the catalogue's current policy for its template or provider and adds the platform's own rules for it, which may only hold or refuse; a credential with no template holds everything, unless the platform let reads through. So a platform can make the catalogue stricter for all of its users at once, never looser, and a change reaches every workspace within 30 seconds. Nobody can change one credential's policy there.

## How the summaries are written

The three policy lines (`without a human`, `needs approval`, `refused`) for a built-in template use the template's reviewed notes ("reads; creates a draft; changes labels"). For an item, they describe each rule from what it matches (method and paths), never from its note, because nothing proves an item's policy is a template's. "anything else" always lands on the line of the policy's default. `mehen check` runs the same matcher locally to say what a request would get; it is advisory ([Find a credential and call an API](../guides/call-an-api.md#check-before-you-send)).

## Standing rules

A **standing rule** (`rul_...`) lets one shape of request through without asking, for 1, 7 or 30 days: one credential, the key that asked (a machine's own or one workload's), one method, one host, one path or a pattern with `*` in place of an id, the same query parameter names and, for GraphQL, the same mutation fields. An agent proposes it with `mehen policy propose` (MCP `vault_policy`), or a person chooses **Approve and allow this from now on** on an approval page; either way a person's passkey turns it on, and a manager of the credential's home co-signs when that person does not manage it. [Standing rules](../guides/standing-rules.md) is the whole procedure.

Where standing rules are on, a member's **My rules** page (`/w/<slug>/rules`, in the workspace navigation) lists every live rule on their own machines or that they approved or co-signed, each with **Stop** and **Extend**, as the credential's and machine's pages show them.

A rule only turns a request this policy would hold into one that goes through. It never changes a `deny`, the binding, the ceiling or the policy itself, and never applies to a lease, a reveal, a protected credential, environment or run, or a managed workspace. Requests that send, pay, share, change credentials or access, set up something that keeps running or delete never become rules, and nor does anything on a credential holding a live key. A rule ends at its deadline, when someone stops it, when access changes under it, or when the credential is edited.

Standing rules are off until the vault switches them on for your workspace, and never on in a managed workspace. Where they are off, `mehen policy propose` answers `forbidden`, "Standing rules are not switched on for this workspace yet." (over HTTP the vault's own message is "Policy widening is not available yet."), and every held request asks as usual. A rule never stands in for a protected context.

## Task grants

A **task grant** (also a `rul_...`) lets an agent carry on with routine building in named areas of one service, for 15 minutes, an hour or four hours, and up to a number of requests: at most 200, and 50 unless someone chooses otherwise. It is for a burst of work, such as setting up a Cloudflare Worker with its routes and KV namespace, where each request differs but all of them are the kind of change a person would wave through.

An area comes from the service's **reviewed list**, the routes Mehen has read one by one and marked as routine building or not. Only GitHub (`issues`), Stripe (`products`) and Cloudflare (`workers`, `routes`, `kv`, `r2`, `d1`, `queues`, `pages`, `ai-gateway`, `vectorize`, `workflows`, `dns`) have one; [Agent reference](../reference/agent-reference.md#task-grant-areas) lists them. A grant covers a request only when:

- it is on that credential, from the same key (the machine's own or one workload's), in the same project and environment, or none, as the request it was made from;
- it goes to the service's host, to a route the list marks routine in one of the areas ticked, with no query string, and with a JSON body, unless the route takes raw bytes or is Cloudflare's Analytics Engine SQL, which takes one SQL statement sent as plain text or as a form;
- the route was on the list when the grant was signed: routes added later are not covered;
- no floor holds it, the credential is not protected and holds no live key, and the machine is not a guest's.

It starts in one of two ways. A person on the approval page of a held routine request chooses **Approve, and let this agent carry on**, ticking the areas, the duration and 25, 50, 100 or 200 requests ([Approvals](approvals.md#grants)). Or the agent proposes one from a held or approved request, `mehen policy propose --from apr_... --item <slug> --area <area> --reason "<why>"`, and a person approves it on the proposal page, "Let an agent carry on", which shows the areas, duration and uses read only. Who approves, and when a manager of the credential's home must co-sign, is as for a standing rule; a proposal that needs a co-signer waits for one.

A grant ends at its deadline, once it has been used as many times as it allows, when someone stops it (no passkey needed), when access changes under it or the credential is edited, or when a newer grant for the same key and credential replaces it. **My rules** and the credential's page list each grant with its areas, its uses out of its most, its end, and what it was used for. Task grants are switched on with standing rules, and never in a managed workspace.

## How careful a credential is

Each credential has a **posture**, set on its page in the **How careful** card by someone who manages its home, with a passkey:

| Level | What goes through without asking | Which machines |
| --- | --- | --- |
| Ask for every change | Nothing more than the policy allows. The default. | |
| Let routine building through | Every route the reviewed list marks as routine building, in any of its areas. Deletes, secrets, sending and sharing still ask. | Members' and teams' machines, never guests' |
| Trust my own machines | Everything except what always asks, including routes nobody has reviewed. Always asks: a delete and any route the reviewed list marks destructive (such as moving a Worker's live traffic), secrets and credentials, sending, sharing and access, payments, anything that keeps running, anything the vault cannot read for safety, a method other than GET, HEAD, POST, PUT or PATCH, anything the credential's own policy refuses or names to ask, and a route nobody has reviewed whose body is not JSON or whose path names one of those acts or a word such as `token`, `hook` or `member` | Only machines of people who manage the credential's home |

The card can also limit either level to machines ticked by name, at most 32. **Custom rules** keeps the posture at ask and points at the credential's own policy and its standing rules.

A level other than ask needs a reviewed list for the credential's host, so it is offered only for GitHub, Stripe and Cloudflare credentials. A guest, or someone whose account is cooling off after a recovery, may only set a credential back to ask. The posture is a record of its own: setting it never touches the policy or the credential's revision, so standing rules outlive it. When the reviewed list grows, the card says so; the new routes are not covered until someone reviews and saves again. Cloudflare's list is at version 2, which added Analytics Engine SQL (`POST` to an account's `analytics_engine/sql`, in the `workers` area): a Cloudflare posture or task grant approved before it covers that route only once approved again. Moving the credential to another home, or the workspace becoming managed, puts it back to ask.

The vault reads the posture after standing rules and task grants, and only for a request the policy holds. It never covers a protected credential, a request with a query string, a credential holding a live key or anything the floor holds. A machine sees only how the posture applies to itself: `mehen show` prints `How careful: routine building allowed for this machine`, `this machine is trusted: changes go through except those that always ask` or `asks for every change`.

The home page's **Asking often** card names a credential that asked at least ten times this week with nothing denied, at least five of them routine building, with a link to its How careful card and **Not now**, which quietens it for seven days.

Postures are switched on per workspace, like standing rules, and never in a managed workspace. Where they are off, `mehen show` prints no How careful line.

## Mandates

A [mandate](mandates.md) is read last, after standing rules, task grants and the posture, and only for a request the policy holds. Its signer lets one of their own machines send held requests of the kinds named (read, change, send, delete), with the credentials named, within daily caps, until a date at most 90 days away. Unlike the other three, it covers sends and deletes, and services nobody has reviewed.

It never covers what the policy refuses, the floor's credential, persistence, sharing and money checks, a request the vault cannot read, a live key, a host only a wildcard in the binding admits, a protected credential, environment or run, a workload's request or anything in a managed or frozen workspace. On a service nobody has reviewed, the floor reads only the method, the path, the query names and the body's shape, so a mandate lets through what those do not name. Its daily caps, its rate trip at 120 requests beyond reading in a minute, and its signer's standing, checked at every use, bound the rest. Mandates are switched on per workspace, and never in a managed workspace.

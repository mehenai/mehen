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
| Credentials | Credentials ticked one by one, or every credential the machine can use whose home the signer manages, now and later | None ticked; `?items=all` on the link chooses every one |
| Kinds | `read`, `change`, `send` and `delete`; read is always included | All four |
| Caps | Requests a day for each kind ticked, counted per UTC day | 5000 reads, 2000 changes, 50 sends and 20 deletes; at most 50000, 10000, 500 and 200 |
| How long | 1, 7, 30 or 90 days | 90 days |
| When | At any time, or up to seven windows of days and hours in one time zone | At any time |
| What it is for | A note of up to 200 characters, seen by everyone who can see the machine | "Routine work on" and the machine's name |

A request may be in more than one kind: posting a message is a change and a send. Every kind it is in must be ticked, and each counts once against its cap, however many credentials the request uses. A cap counts requests, not amounts or recipients: 50 sends a day is 50 requests that send, to any number of people. Once a kind reaches its cap, those requests ask as they would with no mandate until the next UTC day, and the others carry on. The ask says which cap: "This machine's mandate has used today's 50 sends." More than 120 requests beyond reading in any minute **trips** the whole mandate: nothing goes through until its signer resumes it with a passkey, and the signer, owners and admins are told.

Choosing every credential includes credentials the machine can use later, and covers each one only while the signer manages where it lives. A schedule window runs from its start up to its end; one ending earlier than it starts runs past midnight and counts on the day it started. Outside every window, requests ask.

## What a mandate never covers

Whatever is ticked, these ask every time:

- minting or reading credentials, webhooks, forwarding, inbox rules, SSO, members, invites, permissions, sharing and publishing;
- money, and anything on a credential holding a live key;
- a request Mehen cannot read, one with a header that names its operation (`X-Amz-Target`, `SOAPAction`), and a method other than `GET`, `HEAD`, `POST`, `PUT`, `PATCH` or `DELETE`;
- anything the credential's policy refuses, or a destination that is not standard HTTPS;
- a host that only a wildcard in the credential's binding admits: the request's host must be one the binding names exactly;
- a protected credential, environment or run;
- a workload's request (a machine that acts only through workloads gets nothing from a mandate);
- anything in a managed or frozen workspace;
- reveal, lease, fill, push, connect and enrolment, which a mandate is never asked about.

A mandate is also only one of four things that let a held request through, and the last asked. A standing rule, task grant or posture that covers a request comes first, and that request is not a mandate use. When a request uses several credentials and one of them is covered by nothing, the request asks and nothing is spent.

### What "never" means on a service nobody has reviewed

On GitHub, Stripe and Cloudflare, the routes on their reviewed lists and the floors their templates name hold route by route; any other route there is judged as on a service nobody has reviewed. On a service nobody has reviewed, Mehen can only judge a request by its method, its path, its query parameter names, the value of one that names the method, and the floor's checks on its body: it asks for what those name and lets the rest through. So there, whether a `GET` is only a read is decided by the words in its address, on a best-effort basis: no list of words names every act. Telegram and Slack are the exception, decided by a method allowlist (below).

A request whose last path segment is a delete word, or whose segment before up to two IDs at the end, or before a last `all`, `bulk` or `many`, is (`POST /v1/tasks/7/delete`, `/archive`, `/purge`, `POST /v1/delete/7/8`, `GET /v1/delete/all`), is a delete, whatever its method. The delete words are the floor's, and `prune` and `clear` (Discord's `POST /guilds/1/prune`, Mastodon's `POST /api/v1/notifications/clear`). A `GET` whose last path segment is an action word is that act, never a read: `GET /v1/deleteMessage` is a delete, `/v1/editMessageText`, `/v1/logOut`, `/v1/upgradeGift` and `/api/conversations.join` changes, `/v1/forwardMessage` and `/api/chat.postMessage` a change and a send, and `/v1/answerInlineQuery` and `/api/chat.meMessage` sends. A word counts in any letter case, since a service such as Telegram reads a method name in any, and the capitals a sender chooses can only add a match, never take one away. A delete word counts anywhere in a run of letters (`deleteMessage`, `DELETEmessage`, `deletesTory`, `bulk-delete`, `bulkdeletemessages`, `deletemessage.json`), except at its start when all that follows is an inflection, alone or then `by`, `for`, `page`, `list`, `count`, `feed`, `summary` or `info` (`archived`), and in a few words that hold one (`presets`, `enforcement`, `salesforce`, `swipe`, `nuclear`, `clearance`). An act word counts at the start of a run when more than that follows it (`editmessagetext`, `postsTORY`), after `bulk`, `batch`, `mass`, `multi` or `un`, alone, inflected or followed by more (`bulkupdate`, `unpin`, `bulkupdatemessages`), or as a camelCase word of its own as sent. So `getUpdates`, `getStickerSet`, `/settings`, `/settingsPage`, `/posts`, `/postsList`, `chat.scheduledMessages.list` and `/repos/alex/postgres-tools/issues` stay reads, `getDeletedMessages`, `postsByUser` and Discord's `GET /guilds/1/prune`, which only counts, ask, and a last segment with a digit in it is an ID, never an action. A query parameter that names the method, `method`, `action`, `op`, `cmd`, `do` or `operation` in any letter case, names its act or delete in any part of its value, split at everything but a letter or a digit, not only in the last: `GET /services/rest?method=flickr.photos.delete` and `GET /api?action=delete_item`, `delete-item` or `deleteItem` are deletes, and `?action=edit_profile` a change. Its value is also read, part by part and camelCase word by word, for the words the floor reads in a path, on a `GET` only its verbs such as `send`, `publish` and `refund`, so `GET /http-api.php?action=sendsms` is a send; and one that acts and names access, such as `?action=set_acl`, `add_member` or `grant_access`, is sharing, which no mandate covers.

Telegram's Bot API and Slack's Web API put the method in the address and take every method on a `GET`, so for them Mehen decides by an allowlist of method shapes instead, read from the address the vault fetches, never from a header the agent sets. On `api.telegram.org`, a `GET` or `HEAD` of `/bot<token>/<method>` is a read only when the method, in any letter case, is `get` followed by letters (`getMe`, `getUpdates`, `getStickerSet`), and a file download under `/file/bot<token>/` is a read. On `slack.com` and its subdomains, a `GET` or `HEAD` of `/api/<method>` is a read only when the part after the last dot starts with `list`, `info`, `history`, `replies`, `get`, `lookup`, `search`, `members`, `profile`, `test`, `count` or `bots` (`conversations.history`, `users.info`, `chat.getPermalink`, `users.lookupByEmail`), or the method is in the `search` family (`search.messages`). Every other method there is a change, on any HTTP method (`setMyCommands`, `logOut`, `close`, `conversations.join`, `apps.uninstall`). A method that delivers content to a chat or alters what it sees is a send too, on any HTTP method: on Telegram one that starts with `send`, `forward`, `copy`, `answer`, `edit`, `post` or `gift`, and a few others such as `upgradeGift`, `stopPoll` and `setMessageReaction`; on Slack one whose part after the last dot starts with `postmessage`, `postephemeral`, `memessage`, `schedulemessage`, `share` or `invite`. So on these two services a mandate with only change ticked never covers a method that delivers or alters what a chat sees. The delete words still count (`deleteMessage` is a change and a delete), and so does the floor: its generic words make Telegram's `getChatMember`, `getChatMemberCount` and `getWebhookInfo` ask every time though they only read, a cost the floor sets, and they already made `unbanChatMember` and `exportChatInviteLink` ask. Slack's `chat.delete` on `slack.com` asks every time too, as the Slack template's floor holds it as a request Mehen cannot judge.

A route that sends money but whose path says nothing about money, on a service Mehen has never read, would go through as a change. On a service nobody has reviewed that names its methods in the address, as an RPC-style API does, sign a mandate with only reads ticked only with that in mind: a method that acts but whose name holds none of these words goes through as a read. The sign page says this in those words before the passkey: "On services nobody has reviewed, Mehen can only judge a request by its method, address and shape: it asks for what those name and lets the rest through." Choose the credentials and kinds with that in mind. Receipts name the service's reviewed route where there is one, and "on a service nobody has reviewed" where there is not.

## Who signs, pauses, resumes and stops

- **Sign:** only the person who owns the machine, a member who is not a guest, with a passkey that is always fresh (the [15-minute window](approvals.md#the-15-minute-window) never covers a signature). Each credential listed must be one they manage the home of and the machine can use. A team's machine or a guest's cannot have one yet: a team machine gets mandates signed by two people in a later version, and until then its routine work goes through a task grant. A machine has at most one live mandate (active, paused or tripped); signing a new one stops the old one in the same step.
- **Pause:** the signer, an owner or admin who can see the machine, or the machine itself (`mehen mandate pause`), any of its workloads included. No passkey: a pause only narrows. Pausing a paused or tripped mandate changes nothing, except that an owner's or admin's pause takes over one by the signer or the machine.
- **Resume:** the signer only, never the machine. When the signer or the machine paused it and nothing has changed since they signed, resuming needs no passkey. After an owner's or admin's pause it needs the signer's passkey, which the 15-minute window may cover. After a trip, or once it has lapsed (below), it needs a fresh passkey every time.
- **Stop:** the signer, or an owner or admin who can see the machine, with no passkey. Stop is final: to let the machine carry on later, someone signs a new one.

A mandate ends on its own at its end date. Three days before, its signer is told, and the page offers **Renew**; every ended mandate the signer could sign again offers **Sign again with these terms**, however long ago it ended.

## When the signer's standing changes

A mandate does not depend on the browser session that signed it: signing out, another browser or an expired session leave it as it was. Nor does it depend on the identity check that session passed under an identity gate: a mandate is standing authority, so the check reaching its expiry does not lapse it. The identity provider invalidating the signer's check, a change to the identity rule or a new gate generation does. At every use the vault checks again that the signer still stands where they stood when they signed: the same account and security, the same role, no cooling-off or pending account change, the machine still theirs and active, and the credential's home still one they manage. A mandate never reaches further than its signer could approve at that moment.

When that standing goes, the mandate **lapses**: it stays active on paper and covers nothing. Account recovery or another change to the signer's account security, such as signing out everywhere, a role change, a suspension, an identity rule change, the machine's scope widened, or losing management of a credential's home (their project share lowered from manage, removed or past its end date, leaving a team that manages its project or the team deleted, or the credential moved to a home they do not manage) each lapse it. Losing a project's management lapses only a mandate that lists a credential homed in that project, or lists all credentials while one is, and only when the signer no longer manages the project another way: an owner or admin manages every project by their role, and another share or team still counts. A share past its end date lapses the mandate even before the vault's sweep comes to it: a change to a team, a share, a member's role or standing, a credential's home, or a credential made or deleted first lapses what an ended share took, judged on access as it was before that change, so the change can neither hide the lapse nor restore management in its place. A mandate signed at or after the moment the share ended is not lapsed by it. A lapse is sticky: undoing its cause, such as reversing a demotion, does not restore it. Only the signer resuming it with a fresh passkey does. The signer gets a notice once per lapse ("The mandate you signed for build-box covers nothing now"), the machine's page and the mandate's page say it covers nothing until they resume it, and the home shows "1 machine needs you to resume its mandate". The machine is told only that the mandate is not covering requests, never why.

Revoking the machine ends its mandate for good, as a stop does, and so does removing its owner from the workspace or their leaving it, which revokes their machines. Its open proposals close, nobody is told it ends or asked to resume or renew it, and resuming it or signing the machine a new one is refused with `forbidden`: "This machine was revoked, so its mandate ended for good and it cannot have another. A machine enrolled again can."

**Sign out everywhere** on the account page lapses every mandate the person signed until they resume each with their passkey. Their machines stay enrolled. The confirmation says so before they press it.

## How a machine asks for one

The machine proposes; a person decides. `mehen mandate propose --note "<what it is for>"` (MCP `vault_mandate` with `action: "propose"`) prints an ask titled "Trust this machine" and exits 0. Nothing is covered by proposing. A team's or a guest's machine cannot propose one: the refusal is `forbidden`, with `next.command` naming `mehen policy propose --from`. The link opens the sign page on the proposed terms, which the person may change before signing. A proposal lasts 7 days.

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

An ask that only a cap held carries `mandate` with the caps reached instead. The person sees the same on the ask page: their own machine's ask offers "Let build-box carry on with requests like this", which opens the sign page with those kinds ticked, or a link to the mandate when it is paused or tripped.

## What people see

- **The sign page** (`/w/<slug>/sign-mandate`) offers each term, then, before the passkey, a summary of what is being signed in plain words, with the two sentences about reviewed and unreviewed services.
- **The mandates page** (`/w/<slug>/mandates`) lists proposals waiting, then live mandates, then ended ones. **Pause all** pauses every active mandate there the reader may pause, after a confirmation that gives the count; it needs no passkey, and says how many it could not pause, if any.
- **A mandate's page** shows its terms, today's counts against its caps, Pause, Resume and Stop for those who may press them, and **Went through on trust**: every request it let through, newest first, kept for 30 days. Its signer sees **Sign the same for** each of their other machines, which opens the sign page for that machine on the same terms (a list of credentials keeps only the ones that machine can use). There is no signature for several machines at once.
- **A machine's page** has the **Carry on without asking** card: its mandate with its controls, or **Trust this machine** for its owner.
- **The home** says "1 machine is carrying on without asking" while any mandate is active and its signer stands behind it, and how many need the reader to resume theirs.

Owners and admins are told when a mandate is signed. Its signer, owners and admins are told when one trips. Only the signer is told when one is about to end or has lapsed. Notices name the machine, the signer, the kinds and the end date, never a credential.

Everyone who may read a mandate sees its terms, state and counts. Each reader sees only the credentials they can see now, with "and 2 credentials you cannot see" for the rest. A receipt for a credential the reader cannot see says "a credential you cannot see" with the time, kinds and method, and nothing else.

## What the machine sees

A response a mandate let through carries `Mehen-Mandate: mdt_...`. `mehen fetch` adds "allowed without asking by this machine's mandate mdt_..." on stderr, and `mehen fetch --json` and `vault_fetch` carry `mandate`. `mehen status` shows the live mandate with today's counts against its caps, such as `mandate: mdt_...: active, change 3/200, send 1/50, ends 6 Feb`, and how many proposals wait for a signer. `mehen mandate show` reads one, and `mehen mandate uses` lists what went through on trust. A paused, tripped or ended mandate carries its page in `next.url`, for the agent to hand to the person. [Agent reference](../reference/agent-reference.md#mandates) has every flag and field.

## What is recorded

The audit records each proposal, signature, pause, resume, stop, trip, lapse (with its cause) and expiry, by machine and kind, never with a path. Each use on a shared credential is also recorded as `mandate.use` with the method, host and reviewed route; for a member's private credential, the receipt on the mandate's page is the record, and the audit keeps its usual private form.

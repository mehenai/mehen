---
title: Type a credential into a web page
question: How does an agent sign in to a page, or paste a key into a dashboard, without seeing the value?
section: guides
covers: both
order: 87
---

# Type a credential into a web page

Some work happens in a browser: signing in to a dashboard, typing a one-time code, pasting an API key into another service's settings page. `mehen fill` types one field of a credential into one field of the agent's own browser. The vault seals the value to this machine, `mehen` opens it in memory and types it after checking the page, and the agent gets back only what was typed where. It needs `mehen` 0.3.17 or later.

Fill is switched on workspace by workspace. Where it is off, `mehen fill` is refused with `forbidden`, "Typing into web pages is not available in this workspace.", and a credential page shows no In web pages card. A managed workspace has no fill: its platform cannot decide one yet.

## What the human sets up

Three things, each on a vault page with a passkey:

1. **The credential allows it.** On its page, the In web pages card. For a password login or a one-time code secret, **How agents may use it** is **Type it into the sign-in page** (the ceiling `fill`). For an API key, a token or a generic secret, the ceiling must allow fill (`fill` or `lease`).
2. **The page is listed.** A sign-in's pages are the origin of its sign-in address, each exact host it is bound to, and any the human adds under **Sign-in pages**. Any other service's page must be added under **May also be typed into**. Each is an https origin with no path, at most 8 in each list.
3. **The machine may fill.** Its scope's ways of using credentials include typing into web pages, proposed on the machine's page and accepted by its owner. The vault adds it only once the machine has run `mehen` 0.3.17 or later, since an older `mehen` cannot read a scope that includes it.

[Credentials](../concepts/credentials.md#in-web-pages) has the card in full.

## What the agent runs

```sh
mehen fill 'github-alex#username' --cdp http://127.0.0.1:9222 --selector '#login_field' --json
mehen fill 'github-alex#password' --cdp http://127.0.0.1:9222 --selector '#password' --json
mehen fill 'github-alex#totp' --cdp http://127.0.0.1:9222 --selector 'input[autocomplete=one-time-code]' --submit --json
```

- `<item>#<field>`: a `password-login`'s `username`, `password` or `totp`, a `totp` item's `code`, or the key, token or value of an `api-key`, `bearer-token` or `generic` item.
- `--cdp` is the browser's own DevTools endpoint: `ws://127.0.0.1:<port>/devtools/browser/<id>`, `http://127.0.0.1:<port>` or a `wss://` URL. `--user-data-dir <dir>` reads it from the profile's `DevToolsActivePort` instead.
- `--target <id>` names the page when the browser has more than one.
- `--selector` is a CSS selector for exactly one field; ` >>> ` steps into an open shadow root.
- `--submit` presses Enter in the field and waits up to 10 seconds for the page to go. If it does not go, `mehen` empties the field and exits with `not_submitted`.
- `--project <prj_id> --env <name>` names the context, as for `mehen fetch`, for a protected credential or one a team's or guest's machine reaches through a project.
- MCP: `vault_fill` with `item`, `field`, `cdp`, `selector`, and `target`, `submit`, `context` and `approval` as needed.

On success it prints `mehen: typed the password for alex@example.com into https://github.com/login`, and `--json` gives `{ typed, label, origin, page, submitted, navigatedTo, cleared }`. Never the value.

## What mehen checks before typing

Before it asks the vault anything, `mehen` checks in the page that the selector names exactly one field, of the kind the value is for (a password field for a password, a field for a code for a one-time code), visible and not covered, in a frame whose page and every frame above it share one https origin with a host name, not an IP address. A sign-in form embedded from another site is refused (`frame_origin_mismatch`): open the sign-in page itself. Then the vault checks that origin against the credential's lists, and refuses any other with `origin_mismatch`. `mehen` checks the page once more just before typing; if the page moved meanwhile it types nothing and answers `page_changed`.

Each refusal of fill's own (`cdp_unreachable`, `cdp_refused`, `target_ambiguous`, `field_not_found`, `field_ambiguous`, `field_kind_mismatch`, `field_hidden`, `frame_origin_mismatch`, `page_changed`, `not_submitted`) has its entry in [Errors and exit codes](../reference/errors.md).

## Approvals

- **A sign-in's username** is typed without asking.
- **Any other field of a sign-in** asks first. One approval covers that credential's sign-in fields on that page: up to 6 fields in all, within 10 minutes. The card reads "Type the password for alex@example.com into github.com".
- **Another service's page** asks every time: one approval types once, within 10 minutes. The card warns that this puts the credential into another service.

An approval works as for any request ([When a request needs approval](approvals.md)): exit 3 with the ask, write the block, `mehen wait <apr_id> --timeout 60 --json`, then run the same `mehen fill` again with `--approval <apr_id>`.

## One-time codes

The vault makes a one-time code from the stored secret at the moment of the fill, by its own clock, so the secret never leaves the vault. Each time step's code goes to one origin only, whichever machine asked, and a machine gets at most three codes for one credential in one time step; after that, wait for the next code. A secret the vault cannot read as a one-time code secret is refused with `totp_unreadable`.

## Limits

Per machine and credential, 20 secret fields and 20 one-time codes an hour; per machine, 60 fills of any field an hour. A fill over a limit is `rate_limited` with `retryAfter`. Every fill is audited with the machine, the task, the origin and the field, never the value, and so is a fill refused for its page, its limit or an unreadable code.

## What fill never does

- Print, log or write the value, or hand it to the agent in any output.
- Type into a page that is not on the credential's lists, over http, at an IP address, or in a frame from another origin.
- Type into a field it cannot see, a field of the wrong kind, or one of several fields the selector matches.
- Leave a value in a field after `--submit` failed: it empties the field and says whether that worked (`cleared`).
- Add a page or change a ceiling. Only a person does that, with a passkey.

## The honest limit

Fill keeps the value out of the agent's transcript, its screenshots and lookalike pages. It cannot keep the value from the page once it is typed: a script on that page, including one the agent runs in its own browser, can read the field before the form is sent. Fill is opt-in for that reason, credential by credential. For a credential no agent should be able to read at all, leave **How agents may use it** at **Not at all**.

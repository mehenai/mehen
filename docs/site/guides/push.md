---
title: Put a credential into another service
question: How does an agent get a secret into GitHub Actions, Vercel or a Cloudflare Worker without seeing the value?
section: guides
covers: cloud
order: 88
---

# Put a credential into another service

A deploy often needs a secret in another service's own store: an Actions secret for a workflow, a Vercel variable for a build, a Worker secret. `mehen push` asks a human to let the vault put one secret field there. Once the human approves, the vault reads the value and calls the provider itself. The value never reaches the agent's machine, and the agent gets back only where it went. It needs `mehen` 0.3.18 or later.

Use it instead of leasing the value with `mehen run` or typing it into the provider's dashboard with `mehen fill`.

Push is switched on workspace by workspace. Where it is off, `mehen push` is refused with `forbidden`, "Pushing is not available yet.", and a credential page shows no Other services' secret stores card. A managed workspace has no pushing: it is refused with `forbidden`, "Pushing is not available in a managed workspace."

## What the human allows

Two credentials take part: the one pushed, and the provider credential that writes it (a GitHub token or connection, a Vercel token or a Cloudflare API token).

1. **The credential may be pushed.** On its page, under **Other services' secret stores**, a person who may change the credential ticks **May be put into other services' secret stores** and saves with a passkey. It is off until then. An OAuth client or connection is never pushed, and neither is a kind whose ceiling can never reach `lease`, such as an SSH key or a GitHub App.
2. **The machine may use both.** The machine must be able to use the pushed credential and the provider credential through the relay, as for any request. A push counts as handing the value out, so a machine whose owner is cooling off after an account recovery is refused.
3. **The provider credential reaches the provider.** Its bound hosts must cover the provider's API (`api.github.com`, `api.vercel.com` or `api.cloudflare.com`), and its policy must not deny the calls the push makes.

[Credentials](../concepts/credentials.md#other-services-secret-stores) has the allowance in full.

## What the agent runs

```sh
mehen push openai-prod --to github:acme/app/OPENAI_API_KEY --reason 'the evals workflow calls OpenAI' --json
mehen push 'openai-prod#key' --to github:acme/app/env/production/OPENAI_API_KEY --with github-pat-ci --json
mehen push stripe-prod --to vercel:shop@acme/production/STRIPE_SECRET_KEY --json
mehen push resend-key --to cloudflare:0123456789abcdef0123456789abcdef/mailer/RESEND_API_KEY --json
```

- `<item>` pushes the kind's main secret field; `<item>#<field>` names another, and a kind with no main field (a one-time code secret, a note) must name one. A value over 64 KiB is refused with `too_large`.
- `--to` is one destination. `mehen` prints the destination as the vault will read it before it sends anything.
- `--with <item>` names the provider credential that writes it. Without it, the vault uses the one this machine may use for that provider, and answers `ambiguous` with `choices` when there are several.
- `--reason` is the agent's own words, shown to the human as such. The vault checks none of it.
- `--wait` waits for the human in the same process, as `mehen request --wait` does.
- MCP: `vault_push` with `item`, `field`, `to` as the destination's JSON, `with` and `reason`.

The answer is exit 3, `approval_required`, with the ask. Write the block, then `mehen wait <apr_id> --timeout 60 --json`. The same push done by this machine in the last ten minutes answers at once with what was done, and asks no one.

## Destinations

| Destination | Where it goes |
| --- | --- |
| `github:<owner>/<repo>/<NAME>` | A GitHub Actions repository secret |
| `github:<owner>/<repo>/env/<environment>/<NAME>` | A GitHub Actions secret for one environment |
| `github:<owner>/<repo>/dependabot/<NAME>` | A GitHub Dependabot secret |
| `vercel:<project>[@<team>]/<production\|preview\|development>/<NAME>` | A Vercel environment variable for one target |
| `cloudflare:<account id>/<script>/<NAME>` | A Cloudflare Worker secret; Cloudflare deploys the Worker again with it |

The vault reads every part in one canonical form. Owners, repositories, environments, projects, teams, accounts and scripts are lower case, except a Vercel `prj_` or `team_` id, which keeps its case. A GitHub secret's name is upper case and may not start with `GITHUB_`; any other name keeps its case. A destination is ASCII only. MCP takes the same destination as JSON, already canonical ([Agent reference](../reference/agent-reference.md#push-destinations)).

## What the human approves

Every push asks a human, every time, on the ask's own page. The card says where the value goes and what the provider said about that place before anyone decided: whether the secret is already there, whether a GitHub repository is public or a fork, and **New destination** when this workspace has never pushed to that owner and has not bound the repository to a project. It names the store, the secret's name, the value's version, the credential that writes it, and who can read the secret there. It warns that Mehen cannot take a push back.

Approving takes a passkey, which signs the exact destination, the value's version and both credentials' settings. A push is approved once, as asked: no standing rule, task grant or posture covers one, and it is decided only on its own vault page, never in **Review together**. Who may approve is whoever may approve the credential's other requests; a private provider credential narrows that to its owner, and a credential a protected environment needs four eyes for needs a second person ([Approvals](../concepts/approvals.md#pushes)).

## After the approval

The vault sends the push at once and `mehen wait` follows it to its end:

- **Done:** exit 0, `Pushed: <where>: created`, `replaced` or `set` (version N). `--json` gives the approval with `push.state` `done` and `push.outcome`.
- **The provider refused:** exit 5, `provider_refused` with `providerStatus`, the provider's HTTP status. The token may not write there, cannot see the place, or the name was rejected.
- **Not sent, or not confirmed:** exit 1, `failed`. The vault did not send it because something changed first, or it could not tell whether the provider wrote it; check the provider.

The approval is spent either way. Do not push again unless the human asks.

A push is not sent if, between the approval and the send, either credential changed, the allowance was turned off, the workspace was frozen, the machine was revoked or its access changed, another push to the same place was being sent, or two minutes passed. An ask still waiting goes stale when either credential's value or settings change: ask again.

## What is recorded

- **The audit** records each push's end, `push.done`, `push.failed`, `push.not_sent` or `push.unknown`, with the destination, the value's version, the provider credential unless it is private, the outcome or the provider's status, and the approval. A private credential's push is a private event of its owner.
- **The credential page** lists, under **Pushed to**, the latest push to each place: its state, the version, the credential that wrote it where the viewer may see it, and when. `mehen show <item>` lists the same places, without the credential that wrote it or who pushed.
- **Exposure:** a push that was done, or may have been, counts the value as having reached the machine's owner, as a lease does, so removing that member counts it among the values they had.

None of it holds the value.

## Pushing a new value again

After a rotation, the credential's **Pushed to** card offers to put the current value into the places that still hold an older one. A person who may change the credential ticks each place and signs once with a passkey for up to 25. The same provider credential writes each one again. A credential a protected environment needs four eyes for is pushed again only from a machine's ask, so a second person decides.

## What push never does

- Hand the value to the machine that asked, print it or put it in any answer.
- Push without a person's approval, or turn the allowance on. Only a person does either, with a passkey.
- Remember an approval: a push is never covered by a rule, a task grant or a posture.
- Push an OAuth client or connection.
- Take a push back. Deleting the credential removes it from Mehen only; the copies stay in the provider until someone removes them there.

# Security

Mehen holds credentials for people and their agents, so we take reports seriously and want to hear about anything you find.

## Reporting a vulnerability

Email [security@mehen.dev](mailto:security@mehen.dev). Please do not open a public issue, a pull request or a discussion about it first.

Include what you found and what an attacker could do with it, the steps to reproduce, and the affected part: the `mehen` command line (with `mehen version --json`), a local vault (`mehen serve`), Mehen Cloud at `https://app.mehen.dev`, the docs or the site. Never send a credential value, yours or anyone else's.

While you look, use only your own accounts, vaults and keys, do not degrade Mehen Cloud for others, and give us reasonable time to fix the problem before you disclose it. We acknowledge every report and keep you informed while we fix it. There is no bug bounty.

## Supported versions

Fixes go into the latest release of the `mehen` command line and into Mehen Cloud. Installed copies update themselves from signed releases; `mehen update` takes the latest now.

## How Mehen is meant to protect you

The threat model, what each way of running Mehen protects against and what it does not, is at [docs.mehen.dev/security/threat-model](https://docs.mehen.dev/security/threat-model). How keys are encrypted, how machines prove who they are, and how releases are signed is at [docs.mehen.dev/security/keys-and-signing](https://docs.mehen.dev/security/keys-and-signing).

---
title: Reporting a vulnerability
question: How do I report a security problem?
section: security
covers: both
order: 30
---

# Reporting a vulnerability

If you think you have found a security problem in Mehen, email [security@mehen.dev](mailto:security@mehen.dev). Please do not open a public issue or post the details anywhere else first.

## What to include

- **What you found**, and what an attacker could do with it.
- **Steps to reproduce**: the requests, commands or pages involved, and what you saw.
- **The affected surface**: the vault at `https://app.mehen.dev`, the `mehen` command line or its MCP server, the docs at `https://docs.mehen.dev`, or the site at `https://mehen.dev`. Name the `mehen` version (`mehen version --json`) when the command line is involved.
- **How to reach you**, if not the address you write from.

Never send a credential value, yours or anyone else's. If a report needs one to make sense, say so and we will agree a safe way.

## While you look

- Do not access, change or delete other people's data. Use your own account, workspace and credentials; if you reach someone else's data by accident, stop and tell us what you saw.
- Do not degrade the service: no denial-of-service testing, load testing or automated scanning that disrupts it.
- Give us reasonable time to fix the problem before you disclose it publicly.

## What happens next

We acknowledge your report and keep you informed while we look into it and fix it. We cannot promise a response time. There is no bug bounty, and we offer no legal safe harbour.

The same contact is published at `https://app.mehen.dev/.well-known/security.txt`, `https://docs.mehen.dev/.well-known/security.txt` and `https://mehen.dev/.well-known/security.txt`.

## What and why

<!-- What this changes, and the problem it solves. -->

## What does not change

<!-- Anything a reviewer might expect to be touched and is not. -->

## Security

<!-- For changes to the vault, the local host, the relay, the protocol, the hooks or access rules: what an attacker could do before and after. Otherwise "No security impact", with the reason. -->

## Checks run

<!-- The exact commands and their results, for example `bun test packages/protocol` (812 pass). -->

## For a new or changed service template

- [ ] Every host, the header and each allowed write are linked to the provider's own documentation
- [ ] The binding is as narrow as the API allows
- [ ] `bun test packages/protocol` passes

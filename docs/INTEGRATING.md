# Integrating

For contributors: how to add a provider template, and the helpers planned for tools that have their own credential hooks. How an agent harness plugs in is public, on https://docs.mehen.dev/guides/harnesses and https://docs.mehen.dev/reference/ask; the policy model a template follows is https://docs.mehen.dev/concepts/policy.

## Adding a provider template

A provider template tells the vault where a provider's credential may go, how it goes into a request, which endpoints are sensitive, and what the intake form should say. Templates are **data, never code**. An agent can only name one (`mehen request --provider`, `mehen connect <provider>`); the human sees what it fixes. New templates arrive by code review.

There are two shapes: `TEMPLATES` for credentials a human pastes in (API keys and OAuth clients), and `OAUTH_PROVIDERS` for connections a human signs in to.

### Where they live

- `packages/protocol/src/templates/<id>.ts`: one file per template or OAuth provider, named by its id, exporting exactly one `Template` or `OAuthProviderTemplate` (as `export const <camelCaseId>`, with a `Template` suffix where that is a reserved word: `class` exports `classTemplate`). A helper only that template uses (Gmail's path prefix, Graph's action spellings) stays in its file.
- `packages/protocol/src/templates/shared.ts`: what more than one file uses: `BEARER()`, `READS`, `WRITES`, `ALLOW_READS`, `MODEL_CALLS`, GitHub's `githubPaths`, `GITHUB_ALLOWED` and `GITHUB_SENSITIVE`, Google's `GOOGLE_AUTH`, `GOOGLE_IDENTITY`, `GOOGLE_REFRESH` and `GOOGLE_LIFETIMES`, `ACCESS_TOKEN_BEARER` and `CLIENT_SETUP_CALLBACK`.
- `packages/protocol/src/templates.ts`: the index. It holds the types, `TEMPLATE_CATEGORIES`, `getTemplate`, `getOAuthProvider`, `connectionPolicy` and `normaliseScope`, imports each file and registers it in `TEMPLATES` or `OAUTH_PROVIDERS`. Everything outside the protocol imports `@mehen/protocol/templates` and nothing else. The order of the two records is the order `mehen templates`, Connect a service and the providers reference list them in, within each category.
- `packages/protocol/src/templates/<id>.test.ts`: a template's own cases, beside it.

`templates-registry.test.ts` fails when a file in `templates/` is not registered, is registered under another id or exports more than one thing, when a registered id has no file, and when a test has no template beside it.

### Start one with the scaffold

From anywhere inside a checkout:

```sh
mehen templates new acme --host api.acme.com --category productivity --docs https://acme.com/settings/api-keys
mehen templates new acme --host api.acme.com --path "/v2/**" --header X-Api-Key --format "{key}" --prefix acme_ --category ai --name "Acme API key"
```

It writes `templates/<id>.ts` with the safe defaults (kind `api-key`, the exact hosts given, `paths` when `--path` is given, the injection from `--header` and `--format`, `Authorization: Bearer {key}` without them, reads allowed and every other method `approve`, ceiling `placeholder`, a `key` field whose pattern anchors on the prefixes), `templates/<id>.test.ts` with the binding and policy cases below, the import and the entry in the index (the entry goes last in `TEMPLATES`), and, for a `--prefix` that is new, the prefix in `KNOWN_PREFIXES` in `placeholder.ts`. It then prints the files and `bun test packages/protocol`.

It refuses an id that exists, is reserved (`new`, `shared`, `custom`) or does not match `^[a-z][a-z0-9-]{1,40}$`; a host that is not a plain lower-case DNS name; a docs URL that is not https; a reserved header; a format without exactly one `{key}`; a missing `--category` or `clients`. Outside a checkout (no `package.json` called `mehen` above the current folder) it refuses and says so. Nothing is written until every check has passed.

What it writes is a starting point, not a finished template: read the provider's documentation, then add the allow rules for its everyday writes, the deny and approve rules for its sensitive routes, a `check`, `setup` steps where making the key is not obvious, and a test case for each, as the rest of this section describes. For anything other than an API key (an OAuth client, an OAuth provider, another kind), copy the closest existing file instead.

### Credential templates

```ts
type Template = {
  id: string                         // "openai", "github-pat": what agents pass as --provider
  displayName: string                // shown on the intake page
  kind: ItemKind                     // one of the closed list in kinds.ts; an intake must ask for this kind
  category: TemplateCategory         // its section on Connect a service and in mehen templates (TEMPLATE_CATEGORIES)
  docsUrl: string | null             // where the human gets the credential, always https
  binding: BindingInput              // where it may go; see binding.ts
  injection: Injection | null        // how it goes into a request; null if only the vault itself uses it
  policy: PolicyInput                // allow, approve, deny; deny over approve over allow
  ceiling: Mode                      // the ceiling for items made from it
  fields: Record<string, FieldHint>  // label, hint, pattern, multiline per field
  prefixes?: string[]                // well-known value prefixes; the intake form warns when missing
  setup?: Setup                      // numbered steps the intake page shows, where making the key is not obvious
}
```

`templates/anthropic.ts` exports this (the policy follows the model below):

```ts
export const anthropic: Template = {
  id: "anthropic",
  displayName: "Anthropic API key",
  kind: "api-key",
  category: "ai",
  docsUrl: "https://console.anthropic.com/settings/keys",
  binding: { hosts: ["api.anthropic.com"] },
  injection: { in: "header", name: "x-api-key", format: "{key}" },
  policy: { default: "...", rules: [/* reads, model calls; the admin API denied */] },
  ceiling: "placeholder",
  fields: { key: { label: "API key", pattern: "^sk-ant-" } },
  prefixes: ["sk-ant-api03-", "sk-ant-"],
}
```

An `oauth-client` template (`google-oauth-client`, `github-oauth-client`, `microsoft-oauth-client`) has `injection: null` and a binding that covers only the provider's token endpoints, so the client secret can go nowhere else.

### OAuth provider templates

An `OAuthProviderTemplate` fixes everything the vault sends a client secret, a code or a token to:

- `clientTemplate`: the credential template the `oauth-client` item must have been made from;
- `auth`: authorise and token URLs, PKCE, client authentication, scope separator, identity scopes, default and allowed scopes, extra authorise parameters, how to read the token response;
- `identity`: where the verified account comes from (an `id_token`, or a request to a fixed URL) and which fields are the stable subject, the provider's own tenant or organisation id, and the label;
- `upstream`: the API's base URL, binding and injection, so the connection can reach nothing else;
- `refresh`: refresh mode, rotation behaviour, safety margin, and which error codes are terminal or blame the client;
- `lifetimes`, `defaultPolicy` and `sensitiveEndpoints`, combined into the connection's policy by `connectionPolicy`.

The providers today are `google-gmail`, `google-calendar`, `google-drive`, `github-oauth` and `microsoft-graph`.

### The policy model

Templates fail closed:

- reads (`GET`, `HEAD`) are allowed, except a read that hands back another secret (a database password, a decrypted variable, a stored secret), which is `approve`;
- every other method needs a human's approval by default;
- a few narrow everyday writes are allowed explicitly, each with a `note` saying why it is safe enough;
- the worst routes are denied outright: anything that sends mail or data elsewhere for good, gives someone else access, mints tokens, or cannot be shown honestly on an approval card (a batch, or a send of something stored by id that could change after approval).

Where a request's meaning is in its body (GraphQL), a rule names a body matcher from `body-match.ts`; matchers fail closed. The exact rules are in each template's file; read the existing templates before writing a new one.

### Rules a reviewer checks

1. **Written from the provider's own documentation.** Never copy provider data, regexes or settings from Nango (Elastic Licence 2.0). `grant`'s MIT data and `golang/oauth2` endpoints may be used as a cross-check, with their notices kept.
2. **The narrowest binding that works.** Exact hosts, not wildcards, unless the provider really serves from many names. Add `paths` and `methods` when the API lives under one prefix (`cloudflare-api-token` binds `/client/v4/**`; `linear` binds `POST /graphql`). Never plain `http`. Never a host the template author cannot vouch for.
3. **Hosts must not move.** If a provider's host depends on the account (Salesforce `instance_url`, Zendesk subdomains), the host must come from a validated input or a captured value that matches a pinned pattern. A token response can never choose the destination.
4. **The injection matches the provider's documented header.** `Authorization: Bearer {key}`, `x-api-key: {key}`, Linear's bare `{key}`. A query parameter only when the provider accepts nothing else.
5. **The policy follows the model above.** Every explicitly allowed write is narrow and has a `note`. Anything that creates persistence or moves money, mail or credentials is `approve` or `deny`: SSH and deploy keys, webhooks, token minting, mail forwarding, filters and send-as, mailbox rules, app registrations, collaborators and invitations, Actions secrets, payouts, refunds, transfers, every token endpoint. Anything an approval card could not show honestly is `deny`, with a note naming the alternative.
6. **The lowest ceiling that works.** `placeholder` for keys SDKs read from the environment, `relay` for anything else HTTP, never `lease` or `reveal` by default for an HTTP API.
7. **Prefixes are public, well-known prefixes only** (`sk-proj-`, `ghp_`), never characters that would narrow a guess at the secret. If a prefix is new, also add it to `KNOWN_PREFIXES` in `placeholder.ts` so placeholders keep the shape SDKs check for. Template prefixes also feed the check that refuses secret-looking plain variables.
8. **No new kinds by template.** If no kind fits, adding one is a separate code review of `kinds.ts`.

### Tests

`packages/protocol/src/templates.test.ts` checks every template and provider the same way, so a new one is held to these rules without a line of test: a category, https docs, exact hosts, a default of `approve`, an unlisted write that needs an approval, an allow rule for a write that names its paths, a note on every rule, every deny and approve rule reachable inside the binding, prefixes that fit the field's pattern and are in `KNOWN_PREFIXES`. On top of that, the template's own `templates/<id>.test.ts` (the scaffold writes the first cases) proves, with `bun test packages/protocol`, that the binding accepts the provider's real endpoints and refuses neighbours (a look-alike host such as `api.example.com.evil.test`, plain `http`, another path prefix), that reads pass, that each allowed write is allowed, and that each held or denied route evaluates to `approve` or `deny` with `evaluatePolicy`, including spellings with escapes and odd case. Server-side template and approval behaviour is covered in `apps/vault/test/l3-templates.test.ts` and `h4-approvals-templates.test.ts`.

## Helpers for tools with their own credential hooks

Planned, not built yet. Each helper would speak the tool's documented credential protocol and hand back the shortest-lived thing that works. The command names are provisional.

| Tool | Hook | What the helper returns |
| --- | --- | --- |
| git (HTTPS) | `git config credential.helper "!mehen git-credential"` | A minted GitHub App installation token for the requested repository, if the device's scope covers it |
| Docker | `credHelpers` in `~/.docker/config.json` naming `docker-credential-mehen` | A registry token for the bound registry |
| AWS CLI and SDKs | `credential_process = mehen aws-credential-process <item>` in `~/.aws/config` | STS credentials with a short expiry |
| kubectl | client-go `exec` credential plugin (`mehen kube-exec`) | A short-lived token or certificate |
| npm, pip, cargo | `mehen run` with a placeholder in the registry token variable, plus the local relay | Swapped on the wire, bound to the registry host |
| SSH | `SSH_AUTH_SOCK` pointed at `mehen ssh-agent` | Signatures, never the key; preferably 5-minute certificates from a vault SSH CA |

Notes:

- These need the `sign` and `mint` rungs, which are not built either.
- Until the helpers exist, use `mehen run` for tools that read a token from the environment and `mehen fetch` for API calls.
- Non-HTTP tools without a hook (`psql`, SMTP clients) use lease mode through `mehen run`, only where a human set the item's ceiling to `lease` and the device allows it. Local protocol connectors for Postgres, also planned, would remove the need for the value.

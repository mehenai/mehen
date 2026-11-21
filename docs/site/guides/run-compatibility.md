---
title: Which programs work with mehen run
question: Which runtimes and HTTP clients work with placeholders under mehen run, which do not, and what do I use instead?
section: guides
covers: both
order: 91
---

# Which programs work with mehen run

When the vault delivers a variable as a **placeholder**, the program never holds the key. `mehen run` starts a local relay on 127.0.0.1, points the program at it with the proxy variables, and gives it a CA for the hosts the key is bound to. The program's request to one of those hosts goes to the relay, the relay hands it to the vault with the placeholder intact, and the vault puts the real key in on the way out ([Projects, environments and runs](../concepts/projects.md#placeholders)).

That only works when the program's HTTP client does two things:

1. **It sends HTTPS through `HTTPS_PROXY`** (or `https_proxy`). `mehen run` sets both, with `HTTP_PROXY`, `http_proxy`, an empty `NO_PROXY`, and `NODE_USE_ENV_PROXY=1` for Node.
2. **It trusts the run's CA** from one of the variables `mehen run` sets: `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `AWS_CA_BUNDLE` and `DENO_CERT` name a bundle of the system roots plus the run CA; `NODE_EXTRA_CA_CERTS` names the run CA alone.

A client that skips the proxy sends the placeholder straight to the API, which answers 401: the call fails, and the real key was never on the machine. A client that reaches the relay but does not trust the CA fails its TLS handshake.

## What works

Checked with `mehen run`'s own relay on Linux, each client calling a bound host through `HTTPS_PROXY` with no extra settings:

| Client | Version checked | Notes |
| --- | --- | --- |
| curl | 8.18 | Reads `HTTPS_PROXY` and `CURL_CA_BUNDLE`. |
| Bun `fetch` | 1.4 | |
| Node `fetch` and `node:https` | 24.22 | Needs `NODE_USE_ENV_PROXY`, which `mehen run` sets. See [Node versions](#node-versions). |
| Python `requests` | 2.34 | Reads `REQUESTS_CA_BUNDLE`, not the bundled `certifi` roots, when it is set. |
| Python `httpx` | 0.28 | Reads `SSL_CERT_FILE`. |
| Python `urllib.request` | 3.14 | |
| Go `net/http` | 1.27 | The default transport reads `HTTPS_PROXY`, and `crypto/x509` reads `SSL_CERT_FILE`. |
| git over HTTPS | 2.53 | Reads `GIT_SSL_CAINFO`. |

Not tested, but the client's own documentation says it reads these variables:

- **The AWS CLI** reads `AWS_CA_BUNDLE` for the CA bundle and `HTTPS_PROXY` for the proxy.
- **Deno** reads `DENO_CERT` for extra CAs and `HTTPS_PROXY` for `fetch`.
- **gh** is a Go program using `net/http`, so it should behave as Go does. Not tested.
- **Go on macOS before 1.27** verifies with the system's own APIs and ignores `SSL_CERT_FILE`, so it fails the handshake. From 1.27, `SSL_CERT_FILE` takes over, as on Linux.

### Node versions

Node uses the proxy variables only with `NODE_USE_ENV_PROXY=1`, and only from these versions, as Node's own documentation gives them (the `NODE_USE_ENV_PROXY` entry of its command-line page and Built-in Proxy Support in its HTTP page):

| Node | `fetch` | `node:http`, `node:https` and libraries built on them |
| --- | --- | --- |
| 22.21.0 and later on 22 | yes | yes |
| 24.0.0 to 24.4.x | yes | no |
| 24.5.0 and later, 25 and later | yes | yes |
| 23, 22.20 and older, 20, 18 | no | no |

When a run has placeholders and its command is `node`, `npm`, `npx`, `pnpm`, `yarn` or `tsx`, `mehen run` asks the `node` on the child's `PATH` for its version and warns when it is older than these. It never stops the run.

## What does not work

- **HTTP/2-only clients, such as most gRPC libraries.** The relay speaks HTTP/1.1 to the program on an intercepted host and does not carry protocol upgrades, WebSocket included. gRPC-Web over HTTP/1.1 goes through.
- **Anything that is not HTTP:** Postgres, MySQL, Redis, AMQP, SMTP and other protocols with their own wire format. A placeholder in a database URL goes nowhere the vault can swap it.
- **Clients with pinned certificates or their own root store** that ignore the variables above. They reach the relay and fail the TLS handshake.
- **Clients that ignore the proxy variables**, or that set `NO_PROXY` again for the API host. The placeholder goes straight to the API.
- **Plain HTTP to a bound host** with a placeholder in it is refused by the relay: placeholders only go over HTTPS.

## What to use instead

For a program that cannot use the relay, the variable needs the real value, which is **lease** delivery: the value goes into this one child process only, and its stdout and stderr pass through the redactor. The vault decides the delivery, not the program: a lease needs an item whose ceiling is `lease`, a machine allowed leases and, for a protected environment, an approved run ([Leases](../concepts/projects.md#leases)). Database URLs and other program secrets are added that way, as **Database URL** or **Other secret** in the web app.

## The warnings mehen run prints

`mehen run` warns on stderr, once each, and never stops the run:

- **A `.env` or `.env.*` file next to the run**, in the folder of `mehen.toml` or the working folder (`.env.example`, `.env.sample` and `.env.template` are left out). Bun, Next.js, Vite, dotenv and others load it by themselves, so the program can read the old plaintext value instead of the vault's. Move its keys in with `mehen adopt file <path>`, then take it out of play with `mehen adopt retire` ([Bring a machine's credentials into Mehen](adopt.md)).
- **A Node too old for `NODE_USE_ENV_PROXY`**, as above.
- **No connection to any bound host came through the relay.** When a run with placeholders ends and the program never connected to a host the placeholders are bound to, either it did not call that API, or its client skipped the proxy. Not printed for runs with only plain values, leases or base URLs, nor after a Ctrl-C or a stop `mehen run` passed on.

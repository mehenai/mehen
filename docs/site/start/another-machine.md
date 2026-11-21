---
title: Run it on another machine
question: How do I keep the vault on a machine I own, and enrol my other machines in it?
section: start
covers: local
order: 30
---

# Run it on another machine

The vault can live on a machine you own that is not the one your agents run on: a small server at home, a spare desktop, a box on your Tailscale network. The agent's machine then holds only its own device key, and the vault's files are on a machine the agent has no shell on. It is the same vault as on [your own machine](../start.md), started with `mehen serve` and given an https name.

You need that machine to run macOS, or Linux with glibc, and a way to put TLS in front of it: Tailscale serve, Caddy or another reverse proxy. A passkey works only in a secure context, so a vault other machines reach must be https.

## 1. Install and start the vault

On the vault's machine:

```sh
curl -fsSL https://mehen.dev/install | sh
mehen serve --origin https://vault.example.com
```

Use the name people will open, with no path. With `--origin`, the vault takes that name as its address and as the passkeys' site, answers only requests addressed to that name, and still listens on `127.0.0.1:7787` unless you say otherwise, so only the proxy on the same machine reaches it. `--port` changes the port, `--data` the data folder, which must be open to the vault's user alone, (by default `~/.local/share/mehen/vault` on Linux and `~/Library/Application Support/Mehen/vault` on macOS) and `--bind` the address it listens on, for a proxy on another machine.

`mehen serve` runs until you stop it with Ctrl-C. It prints the vault's address and data folder, and, while the vault has no account, where to find the one-time sign-up code. `--json` prints one line, `{ origin, data, bootstrap, dumpable }`, once it is listening; on Linux `dumpable` is `off` when the process has stopped other programs reading its memory.

## 2. Put TLS in front of it

**Tailscale.** On the vault's machine, with Tailscale signed in and HTTPS certificates turned on for your tailnet:

```sh
tailscale serve --bg 7787
```

The vault is then at `https://<machine name>.<your tailnet name>.ts.net` on every device in your tailnet, and nowhere else. Start `mehen serve` with that address as `--origin`.

**Caddy.** On a name you control, with a certificate Caddy gets for it:

```
vault.example.com {
	reverse_proxy 127.0.0.1:7787
}
```

Whatever the proxy, it must pass the request's own `Host` on to the vault, as both of these do: the vault refuses any request addressed to another name.

## 3. Keep it running

`mehen serve` in a terminal stops when the terminal does. Run it under the machine's service manager instead. On Linux, a systemd user unit at `~/.config/systemd/user/mehen-vault.service`:

```ini
[Unit]
Description=Mehen vault
After=network-online.target

[Service]
ExecStart=/home/you/.local/bin/mehen serve --origin https://vault.example.com
Restart=always
UMask=0077

[Install]
WantedBy=default.target
```

```sh
systemctl --user enable --now mehen-vault.service
loginctl enable-linger "$USER"
```

The second command starts your user's services when the machine boots, before anyone logs in. Give the vault its own user account on that machine if other people or programs use it: anything running as the vault's user can read its files ([the threat model](../security/threat-model.md#a-vault-on-your-own-machine)).

### Or run it in Docker

Each release from the next one on publishes an image, `ghcr.io/mehenai/mehen`, for linux/amd64 and linux/arm64, tagged with its version and `latest`, with build provenance and an SBOM attached. It runs `mehen serve` as an unprivileged `mehen` user against a `0700` data volume, and does not update itself: pull a newer tag to update. The repository's `compose.yaml` runs it with a read-only root filesystem, no capabilities and the port bound to `127.0.0.1`.

With an existing reverse proxy on the host (Tailscale serve or your own Caddy):

```sh
git clone https://github.com/mehenai/mehen && cd mehen
MEHEN_SERVE_ORIGIN=https://vault.example.com docker compose up -d
```

Or with bundled automatic HTTPS from Caddy (ports 80 and 443 open to the host):

```sh
MEHEN_SERVE_ORIGIN=https://vault.example.com docker compose --profile caddy up -d
```

`docker compose up` pulls `ghcr.io/mehenai/mehen:latest`, and builds the image from the checkout only when it cannot pull it. Add `--build` to run what the checkout holds instead. To update, `docker compose pull` and then `docker compose up -d` again; the vault's data stays in the `mehen-data` volume.

Check an image was built by Mehen's release workflow before you run it:

```sh
gh attestation verify oci://ghcr.io/mehenai/mehen:latest --repo mehenai/mehen
```

Then read the one-time sign-up code from the container's volume and continue at step 4:

```sh
docker compose exec mehen cat /data/vault/bootstrap
```

## 4. Make your account

While the vault has no account, it keeps a one-time code in the file `bootstrap` in its data folder, readable only by the vault's user. Read it on the vault's machine and open the sign-up page from any device that reaches the vault:

```
https://vault.example.com/signup#<the code>
```

Make your passkey there (Touch ID, Windows Hello, a phone or a security key), save the recovery codes and create your workspace. The code stops working once your account exists.

## 5. Enrol each agent machine

On each machine your agents run on, install `mehen` and enrol it in the workspace, naming the vault with `MEHEN_VAULT_URL`:

```sh
curl -fsSL https://mehen.dev/install | sh
MEHEN_VAULT_URL=https://vault.example.com mehen enrol --workspace <slug>
mehen wait <enr_id>
mehen setup
mehen guard install
```

`mehen enrol` prints a link to the machine's page on your vault and the machine's fingerprint, and exits. Open the link, check the three groups the page shows, type the hidden one and accept with your passkey; `mehen wait` finishes once you have. The machine remembers which vault it enrolled with, so later commands need no `MEHEN_VAULT_URL`. `mehen setup` registers Mehen with the agents on that machine and `mehen guard install` adds the guard hooks ([The guard hooks](../guides/guard.md)).

Or let the agent do it, with this prompt:

```prompt
Follow https://docs.mehen.dev/setup.md to connect this machine to Mehen workspace <slug> at https://vault.example.com. I will approve it in my browser; never ask me for a key, password or secret.
```

A machine can be in this vault and in other vaults at once, Mehen Cloud included: it keeps one key per vault and workspace ([Several workspaces on one machine](../guides/several-workspaces.md)).

## What changes from a vault on one machine

- **The agent's machine holds no vault files.** A program running on it can use what that machine's key may use, as any enrolled machine can, but it cannot read or edit the vault's database or keys.
- **You approve from any device that reaches the vault**, your phone included, as long as it can open the vault's https name.
- **`mehen up` is for a vault on its own machine.** It starts a vault on `localhost` only; on the agent machines, use the enrolment above.

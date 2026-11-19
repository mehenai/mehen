---
title: Keep a service running with mehen run
question: How do I run a long-lived process under mehen run with launchd or systemd, and what do its exit codes mean?
section: guides
covers: both
order: 105
---

# Keep a service running with mehen run

A server, a bot or a resident agent can take its variables from `mehen run` like any other command ([Project variables with mehen run](projects.md)). An ordinary run has a hard end, though: it lives at most 12 hours, or 2 hours when an approval started it, however often it renews. A **service run**, `mehen run --service`, has none: it lives as long as it renews, from a machine a human has allowed to run services, in an unprotected environment ([Service runs](../concepts/projects.md#service-runs)).

Either way a service under `mehen run` stops now and then: a service run when one of its variables or credentials changes, an ordinary run at its maximum life, and any run when the vault refuses it or cannot be reached in time. A supervisor starts it again. The fresh run reads every variable again, so the change reaches the service at the next start.

`mehen run` makes that stop clean, gives it an exit code the supervisor can act on, and writes one line on stderr naming the reason.

## Allow a machine to run services

`mehen run --service` needs the machine's scope to have `serviceRuns` ([Scope and reach](../concepts/machines.md#scope-and-reach)). On the machine's page under Machines, tick **May run services** and sign the change with a passkey. That widens the machine's scope, so it is a proposal: the machine's owner accepts it on the same page with their own passkey. On a team's machine, an owner's or admin's passkey applies it at once.

Without it, `mehen run --service` exits 5 (`forbidden`) and names that page; in a protected environment it exits 5 (`environment_refused`). Unticking it applies at once and ends the live runs of the owner's machines: each run's next renewal gets `not_found` (exit 1), and a supervisor's restart with `--service` exits 5 (`forbidden`) until someone ticks it again or the unit drops `--service`.

## How a run ends

**At its maximum life** (not a service run). The vault answers every run and every renewal with `endsAt`, the run's hard end, or `null` for a service run, which has none. A minute before the stop, `mehen run` warns on stderr that the run reaches its maximum life and that renewal cannot extend it. Then:

1. `--stop-grace` seconds before `endsAt` (10 by default, whole seconds from 1 to 300), it sends SIGTERM to the child: to its process group when the child runs detached (stdin is not a terminal, as under launchd or systemd), otherwise to the child and its descendants. The run is still live, so the local relay and the child's placeholders keep working while it shuts down.
2. When the child exits, or at `endsAt` if it has not, `mehen run` sends SIGKILL to whatever is left, closes the relay and ends the run.
3. `mehen run` exits 7.

**When authority is lost.** If the vault refuses a renewal, or no renewal succeeds before the last confirmed expiry, the run is no use any more. `mehen run` closes the relay first, sends SIGTERM, and sends SIGKILL 10 seconds later whatever `--stop-grace` says, so a revoked machine does not keep real values in memory for longer. If that happens during the maximum-life grace, the relay closes at once and SIGKILL follows 10 seconds later, or at `endsAt` if that is sooner, with the refusal's exit code.

Every renewal of a service run plans it again: a variable bound to something else, an override set or cleared, a changed delivery, a rotated credential or a changed fence on another environment refuses the renewal with `conflict`, which ends the run as any refusal does, and `mehen run` exits 7. Every refusal of a renewal ends the run at once, except `rate_limited`, `upstream_failed` and `refresh_retrying`, which `mehen run` retries with backoff. A network failure is retried too, until the last confirmed expiry: about 15 minutes after the last successful renewal. A Mac that sleeps for longer than that wakes to a run that has expired.

**When the child exits by itself,** `mehen run` ends the run and exits with the child's own code. A SIGTERM or SIGINT sent to `mehen run` is passed to the child, so a supervisor's stop works as it would without Mehen.

## Exit codes

When `mehen run` stops the child itself, it exits with one of [the documented exit codes](../reference/errors.md#exit-codes) instead of the child's, and writes one stderr line naming the reason, for example `mehen: run run_3kq... has reached its maximum life; its child processes were stopped.`

| Exit | Why the child was stopped | What the supervisor does |
| --- | --- | --- |
| 7 | The run reached its maximum life; its sources or credentials changed (`conflict`); or the vault could not renew it in time. | Start it again. |
| 6 | This machine's identity is no longer accepted (`device_revoked`, `unauthenticated`, `proof_invalid`), or its workload ended. | Stop. A human must enrol or repair the machine. |
| 5 | Refused by rule (`forbidden`, `remote_mismatch`, `environment_refused`), for example a machine that may no longer run services. | Stop. Retrying will not help. |
| 4 | A human must act (`frozen`, `owner_inactive`, `project_unshared`). | Restarting fails until they have. |
| 3 | A protected environment needs an approval to start. | A human approves each start. |
| 1 | The run had already ended or expired (`not_found`), for example after a long sleep. | Start it again. |

A protected environment does not suit a service: every run needs a human's approval, so a restart stops at exit 3 until someone approves it. Run services in an unprotected environment.

## launchd on macOS

A LaunchAgent in `~/Library/LaunchAgents/dev.example.api.plist`, loaded as the user who enrolled the machine, so `mehen` finds its key:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.example.api</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/homebrew/bin/mehen</string>
    <string>run</string>
    <string>--service</string>
    <string>--env</string>
    <string>dev</string>
    <string>--</string>
    <string>bun</string>
    <string>run</string>
    <string>start</string>
  </array>
  <key>WorkingDirectory</key>
  <string>/Users/sam/code/example-api</string>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>ExitTimeOut</key>
  <integer>60</integer>
  <key>StandardErrorPath</key>
  <string>/Users/sam/Library/Logs/example-api.log</string>
</dict>
</plist>
```

```sh
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.example.api.plist
```

- `WorkingDirectory` is the service's folder: `mehen run` finds `mehen.toml` from there.
- `KeepAlive` starts it again after every exit, at most once every `ThrottleInterval` seconds. launchd cannot skip a restart by exit code, so a revoked machine retries every 10 seconds until someone unloads the job; watch the log for exit 6.
- `ExitTimeOut` is how long launchd waits after its own SIGTERM before it sends SIGKILL. Keep it above the time the child needs to stop. If launchd kills `mehen` first, the child's group can outlive it until the run expires.
- On a machine that may not run services, drop `--service` and add `--stop-grace <seconds>` to give the child time to stop at the maximum life; keep `ExitTimeOut` above it.

## systemd on Linux

A user unit in `~/.config/systemd/user/example-api.service`, so it runs as the user who enrolled the machine:

```ini
[Unit]
Description=example API under mehen run
Wants=network-online.target
After=network-online.target

[Service]
WorkingDirectory=/home/sam/code/example-api
ExecStart=/usr/local/bin/mehen run --service --env dev -- bun run start
Restart=always
RestartSec=5
RestartPreventExitStatus=5 6
KillMode=control-group
TimeoutStopSec=60

[Install]
WantedBy=default.target
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now example-api
```

- `Restart=always` with `RestartSec=5` starts it again after a changed variable and every other stop.
- `RestartPreventExitStatus=5 6` stops the restarts when the vault refuses by rule or no longer accepts the machine, so a revoked machine does not loop.
- `KillMode=control-group` makes sure a stop reaches the child and anything it started, even if `mehen` is gone.
- `TimeoutStopSec` is how long systemd waits after its own SIGTERM. Keep it above the time the child needs to stop.
- On a machine that may not run services, drop `--service` and add `--stop-grace <seconds>` before `--`; keep `TimeoutStopSec` above it.

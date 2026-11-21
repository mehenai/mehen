---
title: Back up a machine before adopting
question: How do I keep my own copy of every file mehen adopt reads, so Mehen is never the only copy?
section: guides
covers: both
order: 97
---

# Back up a machine before adopting

Before [`mehen adopt submit`](adopt.md) sends anything, take a snapshot (for a single file planned with `mehen adopt file`, before `mehen adopt retire` instead): one encrypted archive of every file the adopt plan names, byte for byte, with its permissions and times. It is encrypted with age, a small and widely packaged encryption tool, to a key whose private half is on no enrolled machine, and stock `age` opens it without Mehen. Every `mehen backup` command runs offline: none talks to the vault.

## 1. Make the key on another machine

Make the backup key on a machine no agent uses, not on the machine you are adopting from:

```sh
mehen backup keygen --out ~/mehen-backup-key.txt
```

It writes a new age identity (mode 0600) and prints only its public half, the recipient, a line starting `age1`. It never writes over a file, and refuses a path under your mehen root or inside a git work tree. On an enrolled machine it refuses unless you add `--on-enrolled-machine`, because an agent there could read the key. `age-keygen -o ~/mehen-backup-key.txt` makes the same kind of key and prints the recipient as `Public key: age1...`.

Only plain X25519 recipients work: not post-quantum (`age1pq1...`), plugin or SSH ones.

## 2. Keep the private key safe

The identity file holds one line starting `AGE-SECRET-KEY-1`. Whoever has it can open every snapshot made to it.

- Put it in a password manager, in a vault no agent account can read.
- Write it on paper too, or print it, and keep that apart from your other recovery material.
- Then delete the file. Never keep it on an enrolled machine, and never paste it into a chat or a command line.

The recipient (`age1...`) is not secret: copy it to the machine you are adopting from.

## 3. Take the snapshot

On the machine you are adopting from, after `mehen adopt plan` and before `mehen adopt submit` (for a single file planned with `mehen adopt file`, any time before `mehen adopt retire`):

```sh
mehen backup snapshot --plan ~/.config/mehen/adopt/<machine>/plan.json --to ~/Backups/mehen --recipient age1...
```

It reads every file the plan names (each source, each service's unit and env file, each repo's existing `mehen.toml`) and the plan itself. Give `--recipient` more than once to encrypt to several keys, or set `MEHEN_BACKUP_RECIPIENTS` to a comma-separated list instead.

- `--to` must be outside every repo the plan adopts and outside any git work tree, so the archive is never committed. A synced folder is fine: only ciphertext lands there. It is made with mode 0700 if it does not exist.
- It writes `<snp_id>.age`, the archive, and `<snp_id>.json`, a sidecar with the file list and the archive's checksum but no value, length or hash of any file's content.
- Before it succeeds, it proves the archive: it reads it back from disk, opens it with a one-time key that exists only in that process, and compares every file with what is on disk again. If anything differs, it deletes what it wrote and fails.
- It records the snapshot on this machine, so `mehen adopt submit` and `mehen adopt retire` can find it.

Copy both files off the machine. To read one file back without Mehen:

```sh
age -d -i key.txt snp_4fQ9cR2mT7.age | jq -r '.files[] | select(.path == "/Users/sam/code/api/.env") | .content' | base64 -d
```

## 4. Check it

```sh
mehen backup check ~/Backups/mehen/snp_4fQ9cR2mT7.age
```

No key needed. It compares the archive's length and SHA-256 with the sidecar beside it, and checks the age header has one stanza per recipient plus the self-check's. That catches a truncated, damaged or swapped file. It cannot prove which key the archive is for, because age hides that by design: only opening it with your key does. Do that once, on the key machine, with `--verify-only` below.

## 5. Restore

`mehen backup restore` takes the identity from a file with `--identity <file>`, or from stdin with `--identity -` (for example piped from your password manager's command line), never as an argument. It refuses an identity file other users can read. Run it on the machine that holds the key; on an enrolled machine it refuses unless you add `--on-enrolled-machine`, and you should remove the key from that machine when you are done.

Exactly one of three modes:

- `--verify-only` opens the archive, checks every file's checksum and prints `restorable: 41 files from sam-laptop, 2026-11-01 (snp_4fQ9cR2mT7)`. It writes nothing.
- `--to <empty dir>` writes each file under that directory at its full original path, for example `~/mehen-restore/Users/sam/code/api/.env`, with its permission bits and modification time. It refuses `/`, anything that is not a directory, and a directory that is not empty. Name a new directory, which `mehen backup restore` creates private to you; an existing one must be private to you and not under a folder others can write. Copy back what you need from there.
- `--in-place` puts files back where they were, on the machine that took the snapshot. It refuses, before writing anything, a snapshot this machine did not take, an archive holding a path this machine's record of the snapshot does not list, an archive whose plan digest is not the one this machine recorded, a file over 1 MiB anywhere but the recorded plan path, and an archive whose length and SHA-256 are not the ones this machine recorded when it wrote it. Snapshots taken before 0.3.13 hold no such record: restore them with `--to`. It writes only files that are missing; a file that is there with other content is listed as `different` and left as it is. Add `--force` to replace those: each old file is kept beside it as `<path>.mehen-restore-<time>`, and it refuses if that name is already taken.

```sh
mehen backup restore ~/Backups/mehen/snp_4fQ9cR2mT7.age --identity - --verify-only
mehen backup restore ~/Backups/mehen/snp_4fQ9cR2mT7.age --identity key.txt --to ~/mehen-restore
mehen backup restore ~/Backups/mehen/snp_4fQ9cR2mT7.age --identity key.txt --in-place
```

Restored files never keep a setuid or setgid bit.

## 6. Compare with Mehen

Once a batch is approved and applied, check that Mehen holds exactly what your files hold. Take an export after `mehen adopt apply` (`mehen backup export --to ~/Backups/mehen`), save the batch's map on the machine you adopted from (`mehen adopt status adp_7Hq2xK --json > adoption.json`), then, on the key machine:

```sh
mehen backup compare ~/Backups/mehen/snp_4fQ9cR2mT7.age ~/Backups/mehen/mehen-acme-2026-11-03-bkx_8Lm2pQ.age --identity - --map adoption.json --json > compare.json
```

It opens both in memory and compares every adopted variable in the snapshot with its credential in the export. It prints paths, variable names and counts, never a value, and exits 1 on any difference or gap. With `--json` it also gives the export's time (`exportedAt`) and every source that matched (`matching`: path, variable, credential and field). `compare.json` holds no value: copy it to the machine you adopted from for [`mehen adopt retire`](adopt.md#8-retire-when-you-are-sure).

## When submit and retire need the snapshot

Adopt never rewrites or deletes an original, but once your credentials are in the vault you will start taking the files out of play, with [`mehen adopt retire`](adopt.md#8-retire-when-you-are-sure) or by hand. The snapshot is your way back that does not depend on Mehen: encrypted to a key no agent can reach, and opened by a tool you can install anywhere.

- `mehen adopt retire` holds every file no passed snapshot on this machine holds unchanged, and moves none of them, whatever plan it came from.
- `mehen adopt submit` refuses, and sends nothing, until a passed snapshot on this machine holds every file the plan names, with none changed since. There is no flag to skip it. Each machine needs its own snapshot, `--join` included, and a new one whenever you plan again or a planned file changes.
- The one exception is a plan [`mehen adopt file`](adopt.md#quick-path-one-env-file) made that names exactly one file. Submit goes ahead without a snapshot and says that retire will need one, with the `mehen backup snapshot` command. Submit only reads that file, and nothing in adopt changes it before retire, so the snapshot still comes before the file can leave its place. A plan that names more than one file never gets the exception, whatever it says it came from. When `--snapshot` names a snapshot, submit checks it as for any plan.

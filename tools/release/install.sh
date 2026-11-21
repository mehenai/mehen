#!/bin/sh
# The Mehen installer, for a machine with no mehen.
# An installed mehen keeps itself current through its own signed updater;
# this script refuses to replace a verified install unless forced.
#
#   curl -fsSL https://mehen.dev/install | sh -s -- [--yes] [--force]
#     [--dir <abs path>] [--no-rc] [--version <v>] [--quiet]
#
# Order: refuse unsafe paths; create the directory; take the installation
# lock (.mehen.update.lock, shared with the updater) first; only then decide,
# download, verify and make one move; roll back on any failure after it.
# Verify: the manifest's ES256 signature against the pinned release key
# first, then the binary's size and sha256 from the verified manifest.
set -eu
fail() { printf 'mehen-install: %s\n' "$1" >&2; exit 2; }
say() { if [ "${MEHEN_QUIET:-0}" != 1 ]; then printf '%s\n' "$1"; fi; }

force=${MEHEN_FORCE:-0}
no_rc=${MEHEN_NO_RC:-0}
version=${MEHEN_VERSION:-}
install_dir=${MEHEN_INSTALL_DIR:-}
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) ;;
    --force) force=1 ;;
    --no-rc) no_rc=1 ;;
    --quiet) MEHEN_QUIET=1 ;;
    --dir) [ $# -ge 2 ] || fail '--dir needs an absolute path.'; install_dir=$2; shift ;;
    --version) [ $# -ge 2 ] || fail '--version needs a release version.'; version=$2; shift ;;
    *) fail "Unknown option $1. Options: --yes --force --dir <abs path> --no-rc --version <v> --quiet" ;;
  esac
  shift
done
[ "$force" = 1 ] || force=0
[ "$no_rc" = 1 ] || no_rc=0

# Paths: no newline or carriage return (a NUL cannot reach a shell
# variable), an absolute directory, and no ':' (it cannot be one PATH entry).
nl='
'
cr=$(printf '\r')
for value in "${HOME:-}" "$install_dir" "${ZDOTDIR:-}"; do
  case "$value" in *"$nl"*|*"$cr"*) fail 'HOME, the install directory and ZDOTDIR must not contain a newline or carriage return.' ;; esac
done
[ -n "${HOME:-}" ] || fail 'HOME is not set.'
[ -n "$install_dir" ] || install_dir=$HOME/.local/bin
case "$install_dir" in /*) ;; *) fail 'MEHEN_INSTALL_DIR must be absolute.' ;; esac
case "$install_dir" in *:*) fail "The install directory must not contain ':' (it cannot be one PATH entry)." ;; esac

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) fail 'Unsupported platform. Use macOS or Linux (including WSL).' ;;
esac
case "$(uname -m)" in
  arm64|aarch64) arch=arm64 ;;
  x86_64|amd64) arch=x64 ;;
  *) fail 'Unsupported architecture. Use arm64 or x64.' ;;
esac
if [ "$os" = darwin ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || :)" = 1 ]; then arch=arm64; fi
# A glibc system may also carry the musl package, so glibc is checked first;
# a Linux with neither answer is taken for glibc, as before musl builds.
libc=
if [ "$os" = linux ] && ! getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
  if ldd --version 2>&1 | grep -qi musl; then libc=-musl; fi
  for loader in /lib/ld-musl-*; do
    if [ -e "$loader" ]; then libc=-musl; fi
  done
fi
if command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 < "$1" | awk '{print $1}'; }
elif command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum < "$1" | awk '{print $1}'; }
else
  fail 'A checksum tool is required: shasum or sha256sum.'
fi
command -v curl >/dev/null 2>&1 || fail 'curl is required.'
command -v openssl >/dev/null 2>&1 || fail 'openssl is required to check the release signature. Install it (Debian and Ubuntu: sudo apt install openssl; Fedora: sudo dnf install openssl), then run the installer again.'
base=${MEHEN_DL_BASE:-https://mehen.dev/dl}
base=${base%/}
# Plain http only for this machine, and loopback (which alone allows the
# test hooks and the test release key) only for an authority that is
# exactly 127.0.0.1, localhost or [::1] with a numeric port: nothing a URL
# parser could read as a user name, another host, a query or a fragment.
loopback=0
case "$base" in
  https://*) ;;
  http://*)
    authority=${base#http://}
    authority=${authority%%/*}
    case "$base" in *[@?#\\\ ]*) authority= ;; esac
    host=${authority%:*}
    port=${authority##*:}
    case "$host" in 127.0.0.1|localhost|'[::1]') ;; *) host= ;; esac
    case "$port" in ''|*[!0-9]*) host= ;; esac
    [ -n "$host" ] && [ "$host:$port" = "$authority" ] || fail 'Download base must use https (or loopback http for tests).'
    loopback=1
    ;;
  *) fail 'Download base must use https (or loopback http for tests).' ;;
esac
case "$version" in *[!A-Za-z0-9.-]*) fail 'Invalid MEHEN_VERSION.' ;; esac
# The musl builds link libstdc++, which a minimal musl system such as Alpine
# does not install; without it the binary cannot start, so say so first.
# MEHEN_INSTALL_TEST_LIBDIRS stands in for the system's folders, loopback only.
if [ "$libc" = -musl ]; then
  libdirs='/lib /usr/lib /usr/local/lib'
  if [ "$loopback" = 1 ] && [ -n "${MEHEN_INSTALL_TEST_LIBDIRS:-}" ]; then libdirs=$MEHEN_INSTALL_TEST_LIBDIRS; fi
  found=0
  for dir in $libdirs; do
    if [ -e "$dir/libstdc++.so.6" ]; then found=1; fi
  done
  [ "$found" = 1 ] || fail 'This musl system has no libstdc++, which mehen needs. Install it (Alpine: apk add libstdc++), then run the installer again.'
fi
# A fault the tests inject after the move, honoured only for a loopback base.
fault() { [ "$loopback" = 1 ] && [ "${MEHEN_INSTALL_TEST_FAULT:-}" = "$1" ]; }

target="$install_dir/mehen"
receipt="$install_dir/.mehen.sha256"
previous="$install_dir/.mehen.previous"
previous_meta="$install_dir/.mehen.previous.json"
env_file="$install_dir/.mehen.env"
lock="$install_dir/.mehen.update.lock"

mkdir -p "$install_dir" || fail "Could not create $install_dir."
[ -d "$install_dir" ] || fail "$install_dir is not a directory."

# --- the lock, before anything is decided -----------------------------------
locked=0
stage=
phase=none
captured=0
moved_aside=0
old_receipt=0
pair_aside=
meta_aside=
result=installed

boot=
if [ -r /proc/sys/kernel/random/boot_id ]; then boot="linux:$(cat /proc/sys/kernel/random/boot_id)"
else
  boot_sec=$(sysctl -n kern.boottime 2>/dev/null | sed -n 's/^{ sec = \([0-9][0-9]*\),.*/\1/p' || :)
  if [ -n "$boot_sec" ]; then boot="darwin:$boot_sec"; fi
fi

owner_text() { printf '{"pid":%s,"boot":"%s","at":"%s","by":"install"}\n' "$$" "$boot" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; }
owner_pid() { sed -n 's/.*"pid":\([0-9][0-9]*\).*/\1/p' "$1/owner.json" 2>/dev/null | head -n 1; }
# Whether a pid is gone, positively. kill -0 also fails for a live process
# of another user (EPERM), so a failure is checked against ps, which lists
# every user's processes; ps must first prove it works by listing this
# shell. Anything it cannot establish (no ps, a ps error, a permission
# message) counts as alive, so the lock stays held.
pid_gone() {
  probe=$(kill -0 "$1" 2>&1) && return 1
  case "$probe" in *ermitted*|*ermission*) return 1 ;; esac
  command -v ps >/dev/null 2>&1 || return 1
  self=$(ps -p "$$" -o pid= 2>/dev/null) || return 1
  [ -n "$self" ] || return 1
  listed=$(ps -p "$1" -o pid= 2>/dev/null || :)
  [ -z "$listed" ]
}
# A test hook run after a stale owner was observed, before the guard; it
# lets the tests put another contender in between. Loopback bases only.
after_observe_hook() { if [ "$loopback" = 1 ] && [ -n "${MEHEN_INSTALL_TEST_AFTER_OBSERVE:-}" ]; then sh -c "$MEHEN_INSTALL_TEST_AFTER_OBSERVE"; fi; }
# Whether a path was last modified over ten minutes ago, the grace period
# for a lock with no owner (OWNERLESS_GRACE_MS in install-state.ts); an
# mtime in the future is not.
old_enough() { [ -n "$(find "$1" -prune -mmin +10 2>/dev/null)" ]; }
owner_file_old() { { [ ! -e "$lock/owner.json" ] && [ ! -L "$lock/owner.json" ]; } || old_enough "$lock/owner.json"; }
lock_inode() { ls -di "$lock" 2>/dev/null | awk '{print $1}'; }

# The installation lock, shared with the CLI (install-state.ts): mkdir of the
# directory, then the owner, which never overwrites one already there. A
# stale lock (its pid gone, or no readable owner for ten minutes) is never
# moved or emptied: the reclaimer makes $lock/reap with mkdir, and only that
# winner re-reads the owner and, when it is still what it saw in the same
# directory, replaces owner.json in place. The guard itself sets the
# directory's mtime, so under it the directory's age is not read again. An
# existing guard is someone else's: held, at any age.
take_lock() {
  if (umask 077; mkdir "$lock") 2>/dev/null; then
    if (umask 077; set -C; owner_text > "$lock/owner.json") 2>/dev/null; then
      locked=1
      return 0
    fi
    pid=$(owner_pid "$lock")
    fail "Another mehen update is running (pid ${pid:-unknown}); retry in a minute, or remove $lock if that process is gone."
  fi
  { [ -d "$lock" ] && [ ! -L "$lock" ]; } || fail "$lock is not a lock directory mehen made. Move it aside, then run the installer again."
  inode=$(lock_inode)
  observed=$(cat "$lock/owner.json" 2>/dev/null || :)
  pid=$(owner_pid "$lock")
  # An owner parses when it names a pid above 0 and is whole.
  ownerless=1
  case "$observed" in *'}') case "$pid" in ''|0) ;; *) ownerless=0 ;; esac ;; esac
  reclaim=0
  if [ -n "$inode" ] && [ ! -e "$lock/reap" ]; then
    if [ "$ownerless" = 0 ]; then
      if pid_gone "$pid"; then reclaim=1; fi
    elif old_enough "$lock" && owner_file_old; then reclaim=1
    fi
  fi
  if [ "$reclaim" = 1 ]; then
    after_observe_hook
    if (umask 077; mkdir "$lock/reap") 2>/dev/null; then
      current=$(cat "$lock/owner.json" 2>/dev/null || :)
      if [ "$current" = "$observed" ] && [ "$(lock_inode)" = "$inode" ]; then
        if [ "$ownerless" = 0 ]; then
          if pid_gone "$pid"; then reclaim=2; fi
        elif owner_file_old; then reclaim=2
        fi
      fi
      if [ "$reclaim" = 2 ]; then
        (umask 077; owner_text > "$lock/owner.json.$$") && mv -f "$lock/owner.json.$$" "$lock/owner.json" && locked=1
      fi
      rmdir "$lock/reap" 2>/dev/null || :
      if [ "$locked" = 1 ]; then return 0; fi
    fi
    pid=$(owner_pid "$lock")
  fi
  fail "Another mehen update is running (pid ${pid:-unknown}); retry in a minute, or remove $lock if that process is gone."
}

# Undoes this transaction: the previous binary and its receipt come back, or
# on a fresh install this transaction's binary and receipt go; the
# pre-transaction previous pair is restored byte for byte.
rollback() {
  if [ "$phase" = moved ]; then
    if [ "$captured" = 1 ]; then mv -f "$previous" "$target"
    elif [ "$moved_aside" = 1 ]; then mv -f "$stage/old.target" "$target"
    else rm -f "$target"; fi
    if [ "$old_receipt" = 1 ]; then mv -f "$stage/receipt.old" "$receipt"; else rm -f "$receipt"; fi
    if [ "$captured" = 1 ] || [ "$moved_aside" = 1 ]; then say 'The install failed after the move; the previous mehen and its receipt are restored.' >&2
    else say 'The install failed after the move; this install'"'"'s binary and receipt are removed.' >&2; fi
  elif [ "$phase" = pair ] && [ "$moved_aside" = 1 ]; then mv -f "$stage/old.target" "$target"
  fi
  if [ "$phase" = pair ] || [ "$phase" = moved ]; then
    if [ "$captured" = 1 ]; then rm -f "$previous"; fi
    if [ -n "$pair_aside" ]; then mv -f "$pair_aside" "$previous"; fi
    if [ -n "$meta_aside" ]; then mv -f "$meta_aside" "$previous_meta"; fi
  fi
}

on_exit() {
  status=$1
  trap - 0
  if [ "$status" != 0 ]; then rollback || :; status=2; fi
  if [ -n "$stage" ]; then rm -rf "$stage"; fi
  # Released only while the owner is still this installer.
  if [ "$locked" = 1 ] && [ "$(owner_pid "$lock")" = "$$" ]; then rm -rf "$lock"; fi
  exit "$status"
}
trap 'on_exit $?' 0
trap 'exit 2' HUP INT TERM

take_lock

# --- decide, under the lock ---------------------------------------------------
verified() {
  [ -f "$target" ] && [ ! -L "$target" ] && [ -f "$receipt" ] && [ ! -L "$receipt" ] && [ "$(sha256_of "$target")" = "$(cat "$receipt")" ]
}
existing=0
if [ -e "$target" ] || [ -L "$target" ]; then
  if [ -d "$target" ] && [ ! -L "$target" ]; then fail 'Existing mehen is a directory. Move it aside first.'; fi
  existing=1
  if verified; then
    if [ "$force" = 1 ]; then result=forced; else result=already-installed; fi
  elif [ "$force" = 1 ]; then result=forced
  else fail 'Existing mehen is not a verified Mehen install. Pass --force (or set MEHEN_FORCE=1) to replace it.'
  fi
fi

# --- JSON helpers for the receipt -------------------------------------------
json_str() { printf '%s' "$1" | awk 'BEGIN {ORS=""; printf "\""} {if(NR>1) printf "\\n"; gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\t/, "\\t"); gsub(/\r/, "\\r"); printf "%s", $0} END {printf "\""}'; }
rc_written=
rc_unchanged=
rc_skipped=
rc_advice=
json_add() { if [ -n "$1" ]; then printf '%s,%s' "$1" "$2"; else printf '%s' "$2"; fi; }
note_written() { rc_written=$(json_add "$rc_written" "$(json_str "$1")"); say "PATH: added the mehen line to $1"; }
note_unchanged() { rc_unchanged=$(json_add "$rc_unchanged" "$(json_str "$1")"); }
note_skipped() { rc_skipped=$(json_add "$rc_skipped" "{\"path\":$(json_str "$1"),\"reason\":$(json_str "$2")}"); say "PATH: left $1 alone ($2)"; }

# --- PATH persistence: zsh and bash only -------------------------------------
uid=$(id -u)
quote() { printf '%s' "$1" | sed "s/'/'\\\\''/g"; }

# HOME with its parent resolved by pwd -P, so a home under a symlinked
# ancestor (macOS /var is /private/var) is walked and written at its real
# path. HOME itself is not resolved: a symlinked HOME stays unsafe. A HOME
# with . or .. components is left as it is, for the walk to refuse.
home=${HOME%/}
real_home=$home
case "$home/" in
  */./*|*/../*) ;;
  /?*)
    home_parent=${home%/*}
    if real_parent=$(cd "${home_parent:-/}" 2>/dev/null && pwd -P); then real_home="${real_parent%/}/${home##*/}"; fi
    ;;
esac

# Every directory from / down to $1 is a real directory, not a link; inside
# $HOME owned by this user and not group or world writable; above $HOME
# owned by root or this user and not group or world writable, or root's
# with the sticky bit.
safe_ancestors() {
  dir=$1
  case "$dir" in /*) ;; *) return 1 ;; esac
  case "$dir/" in */./*|*/../*) return 1 ;; esac
  cur=
  rest=${dir#/}
  check="/"
  while :; do
    if [ -L "$check" ] || [ ! -d "$check" ]; then return 1; fi
    info=$(ls -ldn "$check" | awk '{print substr($1,1,10), $3}')
    mode=${info% *}
    owner=${info#* }
    case "$check/" in "${real_home%/}/"*) inside=1 ;; *) inside=0 ;; esac
    gw=$(printf '%s' "$mode" | cut -c6)
    ow=$(printf '%s' "$mode" | cut -c9)
    sticky=$(printf '%s' "$mode" | cut -c10)
    if [ "$inside" = 1 ]; then
      [ "$owner" = "$uid" ] && [ "$gw" != w ] && [ "$ow" != w ] || return 1
    else
      if [ "$gw" = w ] || [ "$ow" = w ]; then
        [ "$owner" = 0 ] && { [ "$sticky" = t ] || [ "$sticky" = T ]; } || return 1
      else
        [ "$owner" = 0 ] || [ "$owner" = "$uid" ] || return 1
      fi
    fi
    [ -n "$rest" ] || break
    comp=${rest%%/*}
    case "$rest" in */*) rest=${rest#*/} ;; *) rest= ;; esac
    [ -n "$comp" ] || continue
    cur="$cur/$comp"
    check=$cur
  done
  return 0
}

header='# mehen env: adds the Mehen install directory to PATH. Written by the Mehen installer; safe to delete.'
q_dir=$(quote "$install_dir")
q_env=$(quote "$env_file")
rc_line="[ -f '$q_env' ] && . '$q_env' # mehen"

# The env file: written only when absent, or a plain file of this user
# whose first line is the header; anything else is left alone.
write_env_file() {
  if [ -L "$env_file" ]; then note_skipped "$env_file" symlink; return 1; fi
  if [ -e "$env_file" ]; then
    [ -f "$env_file" ] || { note_skipped "$env_file" 'not a regular file'; return 1; }
    [ -O "$env_file" ] || { note_skipped "$env_file" 'other uid'; return 1; }
    [ "$(sed -n 1p "$env_file")" = "$header" ] || { note_skipped "$env_file" 'not written by the Mehen installer'; return 1; }
  fi
  tmp_env="$env_file.tmp.$$"
  (umask 022; { printf '%s\n' "$header"; printf '%s\n' "case \":\$PATH:\" in *':$q_dir:'*) ;; *) PATH='$q_dir:'\"\$PATH\"; export PATH ;; esac"; } > "$tmp_env")
  mv -f "$tmp_env" "$env_file"
}

# One guarded line, exact-line idempotent, appended with >> so the inode,
# mode and ACLs stay; a missing file is created only for the user's shell.
# A file under HOME is checked and written at real_home, so nothing
# re-traverses a link between the walk and the write; the receipt names it
# as given.
add_rc() {
  shown=$1
  file=$shown
  if [ -n "$home" ]; then case "$shown" in "$home"/*) file=$real_home${shown#"$home"} ;; esac; fi
  parent=$(dirname "$file")
  if ! safe_ancestors "$parent"; then note_skipped "$shown" 'unsafe ancestor'; return 0; fi
  # The file's own directory, inside HOME or not (an external ZDOTDIR), is
  # this user's and nobody else can write it; the root-owned allowance is
  # for ancestors only.
  pinfo=$(ls -ldn "$parent" | awk '{print substr($1,1,10), $3}')
  pmode=${pinfo% *}
  powner=${pinfo#* }
  if [ "$powner" != "$uid" ] || [ "$(printf '%s' "$pmode" | cut -c6)" = w ] || [ "$(printf '%s' "$pmode" | cut -c9)" = w ]; then note_skipped "$shown" 'parent not owned'; return 0; fi
  if [ ! -e "$file" ] && [ ! -L "$file" ] && [ ! -w "$parent" ]; then note_skipped "$shown" 'not writable'; return 0; fi
  if [ -L "$file" ]; then note_skipped "$shown" symlink; return 0; fi
  if [ -e "$file" ]; then
    [ -f "$file" ] || { note_skipped "$shown" 'not a regular file'; return 0; }
    [ -O "$file" ] || { note_skipped "$shown" 'other uid'; return 0; }
    [ -w "$file" ] || { note_skipped "$shown" 'not writable'; return 0; }
    size=$(wc -c < "$file" | tr -d ' ')
    [ "$size" -le 1048576 ] || { note_skipped "$shown" 'over 1 MB'; return 0; }
    if ! tr -d '\000' < "$file" | cmp -s - "$file"; then note_skipped "$shown" 'contains NUL'; return 0; fi
    if grep -Fxq -- "$rc_line" "$file"; then note_unchanged "$shown"; return 0; fi
    if [ "$size" -gt 0 ] && [ "$(tail -c 1 "$file" | od -An -c | tr -d ' ')" != '\n' ]; then printf '\n' >> "$file"; fi
    printf '%s\n' "$rc_line" >> "$file"
  else
    (umask 022; printf '%s\n' "$rc_line" > "$file")
  fi
  note_written "$shown"
}

env_json=null
persist_path() {
  [ "$no_rc" = 1 ] && return 0
  case "${SHELL:-sh}" in
    */zsh|*/bash) ;;
    */fish) rc_advice="fish: fish_add_path '$q_dir'"; say "PATH: run $rc_advice"; return 0 ;;
    *) rc_advice="add . '$q_env' to your shell's start-up file"; write_env_file && env_json=$(json_str "$env_file") || :; say "PATH: $rc_advice"; return 0 ;;
  esac
  write_env_file || return 0
  env_json=$(json_str "$env_file")
  case "${SHELL:-sh}" in
    */zsh) add_rc "${ZDOTDIR:-$HOME}/.zshenv" ;;
    */bash)
      add_rc "$HOME/.bashrc"
      login=
      for candidate in .bash_profile .bash_login .profile; do
        if [ -e "$HOME/$candidate" ] || [ -L "$HOME/$candidate" ]; then login=$candidate; break; fi
      done
      add_rc "$HOME/${login:-.profile}"
      ;;
  esac
}

finish() {
  on_path=false
  case ":$PATH:" in *":$install_dir:"*) on_path=true ;; esac
  persist_path
  say 'Next: mehen up, to set Mehen up on this machine (in a shell without the PATH line, use the full path above)'
  if [ -n "$rc_advice" ]; then advice_json=$(json_str "$rc_advice"); else advice_json=null; fi
  printf 'mehen-install: {"v":1,"result":"%s","version":%s,"path":%s,"onPath":%s,"env":%s,"rc":{"written":[%s],"unchanged":[%s],"skipped":[%s],"advice":%s}}\n' "$result" "$1" "$(json_str "$target")" "$on_path" "$env_json" "$rc_written" "$rc_unchanged" "$rc_skipped" "$advice_json"
}

if [ "$result" = already-installed ]; then
  say "Already installed: mehen at $target. It keeps itself current; $target update --json brings it to the current release now."
  finish null
  exit 0
fi

# --- download and verify, staged on the destination filesystem ---------------
stage=$(mktemp -d "$install_dir/.mehen-update.XXXXXX")
if [ -n "$version" ]; then manifest="$base/v$version/manifest.json"; else manifest="$base/latest.json"; fi
curl -fsSL --proto '=https,http' --proto-redir '=https' --retry 2 "$manifest" -o "$stage/manifest.json" || fail 'Manifest download failed.'
# --- the manifest's signature, before any hash in it is trusted ---------------
# The release tool signs the canonical JSON of the manifest without
# `signatures` (keys sorted, no whitespace) with a P-256 key (ES256), as
# packages/protocol/src/release-manifest.ts says; the updater checks the
# same bytes against the same key. Here awk rebuilds those bytes from the
# file, refusing anything it cannot reproduce exactly (an escape, a
# duplicate key, a number that is not a plain integer), and openssl checks
# the signature against the pinned keys. Every file entry is read from the
# verified bytes, never from the file as downloaded.
# The trusted release keys, one "<id> <base64 SPKI>" a line: exactly
# RELEASE_KEYS in packages/protocol/src/release-keys.ts (install.test.ts
# holds the two the same), so a key is added or retired here with it.
release_keys='rk-studio-2026-auto MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoAh4FhedQUyKlbxmNsVvhPy99A/kR2bF+XnqvjBkGDfeQzYyGgdD9LhIdgst9YFbX3Do2yxsvQGmljHzMgAAKg=='
if [ "$loopback" = 1 ] && [ -n "${MEHEN_INSTALL_TEST_RELEASE_KEY:-}" ]; then release_keys=$MEHEN_INSTALL_TEST_RELEASE_KEY; fi
release_key_ids=$(printf '%s\n' "$release_keys" | awk '{print $1}' | tr '\n' ' ' | sed 's/ $//')
# The output paths go through the environment: awk -v would read a
# backslash in the install directory as an escape.
MEHEN_I_UNSIGNED="$stage/unsigned.json" MEHEN_I_SIGS="$stage/signatures" LC_ALL=C awk '
function fail() { bad=1; exit 2 }
function token(   t) {
  sub(/^[ \t\r\n]+/, "", s)
  if (s == "") return ""
  if (match(s, /^"[^"\\\001-\037]*"/)) { t=substr(s,1,RLENGTH); s=substr(s,RLENGTH+1); return t }
  if (match(s, /^(0|[1-9][0-9]*)/)) { t=substr(s,1,RLENGTH); s=substr(s,RLENGTH+1); if (length(t) > 15) fail(); return t }
  # index(), not a bracket expression: BusyBox awk (Alpine) reads \] in one
  # as POSIX does, a backslash and the end of the set, and refused "{".
  t=substr(s,1,1); s=substr(s,2); if (index("{}[]:,", t) == 0) fail(); return t
}
# One value, canonical, from the next token; `top` marks the manifest
# itself, whose signatures go aside.
function value(depth, top,   t, n, i, j, k, keys, vals, out, key, v, sep) {
  if (depth > 8) fail()
  t = token()
  if (t ~ /^"/ || t ~ /^[0-9]/) return t
  if (t == "[") {
    out = "["; sep = ""
    if (peek() == "]") { token(); return "[]" }
    for (;;) {
      out = out sep value(depth + 1, 0); sep = ","
      t = token(); if (t == "]") return out "]"; if (t != ",") fail()
    }
  }
  if (t != "{") fail()
  n = 0
  if (peek() == "}") { token(); return "{}" }
  for (;;) {
    key = token(); if (key !~ /^"[ -~]*"$/) fail()
    if (token() != ":") fail()
    v = value(depth + 1, 0)
    for (i = 1; i <= n; i++) if (keys[i] == key) fail()
    keys[++n] = key; vals[n] = v
    t = token(); if (t == "}") break; if (t != ",") fail()
  }
  # Sorted by the keys themselves, without their quotes, byte by byte.
  for (i = 2; i <= n; i++) { k = keys[i]; v = vals[i]; for (j = i - 1; j >= 1 && bare(keys[j]) > bare(k); j--) { keys[j+1] = keys[j]; vals[j+1] = vals[j] } keys[j+1] = k; vals[j+1] = v }
  out = "{"; sep = ""
  for (i = 1; i <= n; i++) {
    if (top && keys[i] == "\"signatures\"") { signatures = vals[i]; continue }
    out = out sep keys[i] ":" vals[i]; sep = ","
  }
  return out "}"
}
function bare(q) { return substr(q, 2, length(q) - 2) }
function peek() { sub(/^[ \t\r\n]+/, "", s); return substr(s, 1, 1) }
{ s = s $0 "\n" }
END {
  if (bad) exit 2
  if (peek() != "{") exit 2
  body = value(1, 1)
  sub(/^[ \t\r\n]+/, "", s); if (s != "") exit 2
  unsigned = ENVIRON["MEHEN_I_UNSIGNED"]; sigs = ENVIRON["MEHEN_I_SIGS"]
  printf "%s", body > unsigned
  rest = signatures
  if (rest == "" || rest == "[]") exit 3
  if (rest !~ /^\[/) exit 2
  while (match(rest, /\{"alg":"ES256","keyId":"[A-Za-z0-9._-]+","signature":"[A-Za-z0-9_-]+"\}/)) {
    one = substr(rest, RSTART, RLENGTH); rest = substr(rest, RSTART + RLENGTH)
    sub(/^\{"alg":"ES256","keyId":"/, "", one); sub(/","signature":"/, " ", one); sub(/"\}$/, "", one)
    print one > sigs; count++
    if (count > 16) exit 2
  }
  if (count == 0) exit 3
}' "$stage/manifest.json" || {
  [ $? = 3 ] && fail 'The release manifest is not signed, so nothing was installed.'
  fail 'Invalid release manifest.'
}
# r||s, 64 bytes of base64url, as the DER SEQUENCE openssl reads: each
# integer without its leading zero bytes, and one zero byte before a high bit.
signature_der() {
  printf '%s==' "$1" | tr '_-' '/+' | openssl base64 -d -A 2>/dev/null | od -An -v -tx1 | tr -d ' \n' | LC_ALL=C awk '
function byte(h) { return index("0123456789abcdef", substr(h,1,1)) * 16 + index("0123456789abcdef", substr(h,2,1)) - 17 }
function int_(h) { while (length(h) > 2 && substr(h,1,2) == "00") h = substr(h,3); if (byte(substr(h,1,2)) >= 128) h = "00" h; return sprintf("02%02x", length(h) / 2) h }
{ if (length($0) != 128 || $0 ~ /[^0-9a-f]/) exit 2; r = int_(substr($0,1,64)); s = int_(substr($0,65,64)); der = sprintf("30%02x", (length(r) + length(s)) / 2) r s
  for (i = 1; i <= length(der); i += 2) printf "\\%03o", byte(substr(der,i,2)) }'
}
signed=0
while read -r key_id signature; do
  spki=$(printf '%s\n' "$release_keys" | awk -v id="$key_id" '$1 == id {print $2; exit}')
  [ -n "$spki" ] || continue
  printf '%s\n' '-----BEGIN PUBLIC KEY-----' "$spki" '-----END PUBLIC KEY-----' > "$stage/release-key.pem"
  der=$(signature_der "$signature") || continue
  printf "$der" > "$stage/signature.der"
  if openssl dgst -sha256 -verify "$stage/release-key.pem" -signature "$stage/signature.der" "$stage/unsigned.json" >/dev/null 2>&1; then signed=1; break; fi
done < "$stage/signatures"
[ "$signed" = 1 ] || fail "The release manifest's signature does not verify against Mehen's release key ($release_key_ids), so nothing was installed. Someone may have changed it on the way: do not install from this source, and report it to security@mehen.dev."
# The entries, from the verified canonical bytes. Tokenise JSON rather than
# relying on line layout; reject escapes and unexpected syntax rather than guessing.
awk '
function token(   t) {
  sub(/^[ \t\r\n]+/, "", s)
  if (s == "") return ""
  if (match(s, /^"[^"\\]*"/)) { t=substr(s,1,RLENGTH); s=substr(s,RLENGTH+1); return t }
  if (match(s, /^[0-9]+/)) { t=substr(s,1,RLENGTH); s=substr(s,RLENGTH+1); return t }
  t=substr(s,1,1); s=substr(s,2); if (index("{}[]:,", t) == 0) exit 2; return t
}
function plain(t) { if (t ~ /^"/) return substr(t,2,length(t)-2); return t }
{ s=s $0 "\n" }
END {
  depth=0; key=""; count=0
  while ((t=token()) != "") {
    if (t=="{") { depth++; if (depth==2) { name=""; raw=""; gz=""; size=""; gzsize="" }; continue }
    if (t=="}") { if (depth==2 && name!="") { files[++count]=name "|" raw "|" gz "|" size "|" gzsize }; depth--; continue }
    if (t=="[") { key=""; continue }
    if (t==":" || t=="," || t=="]") continue
    if (key=="") { key=plain(t); continue }
    value=plain(t)
    if (depth==1 && key=="version") version=value
    if (depth==2 && key=="name") name=value
    if (depth==2 && key=="sha256") raw=value
    if (depth==2 && key=="gzSha256") gz=value
    if (depth==2 && key=="size") size=value
    if (depth==2 && key=="gzSize") gzsize=value
    key=""
    if (value=="files") key=""
  }
  if (depth!=0 || version !~ /^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$/) exit 2
  print version
  for (i=1;i<=count;i++) print files[i]
}' "$stage/unsigned.json" > "$stage/entries" || fail 'Invalid release manifest.'
version_found=$(sed -n '1p' "$stage/entries")
[ -n "$version_found" ] || fail 'Invalid release version.'
if [ -n "$version" ] && [ "$version" != "$version_found" ]; then fail 'Release version does not match MEHEN_VERSION.'; fi
version=$version_found
name="mehen-$os-$arch$libc"
if [ "$libc" = -musl ] && ! awk -F '|' -v name="$name" '$1 == name {found=1} END {exit !found}' "$stage/entries"; then
  fail "Mehen $version has no build for musl-based Linux, so nothing was installed. Use a glibc system for now: a later release adds the musl builds."
fi
entry=$(awk -F '|' -v name="$name" '$1 == name {print; n++} END {if(n!=1) exit 2}' "$stage/entries") || fail "Release has no unique $name."
IFS='|' read -r name raw gz size gzsize <<EOF
$entry
EOF
case "$raw$gz" in *[!a-f0-9]*) fail 'Invalid release checksum.' ;; esac
[ "${#raw}" = 64 ] && [ "${#gz}" = 64 ] || fail 'Invalid release checksum.'
case "$size" in ''|*[!0-9]*) fail 'Invalid release size.' ;; esac
case "$gzsize" in ''|*[!0-9]*) fail 'Invalid release size.' ;; esac
curl -fsSL --proto '=https,http' --proto-redir '=https' --retry 2 "$base/v$version/$name.gz" -o "$stage/mehen.gz" || fail 'Binary download failed.'
[ "$(wc -c < "$stage/mehen.gz" | tr -d ' ')" = "$gzsize" ] && [ "$(sha256_of "$stage/mehen.gz")" = "$gz" ] || fail 'Compressed checksum or size mismatch. Nothing installed.'
gzip -dc "$stage/mehen.gz" > "$stage/mehen" || fail 'Could not unpack binary. Nothing installed.'
[ "$(wc -c < "$stage/mehen" | tr -d ' ')" = "$size" ] && [ "$(sha256_of "$stage/mehen")" = "$raw" ] || fail 'Binary checksum or size mismatch. Nothing installed.'
chmod 755 "$stage/mehen"
printf '%s\n' "$raw" > "$stage/.mehen.sha256"

# --- the transaction ----------------------------------------------------------
# The pre-transaction previous pair goes aside first, so a rollback can put
# it back byte for byte; the installer never writes .mehen.previous.json.
phase=pair
if [ -e "$previous" ] || [ -L "$previous" ]; then pair_aside="$stage/previous.aside"; mv -f "$previous" "$pair_aside"; fi
if [ -e "$previous_meta" ] || [ -L "$previous_meta" ]; then meta_aside="$stage/previous-meta.aside"; mv -f "$previous_meta" "$meta_aside"; fi
if [ -f "$receipt" ] && [ ! -L "$receipt" ]; then cp -p "$receipt" "$stage/receipt.old"; old_receipt=1; fi
if [ "$existing" = 1 ]; then
  if [ -f "$target" ] && [ ! -L "$target" ]; then
    cp -p "$target" "$previous.tmp.$$"
    mv -f "$previous.tmp.$$" "$previous"
    captured=1
  else
    mv -f "$target" "$stage/old.target"
    moved_aside=1
  fi
fi
mv -f "$stage/mehen" "$target"
phase=moved
if fault receipt; then fail 'Could not write the install receipt (test fault).'; fi
mv -f "$stage/.mehen.sha256" "$receipt"
phase=done
# On success the set-aside previous pair is discarded with the stage.

if [ "$result" = forced ]; then say "Installed mehen $version at $target, replacing the mehen that was there (--force)."
else say "Installed mehen $version at $target"; fi
finish "\"$version\""

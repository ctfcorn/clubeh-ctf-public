#!/usr/bin/env bash
# Shared helpers: logging, Linode API, state, SSH, backup verification.
# Deliberately close to ~/Documents/mcserver/lib/common.sh - same shape, same
# guarantees, different payload.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="$ROOT_DIR/state"
STATE_FILE="$STATE_DIR/current.json"
CREDS_FILE="$STATE_DIR/credentials.env"
SSH_KEY="$STATE_DIR/id_ed25519"

# shellcheck source=/dev/null
source "$ROOT_DIR/config.env"

mkdir -p "$STATE_DIR" "$BACKUP_DIR"
chmod 700 "$STATE_DIR"

# ---------- logging ----------
if [[ -t 1 ]]; then
  C_RST=$'\033[0m'; C_B=$'\033[1m'; C_DIM=$'\033[2m'
  C_GRN=$'\033[32m'; C_YLW=$'\033[33m'; C_RED=$'\033[31m'; C_CYN=$'\033[36m'
else
  C_RST=""; C_B=""; C_DIM=""; C_GRN=""; C_YLW=""; C_RED=""; C_CYN=""
fi

log()   { printf '%s==>%s %s\n'  "$C_CYN$C_B" "$C_RST" "$*"; }
ok()    { printf '%s  ok%s %s\n' "$C_GRN"     "$C_RST" "$*"; }
warn()  { printf '%s  !!%s %s\n' "$C_YLW"     "$C_RST" "$*" >&2; }
die()   { printf '%s FAIL%s %s\n' "$C_RED$C_B" "$C_RST" "$*" >&2; exit 1; }
step()  { printf '\n%s%s%s\n' "$C_B" "$*" "$C_RST"; }
dim()   { printf '%s     %s%s\n' "$C_DIM" "$*" "$C_RST"; }

need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed."; }

# ---------- token ----------
load_token() {
  local src=""
  if   [[ -n "${LINODE_TOKEN:-}" ]];                        then TOKEN="$LINODE_TOKEN"; src="\$LINODE_TOKEN"
  elif [[ -s "$LINODE_TOKEN_FILE" ]];                       then TOKEN="$(tr -d '[:space:]' < "$LINODE_TOKEN_FILE")"; src="$LINODE_TOKEN_FILE"
  elif [[ -s "${LINODE_TOKEN_FILE_ALT:-/nonexistent}" ]];   then TOKEN="$(tr -d '[:space:]' < "$LINODE_TOKEN_FILE_ALT")"; src="$LINODE_TOKEN_FILE_ALT"
  elif [[ -s "${LINODE_TOKEN_FILE_ALT2:-/nonexistent}" ]];  then TOKEN="$(tr -d '[:space:]' < "$LINODE_TOKEN_FILE_ALT2")"; src="$LINODE_TOKEN_FILE_ALT2"
  else
    die "No Linode API token found. Tried:
       \$LINODE_TOKEN
       $LINODE_TOKEN_FILE
       ${LINODE_TOKEN_FILE_ALT:-}
       ${LINODE_TOKEN_FILE_ALT2:-}
     Create one at https://cloud.linode.com/profile/tokens (Linodes: Read/Write)"
  fi
  TOKEN_SRC="$src"
  [[ -n "$TOKEN" ]] || die "Linode token is empty."
}

# ---------- Linode API ----------
linode_api() {
  local method="$1" path="$2" body="${3:-}"
  local resp code out
  local args=(-sS -w '\n%{http_code}' -X "$method"
              -H "Authorization: Bearer $TOKEN"
              -H "Content-Type: application/json")
  [[ -n "$body" ]] && args+=(-d "$body")

  resp="$(curl "${args[@]}" "https://api.linode.com/v4${path}")" || die "curl failed calling $method $path"
  code="$(printf '%s' "$resp" | tail -n1)"
  out="$(printf '%s' "$resp" | sed '$d')"

  if [[ "$code" -lt 200 || "$code" -ge 300 ]]; then
    local msg
    msg="$(printf '%s' "$out" | jq -r '.errors // [] | map((.field//"-")+": "+.reason) | join("; ")' 2>/dev/null)"
    [[ -z "$msg" || "$msg" == "null" ]] && msg="$out"
    die "Linode API $method $path -> HTTP $code
     $msg"
  fi
  printf '%s' "$out"
}

# ---------- state ----------
state_exists() { [[ -f "$STATE_FILE" ]]; }
state_get()    { [[ -f "$STATE_FILE" ]] && jq -r --arg k "$1" '.[$k] // empty' "$STATE_FILE" || true; }

state_write() {
  printf '%s\n' "$1" | jq . > "$STATE_FILE.tmp" && mv "$STATE_FILE.tmp" "$STATE_FILE"
  chmod 600 "$STATE_FILE"
}

state_set() {
  local tmp; tmp="$(mktemp)"
  jq --arg k "$1" --arg v "$2" '.[$k]=$v' "$STATE_FILE" > "$tmp" && mv "$tmp" "$STATE_FILE"
  chmod 600 "$STATE_FILE"
}

require_state() {
  state_exists || die "No server is currently running (no state/current.json).
     Start one with:  ./ctfl up"
}

# ---------- credentials ----------
rand_pw() { LC_ALL=C head -c 512 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c1-24; }

# Credentials live in state/ and OUTLIVE a teardown, because a restored backup
# still contains the password hashes that were set when it was taken. Rotating
# them here would lock you out of your own archive.
ensure_credentials() {
  if [[ ! -f "$CREDS_FILE" ]]; then
    log "generating credentials (stored 0600 in state/credentials.env, kept across teardowns)"
    { printf 'CTFD_ADMIN_PW=%s\n'  "${CTFD_ADMIN_PASSWORD:-$(rand_pw)}"
      printf 'CTFD_DB_PW=%s\n'     "$(rand_pw)"
      printf 'CTFD_DB_ROOT_PW=%s\n' "$(rand_pw)"
      printf 'CTFD_SECRET_KEY=%s\n' "$(rand_pw)$(rand_pw)"
    } > "$CREDS_FILE"
    chmod 600 "$CREDS_FILE"
  fi
  # shellcheck source=/dev/null
  source "$CREDS_FILE"
  # An explicit password in config.env always wins, but warn if it disagrees
  # with what a restorable backup was built against.
  if [[ -n "${CTFD_ADMIN_PASSWORD:-}" && "$CTFD_ADMIN_PASSWORD" != "$CTFD_ADMIN_PW" ]]; then
    warn "config.env CTFD_ADMIN_PASSWORD differs from state/credentials.env."
    dim "A restored backup keeps the OLD password; a fresh CTFd gets the new one."
    CTFD_ADMIN_PW="$CTFD_ADMIN_PASSWORD"
  fi
}

# ---------- ssh ----------
ensure_ssh_key() {
  if [[ ! -f "$SSH_KEY" ]]; then
    log "Generating a dedicated SSH keypair for this server ($SSH_KEY)"
    ssh-keygen -t ed25519 -N '' -C 'ctflite' -f "$SSH_KEY" >/dev/null
    chmod 600 "$SSH_KEY"
  fi
}

SSH_OPTS=(-i "$SSH_KEY"
          -o StrictHostKeyChecking=no
          -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR
          -o ConnectTimeout=10
          -o ServerAliveInterval=15)

rsh()  { ssh  "${SSH_OPTS[@]}" "root@$(state_get ip)" "$@"; }
rcp()  { scp  "${SSH_OPTS[@]}" "$@"; }

# ---------- misc ----------
human_size() {
  local b="$1"
  if   (( b > 1073741824 )); then awk -v b="$b" 'BEGIN{printf "%.2f GB", b/1073741824}'
  elif (( b > 1048576 ));    then awk -v b="$b" 'BEGIN{printf "%.1f MB", b/1048576}'
  else                            awk -v b="$b" 'BEGIN{printf "%.1f KB", b/1024}'
  fi
}

epoch_of() {
  local ts="${1%%.*}"; ts="${ts%Z}"
  if date -u -d "1970-01-01" +%s >/dev/null 2>&1; then
    date -u -d "${ts}Z" +%s 2>/dev/null || echo 0
  else
    date -u -j -f "%Y-%m-%dT%H:%M:%S" "$ts" +%s 2>/dev/null || echo 0
  fi
}

hourly_rate() { linode_api GET "/linode/types/${LINODE_TYPE}" | jq -r '.price.hourly'; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

confirm() {
  [[ "${FORCE:-0}" == "1" ]] && return 0
  local reply
  printf '%s%s%s [y/N] ' "$C_YLW$C_B" "$1" "$C_RST"
  read -r reply </dev/tty || return 1
  [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# -4/-6 are forced: an unqualified curl to ifconfig.me returns whichever family
# the machine happens to prefer, and a v6 address with /32 stuck on the end is
# an invalid ufw rule that silently locks SSH out of the box.
my_public_ip4() {
  local ip
  ip="$(curl -4 -sS --max-time 10 https://ifconfig.me 2>/dev/null || true)"
  [[ -z "$ip" ]] && ip="$(curl -4 -sS --max-time 10 https://api.ipify.org 2>/dev/null || true)"
  printf '%s' "$ip" | tr -d '[:space:]'
}
my_public_ip6() {
  local ip
  ip="$(curl -6 -sS --max-time 10 https://ifconfig.me 2>/dev/null || true)"
  [[ -z "$ip" ]] && ip="$(curl -6 -sS --max-time 10 https://api6.ipify.org 2>/dev/null || true)"
  printf '%s' "$ip" | tr -d '[:space:]'
}
# Back-compat for callers that just want "an" address to show the user.
my_public_ip() { local v4; v4="$(my_public_ip4)"; [[ -n "$v4" ]] && printf '%s' "$v4" || my_public_ip6; }

# ---------- backup verification ----------
# Four independent checks, same contract as mcserver: returns non-zero if ANY
# fails, so the caller can refuse to delete the server. The last check is the
# one that matters - an archive without the SQL dump is not a CTF.
verify_archive() {
  local f="$1" want_sha="$2" want_size="$3" got_size got_sha

  got_size="$(wc -c <"$f" | tr -d ' ')"
  if [[ "$got_size" != "$want_size" ]]; then
    warn "1/4 SIZE MISMATCH: remote $want_size vs local $got_size"; return 1
  fi
  ok "1/4 size matches ($(human_size "$got_size"))"

  got_sha="$(sha256_of "$f")"
  if [[ "$got_sha" != "$want_sha" ]]; then
    warn "2/4 CHECKSUM MISMATCH
     remote $want_sha
     local  $got_sha"; return 1
  fi
  ok "2/4 sha256 matches"

  if ! tar tzf "$f" >/dev/null 2>&1; then
    warn "3/4 ARCHIVE UNREADABLE locally (truncated or corrupt gzip/tar)"; return 1
  fi
  ok "3/4 gzip + tar integrity OK"

  if ! tar tzf "$f" 2>/dev/null | grep -qE '(^|/)ctfd-db\.sql$'; then
    warn "4/4 NO ctfd-db.sql IN ARCHIVE - this does not contain the CTFd database.
     Inspect with: tar tzf '$f' | head -50"; return 1
  fi
  ok "4/4 ctfd-db.sql present"

  return 0
}

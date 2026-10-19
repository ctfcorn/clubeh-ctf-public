#!/usr/bin/env bash
#
# ctf_manager.sh - Linode CTF infrastructure control plane
#
# Deploys a 4-node CTF range into a single Linode VPC:
#   10.0.0.2  gateway   OpenVPN + nftables + NAT for the private nodes
#   10.0.0.3  ctfd      CTFd + Caddy + private registry + Swarm manager
#   10.0.0.4  challenge Swarm worker, zero WAN egress, runs untrusted code
#   10.0.0.5  wazuh     single-node SIEM, admin-VPN reachable only
#
# Written for bash 3.2 so it runs on stock macOS: no associative arrays,
# no mapfile, no ${var^^}. PKI is built with openssl directly (no easy-rsa).
#
set -euo pipefail

# ============================== CONFIGURATION ================================
CTF_TAG="ctf-event"
# us-east (Newark) has NO VPC capability - verified against the Regions API.
# us-iad is the nearest region with VPC + Metadata + Cloud Firewall. Other
# valid choices: us-ord (Chicago), us-sea (Seattle), us-lax, us-mia.
CTF_REGION="us-iad"
EVENT_NAME="club.eh CTF"
# Registration code: when non-empty, CTFd requires players to enter it to sign
# up. Lives in ctf_secrets.env (REGISTRATION_CODE=...) and is applied to CTFd on
# every deploy/register. Empty = open registration.
REGISTRATION_CODE="${REGISTRATION_CODE:-}"

# Leave CTF_DOMAIN empty to serve CTFd over a self-signed cert on the node's
# public IP (testing). Set it to a real hostname to switch Caddy to automatic
# Let's Encrypt - free, no account registration, no payment. Create the A
# record at your registrar first; deploy will verify it resolves.
CTF_DOMAIN=""
ACME_EMAIL="you@example.com"

CTFD_ADMIN_USER="ctf-admin"
PLAYER_COUNT=50

# CTFd scoring mode. "teams" lets players form teams and is what per-team
# instance isolation keys on. NOTE: CTFd fixes this at first-run setup and
# CANNOT change it later - switching means a fresh deployment.
CTF_USER_MODE="teams"
CTF_TEAM_SIZE="4"                 # max members per team

# Per-team instance isolation: players may reach only the whale instance ports
# their own team owns. In "users" mode this degrades to per-player isolation
# automatically. Set to "false" to fall back to the old open-range behaviour.
INSTANCE_ISOLATION="true"
ISOLATION_POLL_SECS=5

# Plans: g6-standard-2 = 4GB/2, g6-standard-6 = 16GB/6
TYPE_GATEWAY="g6-standard-2"
TYPE_CTFD="g6-standard-2"
# 8 GB: per-player instances (whale) mean peak load = concurrent players x
# instance size, on top of the static set. 4 GB fits ~45 players at 64 MB.
TYPE_CHALLENGE="g6-standard-6"
TYPE_WAZUH="g6-standard-6"
NODE_IMAGE="linode/ubuntu24.04"
ENABLE_LINODE_BACKUPS="false"

# Network plan
VPC_LABEL="ctf-vpc"
VPC_CIDR="10.0.0.0/24"
VPC_CIDR_NET="10.0.0.0"
GW_VPC_IP="10.0.0.2"
CTFD_VPC_IP="10.0.0.3"
CHAL_VPC_IP="10.0.0.4"
SIEM_VPC_IP="10.0.0.5"

VPN_NET="10.8.0.0"
VPN_MASK="255.255.255.0"
VPN_OCTETS="10.8.0"
VPN_ADMIN_IP="10.8.0.50"
# Extra admin seats (full access: Wazuh/VPC/gateway). Each a distinct cert +
# pinned VPN IP; the gateway firewall admin rule accepts ADMIN_VPN_RANGE. Kept in
# ctf_secrets.env; re-provision after a redeploy with scripts/extra-admins.sh.
ADMIN_SEATS="admin:10.8.0.50 admin2:10.8.0.51 admin3:10.8.0.52 admin4:10.8.0.53 admin5:10.8.0.54 admin6:10.8.0.55 admin7:10.8.0.56 admin8:10.8.0.57 admin9:10.8.0.58"
ADMIN_VPN_RANGE="10.8.0.50-10.8.0.58"
PLAYER_BASE_LAST=100
CHAL_PORT_LO=30000
CHAL_PORT_HI=32767
CHAL_NET="172.30.0.0/16"
CHAL_NET_NAME="ctf_challenges"

# Pinned image tags (all verified to exist on Docker Hub)
CTFD_IMAGE_TAG="3.8.7"
MARIADB_TAG="10.11"
REDIS_TAG="7.4-alpine"
CADDY_TAG="2.11.4-alpine"
REGISTRY_TAG="3.1.1"
WAZUH_BRANCH="4.14"

# ctfd-whale: per-player challenge instances. Pinned to a reviewed commit.
WHALE_REPO="https://github.com/frankli0324/ctfd-whale"
WHALE_COMMIT="2cc84a904a3f"
FRP_VERSION="0.42.0"              # frankli0324/frp:frps_<v> / frpc_<v> - INI-era frp whale's router speaks
SOCKET_PROXY_TAG="0.3.0"          # tecnativa/docker-socket-proxy
# Hint pricing. Hints are charged as a PERCENTAGE of the challenge's value, one
# number per hint in order: "15 35" = hint 1 costs 15% of the points, hint 2
# costs 35%. Hint 2 is usually close to a full solution; if it is free, every
# challenge collapses into "click hint 2 and paste" no matter how well it is
# designed. Set HINT_PCT="0 0" for a purely instructional event.
HINT_PCT="15 35"
# Legacy flat override: if > 0, every hint costs exactly this many points.
HINT_COST=0
# Attach hints to CTFd at all? Hint TEXT is always kept in each challenge's
# README.md (## Hints) and questions.json - this only controls whether they are
# pushed to the live scoreboard. Off by default; turn on/off any time with
# `./ctf_manager.sh hints on` / `hints off` (or ATTACH_HINTS=true ./ctf_manager.sh register).
ATTACH_HINTS="${ATTACH_HINTS:-false}"
# Unlock order: RULES_CHALLENGE -> GATE_CHALLENGE -> everything else.
# Leave RULES_CHALLENGE empty to gate on start-here alone.
RULES_CHALLENGE="rules"
GATE_CHALLENGE="start-here"
# Auto-create CTFd entries for static challenges (name/category/points/desc/flag/hints).
REGISTER_STATIC="true"
FRP_PORT_LO=10000                 # player-facing 'direct' instance ports, published on the CTFd VPC address
FRP_PORT_HI=10100
WHALE_INSTANCE_TIMEOUT=3600       # seconds an instance lives before the reaper removes it
WHALE_MAX_INSTANCES=60            # global cap on concurrent instances
WHALE_MAX_RENEW=5
WHALE_SUBNET="172.31.0.0/16"      # per-instance networks for grouped challenges; inside CONTAINER_NETS
FLAG_PREFIX="clubeh"

CERT_DAYS=120
CA_DAYS=365

# ================================ PATHS ======================================
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="$BASE_DIR/pki"
PROFILE_DIR="$BASE_DIR/profiles"
TPL_DIR="$BASE_DIR/cloud-init"
PLUGIN_SRC="$BASE_DIR/plugins/vpn_handout"
STATE_FILE="$BASE_DIR/ctf_state.json"
SECRETS_FILE="$BASE_DIR/ctf_secrets.env"
TOKEN_FILE="$BASE_DIR/personal_access_token.txt"
KNOWN_HOSTS="$BASE_DIR/.ssh_known_hosts"
ARCHIVE_DIR="$BASE_DIR/archive"
SSH_KEY="${CTF_SSH_KEY:-$HOME/.ssh/ctf_ed25519}"

# ================================ OUTPUT =====================================
if [ -t 2 ]; then
  C_RST=$'\033[0m'; C_R=$'\033[31m'; C_G=$'\033[32m'
  C_Y=$'\033[33m'; C_B=$'\033[36m'; C_BOLD=$'\033[1m'
else
  C_RST=""; C_R=""; C_G=""; C_Y=""; C_B=""; C_BOLD=""
fi
# Diagnostics go to stderr so functions whose stdout is captured with $(...)
# (create_node, render_check, validate_challenges) never leak log lines into
# the value being returned.
log()  { printf '%s[*]%s %s\n' "$C_B" "$C_RST" "$*" >&2; }
ok()   { printf '%s[+]%s %s\n' "$C_G" "$C_RST" "$*" >&2; }
warn() { printf '%s[!]%s %s\n' "$C_Y" "$C_RST" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$C_R" "$C_RST" "$*" >&2; exit 1; }
hr()   { printf '%s\n' "------------------------------------------------------------------"; }

# ============================== SMALL HELPERS ================================
# Single-line base64, portable across macOS (no -w0) and Linux.
b64() { openssl base64 -A -in "$1"; }
b64s() { printf '%s' "$1" | openssl base64 -A; }
# `head -c` would close the pipe early and SIGPIPE tr, which `set -o pipefail`
# turns into a fatal error. cut drains the stream instead.
rand_pw() { openssl rand -base64 256 | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c1-"${1:-28}"; }
rand_hex() { openssl rand -hex "${1:-32}"; }

# Substitute __PLACEHOLDER__ tokens from a TAB-separated key/value file.
# Unknown placeholders are left intact so render_check can catch them.
render_template() {
  perl -e '
    my ($tpl,$subs) = @ARGV;
    my %h;
    open(my $s, "<", $subs) or die "subs: $!";
    while (<$s>) { chomp; my ($k,$v) = split(/\t/, $_, 2); $h{$k} = defined($v) ? $v : ""; }
    close($s);
    open(my $t, "<", $tpl) or die "tpl: $!";
    local $/; my $c = <$t>; close($t);
    $c =~ s/__([A-Z0-9_]+)__/exists $h{$1} ? $h{$1} : "__${1}__"/ge;
    print $c;
  ' "$1" "$2"
}

render_check() {
  local f="$1" left
  left="$(grep -o '__[A-Z0-9_]\{3,\}__' "$f" | sort -u | tr '\n' ' ' || true)"
  [ -z "$left" ] || die "unsubstituted placeholders in $(basename "$f"): $left"
  # Linode rejects user_data whose DECODED size exceeds 16384 bytes (verified
  # live: "decoded user_data must not exceed 16384 bytes"). cloud-init
  # transparently gunzips user-data, so the payload is gzip'd before base64;
  # the limit applies to the compressed bytes.
  local raw gz; raw=$(wc -c < "$f" | tr -d ' '); gz=$(gzip -9c "$f" | wc -c | tr -d ' ')
  [ "$gz" -lt 16384 ] || die "$(basename "$f") is ${gz}B gzipped (${raw}B raw), over Linode's 16384B decoded user_data limit"
  printf '%s' "$gz"
}

# =============================== LINODE API ==================================
LINODE_TOKEN=""
load_token() {
  [ -f "$TOKEN_FILE" ] || die "missing $TOKEN_FILE"
  LINODE_TOKEN="$(tr -d ' \t\r\n' < "$TOKEN_FILE")"
  [ -n "$LINODE_TOKEN" ] || die "$TOKEN_FILE is empty"
  export LINODE_CLI_TOKEN="$LINODE_TOKEN"
}

lin() { linode-cli --json --suppress-warnings "$@"; }

# linode-cli cannot express the nested rules[] array of a Cloud Firewall, so
# firewall objects go through the REST API directly. Everything else uses the CLI.
api() {
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sS -X "$method" \
      -H "Authorization: Bearer $LINODE_TOKEN" \
      -H "Content-Type: application/json" \
      -d "$body" "https://api.linode.com/v4$path"
  else
    curl -sS -X "$method" -H "Authorization: Bearer $LINODE_TOKEN" \
      "https://api.linode.com/v4$path"
  fi
}

api_check() {
  local resp="$1" what="$2"
  if printf '%s' "$resp" | jq -e '.errors' >/dev/null 2>&1; then
    die "$what failed: $(printf '%s' "$resp" | jq -c '.errors')"
  fi
}

# ================================== SSH ======================================
SSH_OPTS_BASE="-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ServerAliveInterval=15"
# NOTE: `ssh -J` spawns an inner `ssh -W` for the jump hop that does NOT
# inherit -i / -o UserKnownHostsFile / StrictHostKeyChecking. Verified live: the
# inner hop looked for ~/.ssh/known_hosts and failed. An explicit ProxyCommand
# carries the full option set to both legs.
jump_cmd() { printf 'ssh -i %s -o UserKnownHostsFile=%s %s -W %%h:%%p root@%s' "$SSH_KEY" "$KNOWN_HOSTS" "$SSH_OPTS_BASE" "$1"; }
ssh_gw()  { ssh -i "$SSH_KEY" -o UserKnownHostsFile="$KNOWN_HOSTS" $SSH_OPTS_BASE root@"$1" "${@:2}"; }
ssh_via() { ssh -i "$SSH_KEY" -o UserKnownHostsFile="$KNOWN_HOSTS" $SSH_OPTS_BASE -o ProxyCommand="$(jump_cmd "$2")" root@"$1" "${@:3}"; }
scp_via() { scp -i "$SSH_KEY" -o UserKnownHostsFile="$KNOWN_HOSTS" $SSH_OPTS_BASE -o ProxyCommand="$(jump_cmd "$3")" -r "$1" root@"$2"; }
scp_pub() { scp -i "$SSH_KEY" -o UserKnownHostsFile="$KNOWN_HOSTS" $SSH_OPTS_BASE -r "$1" root@"$2"; }

wait_for_ssh() {
  local ip="$1" label="$2" tries="${3:-60}" i=1
  log "waiting for SSH on $label ($ip)"
  while [ "$i" -le "$tries" ]; do
    if ssh -i "$SSH_KEY" -o UserKnownHostsFile="$KNOWN_HOSTS" $SSH_OPTS_BASE \
        root@"$ip" true 2>/dev/null; then
      ok "$label reachable over SSH"; return 0
    fi
    sleep 10; i=$((i+1))
  done
  die "$label never became reachable over SSH"
}

# Blocks on a cloud-init sentinel. This is what removes the deploy race: the
# private nodes are not created until the gateway is actually NATting, and
# post-provision does not start until each node's cloud-init has finished.
wait_for_sentinel() {
  local ip="$1" label="$2" file="$3" jump="${4:-}" tries="${5:-90}" i=1
  log "waiting for $label to signal ready ($file)"
  while [ "$i" -le "$tries" ]; do
    if [ -n "$jump" ]; then
      ssh_via "$ip" "$jump" "test -f $file" 2>/dev/null && { ok "$label ready"; return 0; }
    else
      ssh_gw "$ip" "test -f $file" 2>/dev/null && { ok "$label ready"; return 0; }
    fi
    sleep 20; i=$((i+1))
  done
  die "$label did not signal ready within $((tries*20))s (check /var/log/cloud-init-output.log)"
}

# Resolve an A record without assuming dig exists (macOS may not ship it).
resolve_a() {
  local h="$1" r=""
  if command -v dig >/dev/null 2>&1; then
    r="$(dig +short "$h" A 2>/dev/null | grep -E '^[0-9.]+$' | tail -1 || true)"
  elif command -v host >/dev/null 2>&1; then
    r="$(host -t A "$h" 2>/dev/null | awk '/has address/ {print $NF}' | tail -1 || true)"
  else
    r="$(nslookup -type=A "$h" 2>/dev/null | awk '/^Address: /{print $2}' | tail -1 || true)"
  fi
  printf '%s' "$r"
}

# ============================== PREREQUISITES ================================
ADMIN_IP_V4=""
ADMIN_IP_V6=""

detect_admin_ips() {
  # Re-detected on every run so the firewall follows you between networks.
  ADMIN_IP_V4="$(curl -4 -fsS --max-time 10 https://ifconfig.me 2>/dev/null || \
                 curl -4 -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)"
  ADMIN_IP_V6="$(curl -6 -fsS --max-time 10 https://ifconfig.me 2>/dev/null || true)"
  printf '%s' "$ADMIN_IP_V4" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || die "could not determine your public IPv4 (got '${ADMIN_IP_V4:-nothing}'); check connectivity"
  ok "your IPv4: $ADMIN_IP_V4"
  # On an IPv4-only network `curl -6` can still return a v4 address via a
  # fallback path (seen live). Only trust something that looks like IPv6.
  printf '%s' "$ADMIN_IP_V6" | grep -Eq '^[0-9a-fA-F:]+$' && printf '%s' "$ADMIN_IP_V6" | grep -q ':' || ADMIN_IP_V6=""
  if [ -n "$ADMIN_IP_V6" ]; then
    # SLAAC privacy addresses rotate every few hours; pinning the /128 would
    # lock you out by tomorrow. Allow-list the stable /64 prefix instead.
    ADMIN_IP_V6="$(printf '%s' "$ADMIN_IP_V6" | awk -F: '{printf "%s:%s:%s:%s::", $1,$2,$3,$4}')/64"
    ok "your IPv6 prefix: $ADMIN_IP_V6"
  fi
}

# Accumulated allow-list across every network you have deployed or run status
# from, so moving between home / campus / conference wifi keeps working.
known_ips_json() {
  local existing='[]'
  [ -f "$STATE_FILE" ] && existing="$(jq -c '.known_admin_ips // []' "$STATE_FILE" 2>/dev/null || echo '[]')"
  local add="[\"$ADMIN_IP_V4/32\"]"
  printf '%s' "$existing" | jq -c --argjson a "$add" '. + $a | unique'
}
known_ips6_json() {
  local existing='[]'
  [ -f "$STATE_FILE" ] && existing="$(jq -c '.known_admin_ips6 // []' "$STATE_FILE" 2>/dev/null || echo '[]')"
  local add='[]'
  [ -n "$ADMIN_IP_V6" ] && add="[\"$ADMIN_IP_V6\"]"
  printf '%s' "$existing" | jq -c --argjson a "$add" '. + $a | unique'
}

# pip installs linode-cli into a per-user bin that is often not on PATH
# (verified on this Mac: ~/Library/Python/3.9/bin). Find it ourselves rather
# than making the operator edit their shell profile.
ensure_cli_path() {
  command -v linode-cli >/dev/null 2>&1 && return 0
  local d
  for d in "$HOME/Library/Python"/*/bin "$HOME/.local/bin" /opt/homebrew/bin /usr/local/bin; do
    if [ -x "$d/linode-cli" ]; then
      PATH="$d:$PATH"; export PATH
      log "found linode-cli in $d (added to PATH for this run)"
      return 0
    fi
  done
  return 1
}

preflight() {
  log "checking prerequisites"
  ensure_cli_path || true
  local missing=""
  for c in linode-cli jq openssl curl ssh scp perl; do
    command -v "$c" >/dev/null 2>&1 || missing="$missing $c"
  done
  if [ -n "$missing" ]; then
    warn "missing:$missing"
    cat <<'HINT'
  Install with:
    python3 -m pip install --user linode-cli     # or: brew install linode-cli
    brew install jq openssl
HINT
    die "install the tools above and re-run"
  fi
  openssl ecparam -list_curves >/dev/null 2>&1 || die "openssl lacks EC support"
  if ! openssl version 2>/dev/null | grep -q "^OpenSSL"; then
    local real=""
    for c in /opt/homebrew/bin/openssl /usr/local/opt/openssl@3/bin/openssl /usr/local/bin/openssl; do
      [ -x "$c" ] && "$c" version 2>/dev/null | grep -q "^OpenSSL" && { real="$c"; break; }
    done
    if [ -n "$real" ]; then
      PATH="$(dirname "$real"):$PATH"; export PATH
      log "using $real (system openssl is $(/usr/bin/openssl version 2>/dev/null | cut -d" " -f1))"
    else
      die "need real OpenSSL, found $(openssl version). Install with: brew install openssl"
    fi
  fi
  [ -f "$SSH_KEY" ] || die "SSH key not found at $SSH_KEY (set CTF_SSH_KEY to override)"
  [ -f "$SSH_KEY.pub" ] || die "SSH public key not found at $SSH_KEY.pub"
  for t in node1-gateway node2-ctfd node3-challenge node4-wazuh; do
    [ -f "$TPL_DIR/$t.yaml.tpl" ] || die "missing template $TPL_DIR/$t.yaml.tpl"
  done
  [ -f "$PLUGIN_SRC/__init__.py" ] || die "missing CTFd plugin at $PLUGIN_SRC"
  load_token
  local probe; probe="$(api GET '/linode/instances?page_size=25' || true)"
  printf '%s' "$probe" | jq -e '.data' >/dev/null 2>&1 \
    || die "Linode token rejected: $(printf '%s' "$probe" | jq -rc '.errors[0].reason // "no response"'). Check $TOKEN_FILE and its scopes (linodes, vpcs, firewalls, ips: read/write)."
  ok "linode token accepted"
  local caps; caps="$(api GET "/regions/$CTF_REGION" | jq -r '.capabilities | join(",")' 2>/dev/null || true)"
  for need in VPCs Metadata "Cloud Firewall"; do
    printf '%s' "$caps" | grep -q "$need" || die "region $CTF_REGION lacks '$need' - pick one from: linode-cli regions list"
  done
  ok "region $CTF_REGION supports VPC, Metadata and Cloud Firewall"
  ok "prerequisites satisfied"
}

# ================================== PKI ======================================
# Deliberately built with plain openssl rather than easy-rsa: fewer moving
# parts, one less dependency to install, and a real `openssl ca` database so
# mid-event certificate revocation (menu option 4) actually works.
pki_config() {
  cat > "$PKI_DIR/ca/openssl.cnf" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
new_certs_dir  = $PKI_DIR/ca/newcerts
database       = $PKI_DIR/ca/index.txt
serial         = $PKI_DIR/ca/serial
crlnumber      = $PKI_DIR/ca/crlnumber
private_key    = $PKI_DIR/ca/ca.key
certificate    = $PKI_DIR/ca/ca.crt
default_md     = sha256
default_days   = $CERT_DAYS
default_crl_days = 30
policy         = policy_anything
email_in_dn    = no
rand_serial    = no
unique_subject = no
copy_extensions = none
preserve       = no

[ policy_anything ]
commonName             = supplied
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
emailAddress           = optional

[ req ]
distinguished_name = req_dn
prompt             = no
string_mask        = utf8only

[ req_dn ]
CN = placeholder

[ v3_ca ]
basicConstraints       = critical,CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash

[ server_cert ]
basicConstraints       = CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer

[ client_cert ]
basicConstraints       = CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = clientAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
EOF
}

pki_sign() {
  # $1 = name, $2 = extension section, $3 = output dir
  local name="$1" ext="$2" dir="$3"
  openssl ecparam -name prime256v1 -genkey -noout -out "$dir/$name.key"
  chmod 600 "$dir/$name.key"
  openssl req -new -key "$dir/$name.key" -out "$dir/$name.csr" -subj "/CN=$name" -sha256
  openssl ca -batch -config "$PKI_DIR/ca/openssl.cnf" -extensions "$ext" \
    -days "$CERT_DAYS" -notext -in "$dir/$name.csr" -out "$dir/$name.crt" 2>/dev/null
  rm -f "$dir/$name.csr"
}

pki_gencrl() {
  openssl ca -config "$PKI_DIR/ca/openssl.cnf" -gencrl -out "$PKI_DIR/crl.pem" 2>/dev/null
}

# OpenVPN tls-crypt static key: 2048 bits as 16 lines of 32 hex chars. Written
# by hand so the OpenVPN binary is not needed on the control machine.
gen_tls_crypt() {
  {
    echo "#"
    echo "# 2048 bit OpenVPN static key"
    echo "#"
    echo "-----BEGIN OpenVPN Static key V1-----"
    openssl rand -hex 256 | fold -w 32
    echo "-----END OpenVPN Static key V1-----"
  } > "$1"
  chmod 600 "$1"
}

generate_pki() {
  if [ -d "$PKI_DIR/ca" ] && [ -f "$PKI_DIR/ca/ca.crt" ]; then
    warn "reusing existing PKI in $PKI_DIR (delete it to regenerate)"
    return 0
  fi
  log "generating PKI (1 CA + 1 server + $((PLAYER_COUNT + 1)) clients)"
  rm -rf "$PKI_DIR"
  mkdir -p "$PKI_DIR/ca/newcerts" "$PKI_DIR/server" "$PKI_DIR/clients"
  chmod 700 "$PKI_DIR" "$PKI_DIR/ca"
  : > "$PKI_DIR/ca/index.txt"
  echo "unique_subject = no" > "$PKI_DIR/ca/index.txt.attr"
  echo "01" > "$PKI_DIR/ca/serial"
  echo "01" > "$PKI_DIR/ca/crlnumber"
  pki_config

  # CA. The private key stays on this machine and is NEVER placed in
  # cloud-init, uploaded, or copied to a node.
  openssl ecparam -name secp384r1 -genkey -noout -out "$PKI_DIR/ca/ca.key"
  chmod 600 "$PKI_DIR/ca/ca.key"
  openssl req -x509 -new -key "$PKI_DIR/ca/ca.key" -sha384 -days "$CA_DAYS" \
    -out "$PKI_DIR/ca/ca.crt" -subj "/CN=$EVENT_NAME CA" \
    -config "$PKI_DIR/ca/openssl.cnf" -extensions v3_ca

  pki_sign "server" "server_cert" "$PKI_DIR/server"
  pki_sign "admin"  "client_cert" "$PKI_DIR/clients"
  local i n
  i=1
  while [ "$i" -le "$PLAYER_COUNT" ]; do
    n="$(printf 'player%02d' "$i")"
    pki_sign "$n" "client_cert" "$PKI_DIR/clients"
    i=$((i+1))
  done

  gen_tls_crypt "$PKI_DIR/tls-crypt.key"
  pki_gencrl
  ok "PKI generated in $PKI_DIR"
}

# Profiles are assembled once the gateway's public IP is known, then delivered
# to CTFd over SSH. 51 profiles are ~400KB - far past the 64KB user_data cap,
# so they cannot travel in cloud-init.
build_profiles() {
  local remote="$1"
  log "assembling $((PLAYER_COUNT + 1)) .ovpn profiles for endpoint $remote"
  rm -rf "$PROFILE_DIR"; mkdir -p "$PROFILE_DIR"; chmod 700 "$PROFILE_DIR"
  local names="admin" i
  i=1
  while [ "$i" -le "$PLAYER_COUNT" ]; do
    names="$names $(printf 'player%02d' "$i")"
    i=$((i+1))
  done
  local name
  for name in $names; do
    {
      cat <<PROF
client
dev tun
proto udp
remote $remote 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
tls-version-min 1.2
verb 3
PROF
      echo "<ca>";        cat "$PKI_DIR/ca/ca.crt";            echo "</ca>"
      echo "<cert>";      openssl x509 -in "$PKI_DIR/clients/$name.crt"; echo "</cert>"
      echo "<key>";       cat "$PKI_DIR/clients/$name.key";    echo "</key>"
      echo "<tls-crypt>"; cat "$PKI_DIR/tls-crypt.key";        echo "</tls-crypt>"
    } > "$PROFILE_DIR/$name.ovpn"
    chmod 600 "$PROFILE_DIR/$name.ovpn"
  done
  ok "profiles written to $PROFILE_DIR"
}

# ============================ RENDERED SECRETS ===============================
CTFD_DB_PW=""; CTFD_DB_ROOT_PW=""; CTFD_SECRET_KEY=""
CTFD_ADMIN_PW=""; WAZUH_AUTHD_PASS=""
FRP_TOKEN=""; FRPC_ADMIN_PW=""; ISOLATION_TOKEN=""
GW_ROOT_PW=""; CTFD_ROOT_PW=""; CHAL_ROOT_PW=""; SIEM_ROOT_PW=""; WAZUH_ADMIN_PW=""

generate_secrets() {
  if [ -s "$SECRETS_FILE" ] && [ -f "$STATE_FILE" ]; then
    die "refusing to regenerate secrets: $SECRETS_FILE belongs to a live deployment (state file present). Tear down first."
  fi
  log "generating shared secrets"
  CTFD_DB_PW="$(rand_pw 32)"
  CTFD_DB_ROOT_PW="$(rand_pw 32)"
  CTFD_SECRET_KEY="$(rand_hex 32)"
  CTFD_ADMIN_PW="$(rand_pw 24)"
  WAZUH_AUTHD_PASS="$(rand_pw 32)"
  FRP_TOKEN="$(rand_pw 40)"
  FRPC_ADMIN_PW="$(rand_pw 32)"
  ISOLATION_TOKEN="$(rand_pw 40)"
  GW_ROOT_PW="$(rand_pw 32)"; CTFD_ROOT_PW="$(rand_pw 32)"
  CHAL_ROOT_PW="$(rand_pw 32)"; SIEM_ROOT_PW="$(rand_pw 32)"
  save_secrets
  ok "secrets generated (never echoed; stored 0600 in $(basename "$SECRETS_FILE"))"
}

nft_set_v4() { printf '%s' "$(known_ips_json)" | jq -r 'join(", ")'; }
nft_set_v6() {
  local s; s="$(printf '%s' "$(known_ips6_json)" | jq -r 'join(", ")')"
  # An empty nftables set is a syntax error. 100::/64 is the RFC 6666
  # discard prefix: a valid element that can never match real traffic.
  [ -n "$s" ] && printf '%s' "$s" || printf '100::/64'
}

write_common_subs() {
  local f="$1"
  {
    printf 'VPC_CIDR\t%s\n'        "$VPC_CIDR"
    printf 'VPC_CIDR_NET\t%s\n'    "$VPC_CIDR_NET"
    printf 'GW_VPC_IP\t%s\n'       "$GW_VPC_IP"
    printf 'CTFD_VPC_IP\t%s\n'     "$CTFD_VPC_IP"
    printf 'CHAL_VPC_IP\t%s\n'     "$CHAL_VPC_IP"
    printf 'SIEM_VPC_IP\t%s\n'     "$SIEM_VPC_IP"
    printf 'VPN_NET\t%s\n'         "$VPN_NET"
    printf 'VPN_MASK\t%s\n'        "$VPN_MASK"
    printf 'VPN_OCTETS\t%s\n'      "$VPN_OCTETS"
    printf 'VPN_ADMIN_IP\t%s\n'    "$VPN_ADMIN_IP"
    printf 'PLAYER_COUNT\t%s\n'    "$PLAYER_COUNT"
    printf 'PLAYER_BASE_LAST\t%s\n' "$PLAYER_BASE_LAST"
    printf 'PLAYER_FIRST\t%s.%s\n' "$VPN_OCTETS" "$PLAYER_BASE_LAST"
    printf 'PLAYER_LAST\t%s.%s\n'  "$VPN_OCTETS" "$((PLAYER_BASE_LAST + PLAYER_COUNT - 1))"
    printf 'MAX_CLIENTS\t%s\n'     "$((PLAYER_COUNT + 10))"
    printf 'CHAL_PORT_LO\t%s\n'    "$CHAL_PORT_LO"
    printf 'CHAL_PORT_HI\t%s\n'    "$CHAL_PORT_HI"
    printf 'CHAL_NET\t%s\n'        "$CHAL_NET"
    printf 'CHAL_NET_NAME\t%s\n'   "$CHAL_NET_NAME"
    printf 'ADMIN_SRC_V4\t%s\n'    "$(nft_set_v4)"
    printf 'ADMIN_SRC_V6\t%s\n'    "$(nft_set_v6)"
    printf 'WAZUH_AUTHD_PASS_B64\t%s\n' "$(b64s "$WAZUH_AUTHD_PASS")"
    printf 'WAZUH_BRANCH\t%s\n'    "$WAZUH_BRANCH"
    printf 'CTFD_IMAGE_TAG\t%s\n'  "$CTFD_IMAGE_TAG"
    printf 'MARIADB_TAG\t%s\n'     "$MARIADB_TAG"
    printf 'REDIS_TAG\t%s\n'       "$REDIS_TAG"
    printf 'CADDY_TAG\t%s\n'       "$CADDY_TAG"
    printf 'REGISTRY_TAG\t%s\n'    "$REGISTRY_TAG"
    printf 'WHALE_REPO\t%s\n'      "$WHALE_REPO"
    printf 'WHALE_COMMIT\t%s\n'    "$WHALE_COMMIT"
    printf 'FRP_VERSION\t%s\n'     "$FRP_VERSION"
    printf 'FRPS_IMAGE\t%s\n'      "frankli0324/frp:frps_$FRP_VERSION"
    printf 'FRPC_IMAGE\t%s\n'      "frankli0324/frp:frpc_$FRP_VERSION"
    printf 'SOCKET_PROXY_TAG\t%s\n' "$SOCKET_PROXY_TAG"
    printf 'FRP_PORT_LO\t%s\n'     "$FRP_PORT_LO"
    printf 'FRP_PORT_HI\t%s\n'     "$FRP_PORT_HI"
    printf 'FRP_SUBDOMAIN_HOST\t%s\n' "${CTF_DOMAIN:-chal.invalid}"
    printf 'ISOLATION_TOKEN_B64\t%s\n' "$(b64s "$ISOLATION_TOKEN")"
    printf 'ISOLATION_POLL_SECS\t%s\n' "$ISOLATION_POLL_SECS"
    if [ "$INSTANCE_ISOLATION" = "true" ]; then
      printf 'ISOLATION_FLAG_CMD\tmkdir -p /etc/ctf && touch /etc/ctf/instance-isolation\n'
    else
      printf 'ISOLATION_FLAG_CMD\trm -f /etc/ctf/instance-isolation; true\n'
    fi
  } > "$f"
}


build_caddyfile() {
  local out="$1"
  if [ -n "$CTF_DOMAIN" ]; then
    cat > "$out" <<EOF
{
    email $ACME_EMAIL
    admin off
}
$CTF_DOMAIN {
    encode gzip
    reverse_proxy ctfd:8000
}
# In-VPC callers reach CTFd by its private address (the gateway's instance-ACL
# poller does). Without a site block matching that Host, Caddy answers an empty
# 200 to every path - which looked exactly like a broken endpoint (found live).
https://$CTFD_VPC_IP {
    tls internal
    encode gzip
    reverse_proxy ctfd:8000
}
EOF
  else
    # No domain: Let's Encrypt cannot issue for a bare IP, so Caddy's internal
    # CA signs it. Players will see a certificate warning until CTF_DOMAIN is set.
    # Caddy will not manage a certificate for a bare `:443` block, so the site
    # address must be the actual public IP. It is not known until the node
    # exists; node 2's cloud-init resolves it at first boot and substitutes it.
    # default_sni: a client connecting to a bare IP sends no SNI, and Caddy will
    # not select the IP certificate without it (verified: TLS "internal error").
    cat > "$out" <<'EOF'
{
    admin off
    default_sni CTFD_PUBLIC_IP_AT_BOOT
}
http://CTFD_PUBLIC_IP_AT_BOOT {
    redir https://{host}{uri} permanent
}
https://CTFD_PUBLIC_IP_AT_BOOT {
    tls internal
    encode gzip
    reverse_proxy ctfd:8000
}
# In-VPC callers reach CTFd by its private address (the gateway's instance-ACL
# poller does). Without a site block matching that Host, Caddy answers an empty
# 200 to every path - which looked exactly like a broken endpoint (found live).
https://CTFD_VPC_ADDR {
    tls internal
    encode gzip
    reverse_proxy ctfd:8000
}
EOF
  fi
  # the IP-mode heredoc is quoted, so fill the VPC address in afterwards
  sed -i.bak "s|CTFD_VPC_ADDR|$CTFD_VPC_IP|" "$out" 2>/dev/null || \
    { sed "s|CTFD_VPC_ADDR|$CTFD_VPC_IP|" "$out" > "$out.new" && mv "$out.new" "$out"; }
  rm -f "$out.bak"
}

# ============================= CLOUD FIREWALLS ===============================
# Attached at instance creation so there is no window between first boot and
# cloud-init applying nftables. Enforced outside the instance, so it still
# holds if a challenge-host escape flushes the host ruleset.
fw_rule() {
  local label="$1" proto="$2" ports="$3" v4="$4" v6="$5" action="$6"
  if [ -z "$ports" ]; then
    jq -nc --arg l "$label" --arg p "$proto" --argjson v4 "$v4" --argjson v6 "$v6" --arg a "$action" \
      '{label:$l, action:$a, protocol:$p, addresses:{ipv4:$v4, ipv6:$v6}}'
  else
    jq -nc --arg l "$label" --arg p "$proto" --arg pt "$ports" --argjson v4 "$v4" --argjson v6 "$v6" --arg a "$action" \
      '{label:$l, action:$a, protocol:$p, ports:$pt, addresses:{ipv4:$v4, ipv6:$v6}}'
  fi
}

create_firewall() {
  local label="$1" inbound="$2"
  local body resp
  body="$(jq -nc --arg l "$label" --arg t "$CTF_TAG" --argjson ib "$inbound" \
    '{label:$l, tags:[$t], rules:{inbound_policy:"DROP", outbound_policy:"ACCEPT", inbound:$ib, outbound:[]}}')"
  resp="$(api POST /networking/firewalls "$body")"
  api_check "$resp" "firewall $label"
  printf '%s' "$resp" | jq -r '.id'
}

create_firewalls() {
  log "creating Cloud Firewalls"
  local adm4 adm6 anyv4 anyv6 vpc4 empty6 stamp
  adm4="$(known_ips_json)"; adm6="$(known_ips6_json)"
  anyv4='["0.0.0.0/0"]'; anyv6='["::/0"]'
  vpc4="[\"$VPC_CIDR\"]"; empty6='[]'
  stamp="$(date -u +%H%M%S)"

  # Gateway: OpenVPN from the world, SSH from your networks only.
  FW_GW_ID="$(create_firewall "ctf-gw-$stamp" "$(jq -nc \
    --argjson a "$(fw_rule ssh-admin TCP 22 "$adm4" "$adm6" ACCEPT)" \
    --argjson b "$(fw_rule openvpn UDP 1194 "$anyv4" "$anyv6" ACCEPT)" \
    --argjson c "$(fw_rule vpc-tcp TCP 1-65535 "$vpc4" "$empty6" ACCEPT)" \
    --argjson d "$(fw_rule vpc-udp UDP 1-65535 "$vpc4" "$empty6" ACCEPT)" \
    --argjson e "$(fw_rule vpc-icmp ICMP "" "$vpc4" "$empty6" ACCEPT)" \
    '[$a,$b,$c,$d,$e]')")"
  ok "gateway firewall: $FW_GW_ID"

  # CTFd: public web, SSH from your networks.
  FW_CTFD_ID="$(create_firewall "ctf-web-$stamp" "$(jq -nc \
    --argjson a "$(fw_rule ssh-admin TCP 22 "$adm4" "$adm6" ACCEPT)" \
    --argjson b "$(fw_rule web TCP 80,443 "$anyv4" "$anyv6" ACCEPT)" \
    --argjson c "$(fw_rule vpc-tcp TCP 1-65535 "$vpc4" "$empty6" ACCEPT)" \
    --argjson d "$(fw_rule vpc-udp UDP 1-65535 "$vpc4" "$empty6" ACCEPT)" \
    --argjson e "$(fw_rule vpc-icmp ICMP "" "$vpc4" "$empty6" ACCEPT)" \
    '[$a,$b,$c,$d,$e]')")"
  ok "ctfd firewall: $FW_CTFD_ID"

  # Private nodes: nothing from the internet at all. VPC peers are explicitly
  # permitted rather than relying on Cloud Firewall ignoring VPC traffic -
  # correct either way.
  FW_INT_ID="$(create_firewall "ctf-int-$stamp" "$(jq -nc \
    --argjson c "$(fw_rule vpc-tcp TCP 1-65535 "$vpc4" "$empty6" ACCEPT)" \
    --argjson d "$(fw_rule vpc-udp UDP 1-65535 "$vpc4" "$empty6" ACCEPT)" \
    --argjson e "$(fw_rule vpc-icmp ICMP "" "$vpc4" "$empty6" ACCEPT)" \
    '[$c,$d,$e]')")"
  ok "internal firewall: $FW_INT_ID"
}

sync_firewall_ips() {
  # Called by Status so a new coffee-shop IP gets allow-listed without redeploying.
  local fwid="$1" adm4 adm6 rules body resp
  adm4="$(known_ips_json)"; adm6="$(known_ips6_json)"
  resp="$(api GET "/networking/firewalls/$fwid")"
  printf '%s' "$resp" | jq -e '.id' >/dev/null 2>&1 || { warn "firewall $fwid not found"; return 1; }
  rules="$(printf '%s' "$resp" | jq -c \
    --argjson v4 "$adm4" --argjson v6 "$adm6" \
    '.rules | .inbound = [ .inbound[] | if .label == "ssh-admin"
       then .addresses.ipv4 = $v4 | .addresses.ipv6 = $v6 else . end ]')"
  body="$(jq -nc --argjson r "$rules" '{inbound:$r.inbound, outbound:$r.outbound, inbound_policy:$r.inbound_policy, outbound_policy:$r.outbound_policy}')"
  resp="$(api PUT "/networking/firewalls/$fwid/rules" "$body")"
  api_check "$resp" "firewall $fwid rule sync"
}

# ================================ PROVISION ==================================
VPC_ID=""; SUBNET_ID=""
FW_GW_ID=""; FW_CTFD_ID=""; FW_INT_ID=""
GW_ID=""; CTFD_ID=""; CHAL_ID=""; SIEM_ID=""
GW_PUB=""; CTFD_PUB=""

create_vpc() {
  log "creating VPC $VPC_LABEL ($VPC_CIDR) in $CTF_REGION"
  # Nested subnets[] is not expressible through linode-cli flags, so the VPC
  # and the firewalls go through the REST API. Everything else uses the CLI.
  local body resp
  body="$(jq -nc --arg l "$VPC_LABEL" --arg r "$CTF_REGION" --arg s "$VPC_CIDR" \
    '{label:$l, region:$r, subnets:[{label:"ctf-subnet", ipv4:$s}]}')"
  resp="$(api POST /vpcs "$body")"
  api_check "$resp" "VPC create"
  VPC_ID="$(printf '%s' "$resp" | jq -r '.id')"
  SUBNET_ID="$(printf '%s' "$resp" | jq -r '.subnets[0].id')"
  [ -n "$VPC_ID" ] && [ "$VPC_ID" != "null" ] || die "VPC create returned no id"
  ok "VPC $VPC_ID / subnet $SUBNET_ID"
}

create_node() {
  # $1 label  $2 type  $3 vpc_ip  $4 firewall_id  $5 userdata_file
  # $6 root_pw  $7 "nat" to give it a public address via 1:1 NAT
  local label="$1" type="$2" vip="$3" fwid="$4" udfile="$5" rootpw="$6" nat="${7:-}"
  local ud size resp
  size="$(render_check "$udfile")"
  ud="$(gzip -9c "$udfile" | openssl base64 -A)"
  log "creating $label ($type, vpc $vip, user-data ${size}B gzipped)"

  local -a args
  args=( linodes create
    --label "$label" --region "$CTF_REGION" --type "$type" --image "$NODE_IMAGE"
    --root_pass "$rootpw"
    --authorized_keys "$(cat "$SSH_KEY.pub")"
    --booted true --private_ip false
    --backups_enabled "$ENABLE_LINODE_BACKUPS"
    --tags "$CTF_TAG"
    --firewall_id "$fwid"
    --metadata.user_data "$ud"
    --interfaces.purpose vpc
    --interfaces.subnet_id "$SUBNET_ID"
    --interfaces.ipv4.vpc "$vip" )
  if [ "$nat" = "nat" ]; then
    # 1:1 NAT on the VPC interface gives this node public reachability without
    # a second interface. Nodes without it have NO route off the VPC.
    args=( "${args[@]}" --interfaces.ipv4.nat_1_1 any )
  fi

  resp="$(lin "${args[@]}")" || die "$label creation failed"
  printf '%s' "$resp" | jq -e '.[0].id' >/dev/null 2>&1 || die "$label create returned: $resp"
  printf '%s' "$resp" | jq -r '.[0].id, (.[0].ipv4[0] // "")'
}

# ============================== POST-PROVISION ===============================
post_provision() {
  hr; log "post-provision"

  # --- Swarm join. Docker generates join tokens on the manager; they cannot
  # --- be pre-shared. Rather than have node 3 poll for one, the control plane
  # --- reads it over SSH and issues the join. Race-free, and the token never
  # --- sits in cloud-init or on the worker's disk.
  log "joining challenge host to the swarm"
  local wtok
  wtok="$(ssh_gw "$CTFD_PUB" 'docker swarm join-token -q worker' | tr -d '\r\n')"
  [ -n "$wtok" ] || die "could not read swarm worker token from CTFd node"
  ssh_via "$CHAL_VPC_IP" "$GW_PUB" \
    "docker swarm join --token $wtok $CTFD_VPC_IP:2377 || docker info 2>/dev/null | grep -q 'Swarm: active'"
  ok "challenge host joined swarm"
  # Whale places instances by node label (docker_swarm_nodes = linux-1).
  ssh_gw "$CTFD_PUB" "docker node update --label-add name=linux-1 ctf-challenge >/dev/null" \
    && ok "challenge host labelled name=linux-1 for whale" || warn "node label failed"

  # --- Deliver plugin + profiles (too large for user_data) -----------------
  log "delivering VPN profiles and CTFd plugin"
  ssh_gw "$CTFD_PUB" "mkdir -p /opt/ctf/vpn_profiles /opt/ctf/plugins"
  scp_pub "$PLUGIN_SRC" "$CTFD_PUB:/opt/ctf/plugins/"
  local p
  for p in "$PROFILE_DIR"/player*.ovpn; do
    [ -f "$p" ] || continue
    scp_pub "$p" "$CTFD_PUB:/opt/ctf/vpn_profiles/"
  done
  # uid 1001 = the ctfd user inside the container; it must be able to list and
  # read the profiles, and nothing else on the host needs to.
  ssh_gw "$CTFD_PUB" "chown -R 1001:1001 /opt/ctf/vpn_profiles /opt/ctf/data/CTFd && chmod 700 /opt/ctf/vpn_profiles && chmod 600 /opt/ctf/vpn_profiles/*.ovpn && cd /opt/ctf && docker compose restart ctfd"
  ok "$(ls -1 "$PROFILE_DIR"/player*.ovpn 2>/dev/null | wc -l | tr -d ' ') player profiles delivered (admin.ovpn stays local)"

  # Tell Wazuh to tail the handout audit log.
  ssh_gw "$CTFD_PUB" "printf '<ossec_config><localfile><log_format>syslog</log_format><location>/opt/ctf/data/CTFd/logs/vpn_handout.log</location></localfile></ossec_config>\n' >> /var/ossec/etc/ossec.conf 2>/dev/null; systemctl restart wazuh-agent 2>/dev/null || true" || true

  # --- Collect Wazuh credentials, then seal enrolment ---------------------
  log "collecting Wazuh credentials"
  WAZUH_ADMIN_PW="$(ssh_via "$SIEM_VPC_IP" "$GW_PUB" \
    "grep -A2 \"username: 'admin'\" /root/wazuh-credentials.txt 2>/dev/null | grep password | head -1 | sed \"s/.*password: '//;s/'.*//\"" 2>/dev/null || true)"
  if [ -z "$WAZUH_ADMIN_PW" ]; then
    WAZUH_ADMIN_PW="$(ssh_via "$SIEM_VPC_IP" "$GW_PUB" "grep -m1 -oE \"password: '[^']+'\" /root/wazuh-credentials.txt 2>/dev/null | sed \"s/password: '//;s/'//\"" 2>/dev/null || true)"
  fi
  [ -n "$WAZUH_ADMIN_PW" ] && ok "Wazuh admin password retrieved" \
    || warn "could not auto-read Wazuh password; see /root/wazuh-credentials.txt on $SIEM_VPC_IP"

  log "sealing Wazuh enrolment (agents are registered; authd no longer needed)"
  ssh_via "$SIEM_VPC_IP" "$GW_PUB" "/usr/local/sbin/ctf-wazuh-seal.sh" >/dev/null 2>&1 \
    && ok "Wazuh enrolment sealed" || warn "seal step failed; run ctf-wazuh-seal.sh manually"

  # --- ENFORCE CHALLENGE ZERO-OUTBOUND ------------------------------------
  # Two independent cuts: the host drops its proxy configuration, and the
  # gateway stops accepting proxy/DNS connections from it. Either alone would
  # suffice; both means one mistake cannot restore internet to player containers.
  log "revoking WAN egress from the challenge host"
  ssh_via "$CHAL_VPC_IP" "$GW_PUB" "/usr/local/sbin/ctf-revoke-wan.sh" >/dev/null \
    && ok "challenge host proxy configuration removed" || warn "proxy revoke failed"
  # The flag file makes this survive gateway reboots: ctf-firewall.sh will
  # never emit the bootstrap rule again once it exists.
  ssh_gw "$GW_PUB" "mkdir -p /etc/ctf && touch /etc/ctf/chal-wan-revoked && /usr/local/sbin/ctf-firewall.sh && ! nft list chain inet ctf_filter forward | grep -q CHAL_WAN_BOOTSTRAP" \
    && ok "gateway no longer proxies for $CHAL_VPC_IP (persistent across reboots)" || warn "gateway rule removal failed"

  # Prove it rather than assume it: direct, and via the proxy.
  if ssh_via "$CHAL_VPC_IP" "$GW_PUB" "timeout 8 curl -sf -m 5 https://1.1.1.1 -o /dev/null" 2>/dev/null; then
    warn "VERIFY FAILED: challenge host reaches the internet directly - investigate before the event"
  else
    ok "verified: challenge host has no direct WAN egress"
  fi
  if ssh_via "$CHAL_VPC_IP" "$GW_PUB" "timeout 8 curl -sf -m 5 -x http://$GW_VPC_IP:3128 https://1.1.1.1 -o /dev/null" 2>/dev/null; then
    warn "VERIFY FAILED: challenge host can still use the gateway proxy"
  else
    ok "verified: gateway proxy refuses the challenge host"
  fi
  if ssh_via "$CHAL_VPC_IP" "$GW_PUB" "timeout 8 curl -sf -m 5 http://169.254.169.254/v1/ -o /dev/null" 2>/dev/null; then
    warn "VERIFY FAILED: metadata reachable from challenge host"
  else
    ok "verified: metadata blackholed on challenge host"
  fi

  # --- Rotate swarm tokens: the values used during bootstrap are now dead --
  log "rotating swarm join tokens"
  ssh_gw "$CTFD_PUB" 'docker swarm join-token --rotate -q worker >/dev/null && docker swarm join-token --rotate -q manager >/dev/null' \
    && ok "swarm tokens rotated" || warn "token rotation failed"

  # ---- Wazuh: custom decoders, rules and per-node log sources --------------
  # Shipped here rather than in cloud-init: user_data is capped at 16 KB and
  # this content changes far more often than the node templates do.
  if [ -d "$BASE_DIR/wazuh" ]; then
    log "installing Wazuh CTF ruleset and agent log sources"
    COPYFILE_DISABLE=1 tar -C "$BASE_DIR" --no-xattrs -czf - wazuh 2>/dev/null \
      | ssh_via "$SIEM_VPC_IP" "$GW_PUB" "rm -rf /root/wazuh && tar -C /root -xzf - && bash /root/wazuh/install.sh manager" \
      && ok "Wazuh manager: decoders + rules installed" \
      || warn "Wazuh manager ruleset install failed - check 'wazuh-logtest -t' on node 4"
    local _n _ip
    for _n in node1:"$GW_VPC_IP" node2:"$CTFD_VPC_IP" node3:"$CHAL_VPC_IP"; do
      _ip="${_n#*:}"; _n="${_n%%:*}"
      COPYFILE_DISABLE=1 tar -C "$BASE_DIR" --no-xattrs -czf - wazuh 2>/dev/null \
        | ssh_via "$_ip" "$GW_PUB" "rm -rf /root/wazuh && tar -C /root -xzf - && bash /root/wazuh/install.sh agent $_n" \
        && ok "Wazuh agent on $_n: log sources added" \
        || warn "Wazuh agent config on $_n failed"
    done
  fi


}

ctfd_bootstrap() {
  local base jar nonce code
  if [ -n "$CTF_DOMAIN" ]; then base="https://$CTF_DOMAIN"; else base="https://$CTFD_PUB"; fi
  jar="$(mktemp -t ctfdjar)"
  log "running CTFd first-run setup at $base"
  local i=1
  while [ "$i" -le 30 ]; do
    curl -sk -m 10 -o /dev/null "$base/setup" && break
    sleep 10; i=$((i+1))
  done
  # Markup is <input id="nonce" name="nonce" type="hidden" value="..."> -
  # attributes between name and value, so match across them.
  nonce="$(curl -sk -m 15 -c "$jar" "$base/setup" \
    | grep -o 'name="nonce"[^>]*value="[^"]*' | head -1 | sed 's/.*value="//' || true)"
  if [ -z "$nonce" ]; then
    warn "could not read CTFd setup nonce - complete the wizard manually at $base/setup"
    rm -f "$jar"; return 0
  fi
  code="$(curl -sk -m 30 -o /dev/null -w '%{http_code}' -b "$jar" -c "$jar" -X POST "$base/setup" \
    -F "ctf_name=$EVENT_NAME" \
    -F "ctf_description=$EVENT_NAME - connect over the VPN profile on your account page." \
    -F "user_mode=$CTF_USER_MODE" \
    -F "team_size=$CTF_TEAM_SIZE" \
    -F "challenge_visibility=private" \
    -F "account_visibility=private" \
    -F "score_visibility=private" \
    -F "registration_visibility=public" \
    -F "registration_code=$REGISTRATION_CODE" \
    -F "verify_emails=false" \
    -F "name=$CTFD_ADMIN_USER" \
    -F "email=$ACME_EMAIL" \
    -F "password=$CTFD_ADMIN_PW" \
    -F "ctf_theme=core-beta" \
    -F "nonce=$nonce" \
    -F "_submit=Finish" || true)"
  rm -f "$jar"
  case "$code" in
    200|302) ok "CTFd initialised (admin: $CTFD_ADMIN_USER)";;
    *) warn "CTFd setup returned HTTP $code - finish the wizard manually at $base/setup";;
  esac
  whale_configure || warn "whale not configured - open /plugins/ctfd-whale/admin/settings and set it by hand"
}

# ============================ CTFd ADMIN API =================================
CTFD_JAR=""; CTFD_BASE=""; CTFD_CSRF=""
ctfd_base_url() { if [ -n "$CTF_DOMAIN" ]; then printf 'https://%s' "$CTF_DOMAIN"; else printf 'https://%s' "$CTFD_PUB"; fi; }

# Logs in as the admin and captures the CSRF nonce the JSON API requires.
ctfd_admin_login() {
  CTFD_BASE="$(ctfd_base_url)"
  CTFD_JAR="$(mktemp -t ctfdjar)"
  local nonce
  nonce="$(curl -sk -m 15 -c "$CTFD_JAR" "$CTFD_BASE/login" | grep -o 'name="nonce"[^>]*value="[^"]*' | head -1 | sed 's/.*value="//' || true)"
  [ -n "$nonce" ] || { warn "CTFd login page has no nonce"; return 1; }
  curl -sk -m 20 -o /dev/null -b "$CTFD_JAR" -c "$CTFD_JAR" -X POST "$CTFD_BASE/login" \
    -F "name=$CTFD_ADMIN_USER" -F "password=$CTFD_ADMIN_PW" -F "nonce=$nonce" -F "_submit=Submit"
  CTFD_CSRF="$(curl -sk -m 15 -b "$CTFD_JAR" "$CTFD_BASE/admin/config" | grep -o "'csrfNonce': \"[^\"]*" | head -1 | sed "s/.*\"//" || true)"
  [ -n "$CTFD_CSRF" ] || { warn "could not obtain CSRF nonce (is the admin password right?)"; return 1; }
}
ctfd_admin_logout() { rm -f "$CTFD_JAR"; CTFD_JAR=""; }

# ctfd_api METHOD PATH [JSON]
# CTFd's API answers a generic 403 to any state-changing request that lacks a
# JSON content type/body (verified live: bare DELETE 403, DELETE with `{}` 200),
# so every non-GET call carries one.
ctfd_api() {
  local m="$1" path="$2" body="${3:-}"
  if [ "$m" = "GET" ]; then
    curl -sk -m 30 -b "$CTFD_JAR" -H "CSRF-Token: $CTFD_CSRF" "$CTFD_BASE/api/v1$path"
  else
    [ -n "$body" ] || body='{}'
    curl -sk -m 30 -b "$CTFD_JAR" -X "$m" -H "Content-Type: application/json" -H "CSRF-Token: $CTFD_CSRF" \
      -d "$body" "$CTFD_BASE/api/v1$path"
  fi
}

# Push whale's settings through CTFd's config API. Whale reads them from the
# same table its admin page writes to, so this replaces clicking through the UI.
whale_configure() {
  ctfd_admin_login || return 1
  local cfg
  cfg="$(jq -nc \
    --arg api  "tcp://docker-proxy:2375" \
    --arg net  "$CHAL_NET_NAME" \
    --arg sub  "$WHALE_SUBNET" \
    --arg frp  "http://whale:$FRPC_ADMIN_PW@frpc:7400" \
    --arg ip   "$CTFD_VPC_IP" \
    --arg lo   "$FRP_PORT_LO" --arg hi "$FRP_PORT_HI" \
    --arg to   "$WHALE_INSTANCE_TIMEOUT" --arg max "$WHALE_MAX_INSTANCES" --arg renew "$WHALE_MAX_RENEW" \
    --arg dom  "${CTF_DOMAIN:-chal.invalid}" \
    --arg flag "{{ \"$FLAG_PREFIX{\"+uuid.uuid4()|string+\"}\" }}" \
    '{
      "whale:docker_api_url": $api,
      "whale:docker_credentials": "",
      "whale:docker_swarm_nodes": "linux-1",
      "whale:docker_auto_connect_network": $net,
      "whale:docker_subnet": $sub,
      "whale:docker_subnet_new_prefix": "24",
      "whale:docker_dns": "127.0.0.11",
      "whale:docker_timeout": $to,
      "whale:docker_max_container_count": $max,
      "whale:docker_max_renew_count": $renew,
      "whale:router_type": "frp",
      "whale:frp_api_url": $frp,
      "whale:frp_direct_ip_address": $ip,
      "whale:frp_direct_port_minimum": $lo,
      "whale:frp_direct_port_maximum": $hi,
      "whale:frp_http_port": "8001",
      "whale:frp_http_domain_suffix": $dom,
      "whale:template_chall_flag": $flag,
      "whale:refresh": "true"
    }')"
  local resp; resp="$(ctfd_api PATCH /configs "$cfg")"
  if printf '%s' "$resp" | jq -e '.success == true' >/dev/null 2>&1; then
    ok "whale configured (docker via socket proxy, frp direct ports $FRP_PORT_LO-$FRP_PORT_HI on $CTFD_VPC_IP)"
  else
    warn "whale config PATCH failed: $(printf '%s' "$resp" | cut -c1-160)"
  fi

  # MANDATORY restart. Whale builds its Docker client once, in `load()`, and
  # caches it on the class. At first boot the config did not exist yet, so that
  # call failed and the attribute was never set; visiting the settings page
  # re-initialises it in ONLY the gunicorn worker that serves that request, so
  # with WORKERS=4 three of four workers still raise
  # "type object 'DockerUtils' has no attribute 'client'" on Start - which
  # presents to players as a random "Container creation failed". Restarting
  # makes every worker load with the config already in the database.
  log "restarting CTFd so every worker picks up whale's configuration"
  ssh_gw "$CTFD_PUB" "cd /opt/ctf && docker compose restart ctfd" >/dev/null 2>&1 \
    || warn "could not restart CTFd; whale may work only intermittently"
  # Wait for a real 200: Caddy answers 502 while CTFd is still booting, and a
  # bare `curl -o /dev/null` counts that as success, so the re-login raced it.
  local i=1 code=""
  while [ "$i" -le 40 ]; do
    code="$(curl -sk -m 10 -o /dev/null -w '%{http_code}' "$CTFD_BASE/login" || true)"
    [ "$code" = "200" ] && break
    sleep 5; i=$((i+1))
  done
  [ "$code" = "200" ] || warn "CTFd still returning HTTP ${code:-none} after restart"
  i=1
  while [ "$i" -le 3 ]; do
    ctfd_admin_login && break
    i=$((i+1)); sleep 5
  done
  [ -n "$CTFD_CSRF" ] || { warn "could not re-authenticate after restart"; return 1; }

  # Now read whale's own health checks back.
  local page; page="$(curl -sk -m 30 -b "$CTFD_JAR" "$CTFD_BASE/plugins/ctfd-whale/admin/settings")"
  # Whale renders check failures inside an alert-danger block; match only that,
  # not its help text (which mentions frpc and once produced a false alarm).
  # `|| true` is load-bearing: with `set -o pipefail`, grep finding nothing
  # (i.e. whale reporting NO errors - the good case) returns 1 and would kill
  # the script silently right at the moment everything is healthy.
  local errs; errs="$(printf '%s' "$page" | tr '\n' ' ' | grep -oE 'class="alert alert-danger[^>]*>[^<]*(<[^/][^>]*>[^<]*)*' | sed 's/<[^>]*>/ /g; s/  */ /g' | head -c 300 || true)"
  if [ -n "$errs" ]; then
    warn "whale checks report: $errs"
  else
    ok "whale checks pass (Docker API via proxy + frpc admin API reachable)"
  fi
  ctfd_admin_logout
}

# ================================= STATE =====================================
# Written after every resource creation, not just at the end: if deploy dies
# halfway, teardown still knows exactly what to delete. Empty vars become null.
save_state() {
  jq -n \
    --arg tag "$CTF_TAG" --arg region "$CTF_REGION" --arg event "$EVENT_NAME" \
    --arg domain "$CTF_DOMAIN" --arg created "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg vpc "$VPC_ID" --arg subnet "$SUBNET_ID" \
    --arg fwgw "$FW_GW_ID" --arg fwweb "$FW_CTFD_ID" --arg fwint "$FW_INT_ID" \
    --arg gw "$GW_ID" --arg ctfd "$CTFD_ID" --arg chal "$CHAL_ID" --arg siem "$SIEM_ID" \
    --arg gwpub "$GW_PUB" --arg ctfdpub "$CTFD_PUB" \
    --arg vpccidr "$VPC_CIDR" --arg gwv "$GW_VPC_IP" --arg ctfdv "$CTFD_VPC_IP" \
    --arg chalv "$CHAL_VPC_IP" --arg siemv "$SIEM_VPC_IP" \
    --argjson ips "$(known_ips_json)" --argjson ips6 "$(known_ips6_json)" \
    'def num: if . == "" then null else tonumber end;
     {
       event:$event, tag:$tag, region:$region, domain:$domain, created:$created,
       vpc:{id:($vpc|num), subnet_id:($subnet|num), cidr:$vpccidr},
       firewalls:{gateway:($fwgw|num), ctfd:($fwweb|num), internal:($fwint|num)},
       nodes:{
         gateway:{id:($gw|num), public_ip:$gwpub, vpc_ip:$gwv},
         ctfd:{id:($ctfd|num), public_ip:$ctfdpub, vpc_ip:$ctfdv},
         challenge:{id:($chal|num), vpc_ip:$chalv},
         wazuh:{id:($siem|num), vpc_ip:$siemv}
       },
       known_admin_ips:$ips, known_admin_ips6:$ips6
     }' > "$STATE_FILE.tmp" && mv "$STATE_FILE.tmp" "$STATE_FILE" \
    || { rm -f "$STATE_FILE.tmp"; warn "state write failed (previous state kept)"; return 1; }
  chmod 644 "$STATE_FILE"
}

save_secrets() {
  # Credentials live in a separate 0600 file, never in the state file that you
  # might paste into a ticket or commit by accident. Written as soon as the
  # values exist and again at the end, so an interrupted deploy can resume.
  umask 077
  cat > "$SECRETS_FILE" <<EOF
# $EVENT_NAME - generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# 0600. Contains live credentials. Do not commit; archived on teardown.
CTFD_URL="$( [ -n "$CTF_DOMAIN" ] && echo "https://$CTF_DOMAIN" || echo "https://$CTFD_PUB" )"
CTFD_ADMIN_USER="$CTFD_ADMIN_USER"
CTFD_ADMIN_PASSWORD="$CTFD_ADMIN_PW"
REGISTRATION_CODE="$REGISTRATION_CODE"
ADMIN_SEATS="$ADMIN_SEATS"
ADMIN_VPN_RANGE="$ADMIN_VPN_RANGE"
CTFD_DB_PASSWORD="$CTFD_DB_PW"
CTFD_DB_ROOT_PASSWORD="$CTFD_DB_ROOT_PW"
CTFD_SECRET_KEY="$CTFD_SECRET_KEY"
WAZUH_DASHBOARD_URL="https://$SIEM_VPC_IP (admin VPN only)"
WAZUH_ADMIN_USER="admin"
WAZUH_ADMIN_PASSWORD="${WAZUH_ADMIN_PW:-see /root/wazuh-credentials.txt}"
WAZUH_AUTHD_PASSWORD="$WAZUH_AUTHD_PASS"
FRP_TOKEN="$FRP_TOKEN"
FRPC_ADMIN_PASSWORD="$FRPC_ADMIN_PW"
VPN_ISOLATION_TOKEN="$ISOLATION_TOKEN"
ROOT_PW_GATEWAY="$GW_ROOT_PW"
ROOT_PW_CTFD="$CTFD_ROOT_PW"
ROOT_PW_CHALLENGE="$CHAL_ROOT_PW"
ROOT_PW_WAZUH="$SIEM_ROOT_PW"
EOF
  chmod 600 "$SECRETS_FILE"
  umask 022
}

load_secrets() {
  [ -f "$SECRETS_FILE" ] || die "no $SECRETS_FILE to resume from"
  CTFD_ADMIN_PW="$(sed -n 's/^CTFD_ADMIN_PASSWORD="\(.*\)"$/\1/p' "$SECRETS_FILE")"
  REGISTRATION_CODE="$(sed -n 's/^REGISTRATION_CODE="\(.*\)"$/\1/p' "$SECRETS_FILE")"
  local _as _ar
  _as="$(sed -n 's/^ADMIN_SEATS="\(.*\)"$/\1/p' "$SECRETS_FILE")"; [ -n "$_as" ] && ADMIN_SEATS="$_as"
  _ar="$(sed -n 's/^ADMIN_VPN_RANGE="\(.*\)"$/\1/p' "$SECRETS_FILE")"; [ -n "$_ar" ] && ADMIN_VPN_RANGE="$_ar"
  CTFD_DB_PW="$(sed -n 's/^CTFD_DB_PASSWORD="\(.*\)"$/\1/p' "$SECRETS_FILE")"
  CTFD_DB_ROOT_PW="$(sed -n 's/^CTFD_DB_ROOT_PASSWORD="\(.*\)"$/\1/p' "$SECRETS_FILE")"
  CTFD_SECRET_KEY="$(sed -n 's/^CTFD_SECRET_KEY="\(.*\)"$/\1/p' "$SECRETS_FILE")"
  WAZUH_AUTHD_PASS="$(sed -n 's/^WAZUH_AUTHD_PASSWORD="\(.*\)"$/\1/p' "$SECRETS_FILE")"
  GW_ROOT_PW="$(sed -n 's/^ROOT_PW_GATEWAY="\(.*\)"$/\1/p' "$SECRETS_FILE")"
  CTFD_ROOT_PW="$(sed -n 's/^ROOT_PW_CTFD="\(.*\)"$/\1/p' "$SECRETS_FILE")"
  CHAL_ROOT_PW="$(sed -n 's/^ROOT_PW_CHALLENGE="\(.*\)"$/\1/p' "$SECRETS_FILE")"
  SIEM_ROOT_PW="$(sed -n 's/^ROOT_PW_WAZUH="\(.*\)"$/\1/p' "$SECRETS_FILE")"
  WAZUH_ADMIN_PW="$(sed -n 's/^WAZUH_ADMIN_PASSWORD="\(.*\)"$/\1/p' "$SECRETS_FILE")"
  FRP_TOKEN="$(sed -n 's/^FRP_TOKEN="\(.*\)"$/\1/p' "$SECRETS_FILE")"
  FRPC_ADMIN_PW="$(sed -n 's/^FRPC_ADMIN_PASSWORD="\(.*\)"$/\1/p' "$SECRETS_FILE")"
  ISOLATION_TOKEN="$(sed -n 's/^VPN_ISOLATION_TOKEN="\(.*\)"$/\1/p' "$SECRETS_FILE")"
}

write_state() {
  save_state
  save_secrets
}

deploy_summary() {
  local url
  if [ -n "$CTF_DOMAIN" ]; then url="https://$CTF_DOMAIN"; else url="https://$CTFD_PUB"; fi
  hr
  printf '%s%s DEPLOYED%s\n' "$C_BOLD" "$EVENT_NAME" "$C_RST"
  hr
  printf '  CTFd URL              %s\n' "$url"
  [ -z "$CTF_DOMAIN" ] && printf '                        %s(self-signed cert: set CTF_DOMAIN for Let'"'"'s Encrypt)%s\n' "$C_Y" "$C_RST"
  printf '  CTFd admin            %s / see %s\n' "$CTFD_ADMIN_USER" "$(basename "$SECRETS_FILE")"
  printf '  Admin VPN profile     %s\n' "$PROFILE_DIR/admin.ovpn"
  printf '  Player VPN profiles   %s  (%s profiles, served per-user at %s/vpn)\n' \
    "$PROFILE_DIR" "$PLAYER_COUNT" "$url"
  printf '  Wazuh dashboard       https://%s   (admin VPN %s only)\n' "$SIEM_VPC_IP" "$VPN_ADMIN_IP"
  printf '  Wazuh admin           admin / see %s\n' "$(basename "$SECRETS_FILE")"
  hr
  printf '  Gateway (bastion)     %s   ssh -i %s root@%s\n' "$GW_PUB" "$SSH_KEY" "$GW_PUB"
  printf '  Private nodes         ssh -i %s -J root@%s root@%s|%s\n' "$SSH_KEY" "$GW_PUB" "$CHAL_VPC_IP" "$SIEM_VPC_IP"
  printf '  Break-glass           Linode LISH console if the VPN or SSH path fails:\n'
  printf '                        ssh <linode-username>@lish-%s.linode.com\n' "$CTF_REGION"
  hr
  printf '  State                 %s\n' "$STATE_FILE"
  printf '  Secrets (0600)        %s\n' "$SECRETS_FILE"
  hr
  printf '  %sNext:%s publish challenges to the registry at %s:5000, then deploy\n' "$C_BOLD" "$C_RST" "$CTFD_VPC_IP"
  printf '  them as Swarm services with --publish mode=host,published=<%s-%s>.\n' "$CHAL_PORT_LO" "$CHAL_PORT_HI"
  printf '  %sDo not use ingress mode%s - it would expose challenge ports on the\n' "$C_R" "$C_RST"
  printf '  CTFd node public IP, bypassing the VPN entirely.\n'
  hr
}

# ============================ ROAMING SUPPORT ================================
GW_ADDR=""
# From a network the hosts have not seen, public SSH is refused by the host
# nftables allow-list even after the Cloud Firewall is synced. The admin VPN
# profile is always allowed, so fall back to the gateway's VPC address.
resolve_gateway() {
  local pub="$1"
  if ssh_gw "$pub" true 2>/dev/null; then GW_ADDR="$pub"; return 0; fi
  if ssh_gw "$GW_VPC_IP" true 2>/dev/null; then
    GW_ADDR="$GW_VPC_IP"
    warn "public SSH refused from this network; reached gateway over the admin VPN instead"
    return 0
  fi
  warn "gateway unreachable. From a new network: connect $PROFILE_DIR/admin.ovpn first, then re-run status."
  return 1
}

push_host_allowlist() {
  local v4 v6
  v4="$(nft_set_v4)"; v6="$(nft_set_v6)"
  local cmd="mkdir -p /etc/ctf && printf '%s' '$v4' > /etc/ctf/admin_src_v4 && printf '%s' '$v6' > /etc/ctf/admin_src_v6 && /usr/local/sbin/ctf-firewall.sh"
  ssh_gw "$GW_ADDR" "$cmd" >/dev/null 2>&1 && ok "gateway host allow-list updated" || warn "gateway host allow-list update failed"
  ssh_via "$CTFD_VPC_IP" "$GW_ADDR" "$cmd" >/dev/null 2>&1 && ok "ctfd host allow-list updated" || warn "ctfd host allow-list update failed"
}

persist_known_ips() {
  local tmp; tmp="$(mktemp -t ctfstate)"
  jq --argjson a "$(known_ips_json)" --argjson b "$(known_ips6_json)" \
    '.known_admin_ips = $a | .known_admin_ips6 = $b' "$STATE_FILE" > "$tmp" && mv "$tmp" "$STATE_FILE"
}

# ================================ COMMANDS ===================================
cmd_deploy() {
  preflight
  detect_admin_ips
  if [ -f "$STATE_FILE" ]; then
    warn "$STATE_FILE already exists - a deployment (or the remains of a failed one) may be live."
    warn "Run [3] Teardown first to clean it up; it handles partial deployments."
    printf 'Type %sDEPLOY%s to provision a second stack anyway: ' "$C_BOLD" "$C_RST"
    local a; read -r a; [ "$a" = "DEPLOY" ] || { warn "aborted"; return 1; }
  fi

  generate_secrets
  generate_pki
  create_firewalls
  save_state
  create_vpc
  save_state

  local tmp subs out
  tmp="$(mktemp -d -t ctfdeploy)"
  subs="$tmp/subs.tsv"
  write_common_subs "$subs"

  # ---------- Stage 1: gateway. Nothing else can boot until this NATs. ------
  {
    printf 'CA_CRT_B64\t%s\n'     "$(b64 "$PKI_DIR/ca/ca.crt")"
    printf 'SERVER_CRT_B64\t%s\n' "$(b64 "$PKI_DIR/server/server.crt")"
    printf 'SERVER_KEY_B64\t%s\n' "$(b64 "$PKI_DIR/server/server.key")"
    printf 'TLS_CRYPT_B64\t%s\n'  "$(b64 "$PKI_DIR/tls-crypt.key")"
    printf 'CRL_B64\t%s\n'        "$(b64 "$PKI_DIR/crl.pem")"
  } >> "$subs"
  render_template "$TPL_DIR/node1-gateway.yaml.tpl" "$subs" > "$tmp/node1.yaml"
  out="$(create_node "ctf-gateway" "$TYPE_GATEWAY" "$GW_VPC_IP" "$FW_GW_ID" "$tmp/node1.yaml" "$GW_ROOT_PW" nat)"
  GW_ID="$(printf '%s\n' "$out" | sed -n 1p)"
  GW_PUB="$(printf '%s\n' "$out" | sed -n 2p)"
  ok "gateway $GW_ID at $GW_PUB"
  save_state
  wait_for_ssh "$GW_PUB" "gateway" 90
  wait_for_sentinel "$GW_PUB" "gateway NAT+VPN" "/run/ctf-nat-ready"

  # Profiles need the gateway's real public address as their `remote`.
  build_profiles "$GW_PUB"

  # ---------- Stage 2: the remaining three, in parallel ---------------------
  build_caddyfile "$tmp/Caddyfile"
  {
    printf 'MYSQL_ROOT_PASSWORD=%s\n' "$CTFD_DB_ROOT_PW"
    printf 'MYSQL_PASSWORD=%s\n'      "$CTFD_DB_PW"
    printf 'CTFD_SECRET_KEY=%s\n'     "$CTFD_SECRET_KEY"
    printf 'FRP_TOKEN=%s\n'           "$FRP_TOKEN"
    printf 'FRPC_ADMIN_PASSWORD=%s\n' "$FRPC_ADMIN_PW"
    printf 'VPN_ISOLATION_TOKEN=%s\n'   "$ISOLATION_TOKEN"
  } > "$tmp/ctfd.env"
  {
    printf 'CADDYFILE_B64\t%s\n' "$(b64 "$tmp/Caddyfile")"
    printf 'CTFD_ENV_B64\t%s\n'  "$(b64 "$tmp/ctfd.env")"
  } >> "$subs"

  render_template "$TPL_DIR/node2-ctfd.yaml.tpl"      "$subs" > "$tmp/node2.yaml"
  render_template "$TPL_DIR/node3-challenge.yaml.tpl" "$subs" > "$tmp/node3.yaml"
  render_template "$TPL_DIR/node4-wazuh.yaml.tpl"     "$subs" > "$tmp/node4.yaml"

  out="$(create_node "ctf-ctfd" "$TYPE_CTFD" "$CTFD_VPC_IP" "$FW_CTFD_ID" "$tmp/node2.yaml" "$CTFD_ROOT_PW" nat)"
  CTFD_ID="$(printf '%s\n' "$out" | sed -n 1p)"; CTFD_PUB="$(printf '%s\n' "$out" | sed -n 2p)"
  ok "ctfd $CTFD_ID at $CTFD_PUB"
  save_state

  if [ -n "$CTF_DOMAIN" ]; then
    hr
    printf '  Point %s at %s (A record) now.\n' "$CTF_DOMAIN" "$CTFD_PUB"
    printf '  Press Enter once created; Let'"'"'s Encrypt will fail until it resolves.\n'
    hr
    read -r _ || true
    local r i=1
    while [ "$i" -le 30 ]; do
      r="$(resolve_a "$CTF_DOMAIN")"
      [ "$r" = "$CTFD_PUB" ] && { ok "$CTF_DOMAIN resolves to $CTFD_PUB"; break; }
      log "waiting for DNS ($CTF_DOMAIN -> ${r:-nothing}, want $CTFD_PUB)"; sleep 20; i=$((i+1))
    done
  fi

  out="$(create_node "ctf-challenge" "$TYPE_CHALLENGE" "$CHAL_VPC_IP" "$FW_INT_ID" "$tmp/node3.yaml" "$CHAL_ROOT_PW")"
  CHAL_ID="$(printf '%s\n' "$out" | sed -n 1p)"
  ok "challenge host $CHAL_ID (no public IP)"
  save_state

  out="$(create_node "ctf-wazuh" "$TYPE_WAZUH" "$SIEM_VPC_IP" "$FW_INT_ID" "$tmp/node4.yaml" "$SIEM_ROOT_PW")"
  SIEM_ID="$(printf '%s\n' "$out" | sed -n 1p)"
  ok "wazuh $SIEM_ID (no public IP)"
  save_state

  wait_for_ssh "$CTFD_PUB" "ctfd" 90
  wait_for_sentinel "$CTFD_PUB" "ctfd"      "/run/ctf-node-ready"
  wait_for_sentinel "$CHAL_VPC_IP" "challenge host" "/run/ctf-node-ready" "$GW_PUB"
  # Wazuh pulls ~2GB through the gateway; give it a long runway.
  wait_for_sentinel "$SIEM_VPC_IP" "wazuh"  "/run/ctf-node-ready" "$GW_PUB" 150

  post_provision
  ctfd_bootstrap
  write_state
  rm -rf "$tmp"
  deploy_summary
}

# Continue a deploy that was interrupted after the nodes were created (an SSH
# hiccup, a laptop sleep, a Ctrl-C). Everything it needs is in state + secrets.
cmd_resume() {
  preflight
  [ -f "$STATE_FILE" ] || die "no $STATE_FILE to resume from"
  load_secrets
  detect_admin_ips
  VPC_ID="$(jq -r '.vpc.id // empty' "$STATE_FILE")"; SUBNET_ID="$(jq -r '.vpc.subnet_id // empty' "$STATE_FILE")"
  FW_GW_ID="$(jq -r '.firewalls.gateway // empty' "$STATE_FILE")"
  FW_CTFD_ID="$(jq -r '.firewalls.ctfd // empty' "$STATE_FILE")"
  FW_INT_ID="$(jq -r '.firewalls.internal // empty' "$STATE_FILE")"
  GW_ID="$(jq -r '.nodes.gateway.id // empty' "$STATE_FILE")";   GW_PUB="$(jq -r '.nodes.gateway.public_ip // empty' "$STATE_FILE")"
  CTFD_ID="$(jq -r '.nodes.ctfd.id // empty' "$STATE_FILE")";    CTFD_PUB="$(jq -r '.nodes.ctfd.public_ip // empty' "$STATE_FILE")"
  CHAL_ID="$(jq -r '.nodes.challenge.id // empty' "$STATE_FILE")"
  SIEM_ID="$(jq -r '.nodes.wazuh.id // empty' "$STATE_FILE")"
  for v in GW_PUB CTFD_PUB CHAL_ID SIEM_ID; do
    eval "[ -n \"\$$v\" ]" || die "state is missing $v - not all nodes were created; tear down and redeploy"
  done
  [ -d "$PROFILE_DIR" ] || build_profiles "$GW_PUB"
  log "resuming: gateway $GW_PUB, ctfd $CTFD_PUB"
  wait_for_ssh "$GW_PUB" "gateway" 30
  wait_for_sentinel "$GW_PUB" "gateway NAT+VPN" "/run/ctf-nat-ready" "" 30
  wait_for_ssh "$CTFD_PUB" "ctfd" 30
  wait_for_sentinel "$CTFD_PUB" "ctfd" "/run/ctf-node-ready" "" 60
  wait_for_sentinel "$CHAL_VPC_IP" "challenge host" "/run/ctf-node-ready" "$GW_PUB" 90
  wait_for_sentinel "$SIEM_VPC_IP" "wazuh" "/run/ctf-node-ready" "$GW_PUB" 150
  post_provision
  ctfd_bootstrap
  write_state
  deploy_summary
}

# Re-apply whale's settings (after changing WHALE_* / FRP_* at the top, or if
# the deploy-time configuration reported a problem). Safe to run any time.
cmd_whale_config() {
  preflight
  [ -f "$STATE_FILE" ] || die "no $STATE_FILE"
  load_secrets
  CTFD_PUB="$(jq -r '.nodes.ctfd.public_ip' "$STATE_FILE")"
  whale_configure
}

cmd_status() {
  preflight
  [ -f "$STATE_FILE" ] || die "no $STATE_FILE - nothing deployed from this machine"
  detect_admin_ips

  local gwpub ctfdpub fwgw fwweb
  gwpub="$(jq -r '.nodes.gateway.public_ip' "$STATE_FILE")"
  ctfdpub="$(jq -r '.nodes.ctfd.public_ip' "$STATE_FILE")"
  fwgw="$(jq -r '.firewalls.gateway' "$STATE_FILE")"
  fwweb="$(jq -r '.firewalls.ctfd' "$STATE_FILE")"

  hr; printf '%sLinode resources tagged %s%s\n' "$C_BOLD" "$CTF_TAG" "$C_RST"; hr
  lin linodes list --tags "$CTF_TAG" \
    | jq -r '.[] | "  \(.label)\t\(.id)\t\(.status)\t\(.ipv4[0] // "-")\t\(.type)"' \
    | awk -F'\t' '{printf "  %-16s %-10s %-12s %-16s %s\n", $1, $2, $3, $4, $5}' \
    || warn "could not list linodes"

  local vpcid; vpcid="$(jq -r '.vpc.id' "$STATE_FILE")"
  printf '\n  VPC %s: %s\n' "$vpcid" "$(api GET "/vpcs/$vpcid" | jq -r '.label + " " + (.subnets[0].ipv4 // "?")')"

  # Keep the SSH allow-list current for whatever network you are on today.
  log "syncing firewall allow-list with $ADMIN_IP_V4"
  sync_firewall_ips "$fwgw"  >/dev/null 2>&1 && ok "gateway firewall synced" || warn "gateway firewall sync failed"
  sync_firewall_ips "$fwweb" >/dev/null 2>&1 && ok "ctfd firewall synced"    || warn "ctfd firewall sync failed"

  hr; printf '%sVPC connectivity and services%s\n' "$C_BOLD" "$C_RST"; hr
  resolve_gateway "$gwpub" || return 1
  push_host_allowlist
  persist_known_ips
  gwpub="$GW_ADDR"
  local n
  for n in "$CTFD_VPC_IP" "$CHAL_VPC_IP" "$SIEM_VPC_IP"; do
    if ssh_gw "$gwpub" "ping -c1 -W2 $n >/dev/null 2>&1"; then
      printf '  %s[up]%s   %s reachable inside VPC\n' "$C_G" "$C_RST" "$n"
    else
      printf '  %s[down]%s %s NOT reachable inside VPC\n' "$C_R" "$C_RST" "$n"
    fi
  done

  printf '\n  Gateway services: openvpn=%s proxy=%s dns=%s\n' \
    "$(ssh_gw "$gwpub" 'systemctl is-active openvpn-server@server' 2>/dev/null || echo unknown)" \
    "$(ssh_gw "$gwpub" 'systemctl is-active tinyproxy' 2>/dev/null || echo unknown)" \
    "$(ssh_gw "$gwpub" 'systemctl is-active dnsmasq' 2>/dev/null || echo unknown)"
  printf '  Per-team instance ACL: %s\n' \
    "$(ssh_gw "$gwpub" 'systemctl is-active ctf-instance-acl' 2>/dev/null || echo unknown)"
  acl_n="$(ssh_gw "$gwpub" "nft list set inet ctf_filter player_instance 2>/dev/null | grep -cE '\\. [0-9]+'" 2>/dev/null || echo 0)"
  printf '    %s source/port pair(s) allowed right now\n' "${acl_n:-0}"
  printf '  Connected clients:\n'
  ssh_gw "$gwpub" "awk -F, '/^CLIENT_LIST/ {printf \"    %-12s %-15s %s\\n\", \$2, \$4, \$3}' /var/log/openvpn/status.log 2>/dev/null" \
    || printf '    (none)\n'

  printf '\n  Isolation counters (packets dropped by policy):\n'
  ssh_gw "$gwpub" "nft list chain inet ctf_filter forward 2>/dev/null | grep -E 'counter packets' | sed 's/^/    /'" \
    || printf '    (unavailable)\n'

  printf '\n  Challenge host egress: '
  if ssh_via "$CHAL_VPC_IP" "$gwpub" "timeout 8 curl -sf -m 5 https://1.1.1.1 -o /dev/null" 2>/dev/null; then
    printf '%sLEAKING - has internet access%s\n' "$C_R" "$C_RST"
  else
    printf '%ssealed (no WAN)%s\n' "$C_G" "$C_RST"
  fi

  printf '  Swarm nodes:\n'
  ssh_via "$CTFD_VPC_IP" "$gwpub" "docker node ls --format '{{.Hostname}} {{.Status}} {{.Availability}} {{.ManagerStatus}}' 2>/dev/null" | sed 's/^/    /' \
    || printf '    (unavailable)\n'

  local url; url="$(jq -r '.domain' "$STATE_FILE")"
  [ -n "$url" ] && [ "$url" != "null" ] && url="https://$url" || url="https://$ctfdpub"
  printf '\n  CTFd %s -> HTTP %s\n' "$url" "$(curl -sk -o /dev/null -w '%{http_code}' -m 10 "$url" || echo 'no response')"
  printf '  Wazuh https://%s -> HTTP %s\n' "$SIEM_VPC_IP" \
    "$(ssh_gw "$gwpub" "curl -sk -o /dev/null -w '%{http_code}' -m 10 https://$SIEM_VPC_IP" 2>/dev/null || echo 'no response')"
  hr
}

cmd_teardown() {
  preflight
  [ -f "$STATE_FILE" ] || { warn "no $STATE_FILE - will discover resources by tag/label instead"; echo '{}' > "$STATE_FILE"; }
  hr
  printf '%sThis destroys every Linode, the VPC, and the Cloud Firewalls tagged %s.%s\n' "$C_R" "$CTF_TAG" "$C_RST"
  printf 'Scoreboard data on the CTFd node will be lost unless you have pulled a backup.\n'
  printf 'Type %sDESTROY%s to proceed: ' "$C_BOLD" "$C_RST"
  local a; read -r a
  [ "$a" = "DESTROY" ] || { warn "aborted"; return 1; }

  # ---- Step 1: delete the Linodes ----------------------------------------
  # Union of the CLI tag filter and an API-side scan: during live testing the
  # CLI listing showed 3 of 4 tagged instances. Billable resources get two
  # independent discovery paths.
  local ids id
  ids="$( { lin linodes list --tags "$CTF_TAG" | jq -r '.[].id';
           api GET '/linode/instances?page_size=100' | jq -r --arg t "$CTF_TAG" '.data[] | select(.tags|index($t)) | .id'; } | sort -u )"
  if [ -z "$ids" ]; then
    warn "no linodes tagged $CTF_TAG"
  else
    for id in $ids; do
      log "deleting linode $id"
      lin linodes delete "$id" >/dev/null 2>&1 || warn "delete failed for $id"
    done
  fi

  # ---- Step 2: poll until they are really gone ----------------------------
  # Mandatory: a VPC cannot be deleted while any interface still references
  # its subnets, and interfaces detach only once the instance is destroyed.
  log "waiting for instances to terminate so VPC interfaces detach"
  local i=1 remaining
  while [ "$i" -le 60 ]; do
    remaining="$(api GET '/linode/instances?page_size=100' | jq -r --arg t "$CTF_TAG" '[.data[] | select(.tags|index($t))] | length')"
    [ "$remaining" = "0" ] && { ok "all instances terminated"; break; }
    log "  $remaining still terminating"
    sleep 10; i=$((i+1))
  done
  [ "${remaining:-0}" = "0" ] || warn "instances still present; VPC deletion may fail"

  # ---- Step 3: delete the VPC (subnets go with it) ------------------------
  local vpcid; vpcid="$(jq -r '.vpc.id // empty' "$STATE_FILE")"
  if [ -z "$vpcid" ]; then
    vpcid="$(api GET '/vpcs?page_size=100' | jq -r --arg l "$VPC_LABEL" '.data[] | select(.label==$l) | .id' | head -1 || true)"
    [ -n "$vpcid" ] && log "discovered VPC $vpcid by label"
  fi
  if [ -n "$vpcid" ] && [ "$vpcid" != "null" ]; then
    i=1
    while [ "$i" -le 12 ]; do
      local resp; resp="$(api DELETE "/vpcs/$vpcid")"
      if printf '%s' "$resp" | jq -e '.errors' >/dev/null 2>&1; then
        log "  VPC busy, retrying: $(printf '%s' "$resp" | jq -rc '.errors[0].reason')"
        sleep 10; i=$((i+1))
      else
        ok "VPC $vpcid deleted"; break
      fi
    done
    [ "$i" -le 12 ] || warn "VPC $vpcid could not be deleted - remove it manually"
  fi

  # ---- Step 4: firewalls, then local state --------------------------------
  local fw fws
  fws="$(jq -r '.firewalls // {} | .[] | select(. != null)' "$STATE_FILE")"
  if [ -z "$fws" ]; then
    fws="$(api GET '/networking/firewalls?page_size=100' | jq -r --arg t "$CTF_TAG" '.data[] | select(.tags|index($t)) | .id' || true)"
    [ -n "$fws" ] && log "discovered firewalls by tag: $(printf '%s' "$fws" | tr '\n' ' ')"
  fi
  for fw in $fws; do
    api DELETE "/networking/firewalls/$fw" >/dev/null 2>&1 && ok "firewall $fw deleted" \
      || warn "firewall $fw delete failed"
  done

  mkdir -p "$ARCHIVE_DIR"
  local stamp; stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  local arc="$ARCHIVE_DIR/ctf-$stamp.tar.gz"
  # bash 3.2 + set -u: an empty array is "unbound". Names have no spaces, so
  # a plain string list is both simpler and safe here.
  local items=""
  [ -d "$PKI_DIR" ]      && items="$items $(basename "$PKI_DIR")"
  [ -d "$PROFILE_DIR" ]  && items="$items $(basename "$PROFILE_DIR")"
  [ -s "$STATE_FILE" ]   && items="$items $(basename "$STATE_FILE")"
  [ -f "$SECRETS_FILE" ] && items="$items $(basename "$SECRETS_FILE")"
  if [ -n "$items" ]; then
    # shellcheck disable=SC2086
    tar -czf "$arc" -C "$BASE_DIR" $items 2>/dev/null || true
  fi
  chmod 600 "$arc" 2>/dev/null || true
  ok "local PKI, profiles and credentials archived to $arc"

  printf 'Purge the live copies (pki/, profiles/, state, secrets)? [y/N]: '
  read -r a
  if [ "$a" = "y" ] || [ "$a" = "Y" ]; then
    rm -rf "$PKI_DIR" "$PROFILE_DIR" "$STATE_FILE" "$SECRETS_FILE" "$KNOWN_HOSTS"
    ok "local state purged (archive retained at $arc)"
  else
    log "live copies retained"
  fi
  hr
  warn "Rotate the Linode API token in $TOKEN_FILE now that the event is over."
}

cmd_revoke() {
  preflight
  [ -d "$PKI_DIR/ca" ] || die "no PKI at $PKI_DIR"
  [ -f "$STATE_FILE" ] || die "no $STATE_FILE"

  printf 'Profile to revoke (e.g. player07, or admin): '
  local cn; read -r cn
  [ -n "$cn" ] || { warn "nothing entered"; return 1; }
  [ -f "$PKI_DIR/clients/$cn.crt" ] || die "no certificate for '$cn' in $PKI_DIR/clients"

  printf 'Revoke %s? This is permanent for this PKI. [y/N]: ' "$cn"
  local a; read -r a
  [ "$a" = "y" ] || [ "$a" = "Y" ] || { warn "aborted"; return 1; }

  log "revoking $cn"
  openssl ca -config "$PKI_DIR/ca/openssl.cnf" -revoke "$PKI_DIR/clients/$cn.crt" 2>/dev/null \
    || warn "already revoked?"
  pki_gencrl
  ok "CRL regenerated"

  local gwpub; gwpub="$(jq -r '.nodes.gateway.public_ip' "$STATE_FILE")"
  scp_pub "$PKI_DIR/crl.pem" "$gwpub:/etc/openvpn/server/crl.pem"
  ssh_gw "$gwpub" "chmod 644 /etc/openvpn/server/crl.pem"
  ok "CRL pushed to gateway (blocks the next handshake)"

  # Also cut any session that is live right now, via the localhost-only
  # management socket. Without this the cheater keeps their current tunnel.
  ssh_gw "$gwpub" "bash -c 'exec 3<>/dev/tcp/127.0.0.1/7505; printf \"kill $cn\r\nquit\r\n\" >&3; head -3 <&3'" 2>/dev/null \
    && ok "live session for $cn terminated" \
    || warn "no live session for $cn (or management socket unavailable)"

  ssh_gw "$gwpub" "logger -t ctf-vpn 'REVOKED cn=$cn by operator'" || true
  ok "$cn revoked. Its .ovpn will no longer connect."
  warn "The CTFd account keeps this profile assigned. Reassign in the DB, or issue a replacement profile out of band."
}

# =============================== CHALLENGES ==================================
# Authors hand you a directory (see challenges/README.md). This builds every
# image ON the CTFd node, pushes it to the private registry, renders a Swarm
# stack with the sandbox settings hard-wired, and deploys it to the challenge
# host. No Docker is needed on this machine.
CHAL_DIR="$BASE_DIR/challenges"

chal_get() {
  awk -F': *' -v k="$2" '$1==k {sub(/^[ \t]+/,"",$2); print $2; exit}' "$1" \
    | sed 's/[[:space:]]*#.*$//; s/^"//; s/"$//; s/^'"'"'//; s/'"'"'$//; s/[[:space:]]*$//'
}

# static  = Swarm service + one CTFd challenge (or a question set, see questions.json)
# dynamic = per-player whale instance
# info    = CTFd-only: no container, no port (the rules gate)
chal_type() {
  case "$(chal_get "$1" type)" in
    dynamic) echo dynamic ;; info) echo info ;; *) echo static ;;
  esac
}

challenge_dirs() {
  local d
  for d in "$CHAL_DIR"/*/; do
    d="${d%/}"
    [ "$(basename "$d")" = "_template" ] && continue
    [ -f "$d/challenge.yml" ] || continue
    printf '%s\n' "$d"
  done
}

validate_challenges() {
  local d f name port pub proto seen_ports="" n=0
  for d in $(challenge_dirs); do
    f="$d/challenge.yml"
    name="$(chal_get "$f" name)"
    if [ "$(chal_type "$f")" = "info" ]; then
      [ "$name" = "$(basename "$d")" ] || die "$(basename "$d"): name '$name' must equal the directory name"
      [ -n "$(chal_get "$f" flag)" ] || die "$name: flag is empty"
      n=$((n+1)); continue
    fi
    [ -f "$d/Dockerfile" ] || die "$(basename "$d"): missing Dockerfile"
    port="$(chal_get "$f" port)"
    pub="$(chal_get "$f" published)"; proto="$(chal_get "$f" protocol)"
    [ "$name" = "$(basename "$d")" ] || die "$(basename "$d"): name '$name' must equal the directory name"
    printf '%s' "$name" | grep -Eq '^[a-z0-9-]{2,40}$' || die "$name: name must match [a-z0-9-]{2,40}"
    printf '%s' "$port" | grep -Eq '^[0-9]+$' || die "$name: port must be numeric"
    if [ "$(chal_type "$f")" = "dynamic" ]; then
      # Per-player instance (ctfd-whale). No host port: frpc reaches it over the
      # overlay and players get a per-instance port on the CTFd node.
      [ -n "$(chal_get "$f" category)" ] || die "$name: dynamic challenges need 'category'"
      printf '%s' "$(chal_get "$f" points)" | grep -Eq '^[0-9]+$' || die "$name: dynamic challenges need numeric 'points'"
      case "$(chal_get "$f" redirect)" in direct|http|"") ;; *) die "$name: redirect must be direct or http";; esac
      [ -n "$(chal_get "$f" flag)" ] && warn "$name: 'flag' is ignored for dynamic challenges - whale generates one per instance"
    else
      printf '%s' "$pub" | grep -Eq '^[0-9]+$' || die "$name: published must be numeric"
      { [ "$pub" -ge "$CHAL_PORT_LO" ] && [ "$pub" -le "$CHAL_PORT_HI" ]; } \
        || die "$name: published $pub outside $CHAL_PORT_LO-$CHAL_PORT_HI (the only range players can reach)"
      [ "$proto" = "tcp" ] || [ "$proto" = "udp" ] || die "$name: protocol must be tcp or udp"
      if [ -f "$d/questions.json" ]; then
        jq -e 'type=="array" and length>0 and all(.[]; (.id|type=="string") and (.question|type=="string") and (.answer|type=="string") and (.points|type=="number"))' \
          "$d/questions.json" >/dev/null 2>&1 || die "$name: questions.json must be a non-empty array of {id, question, answer, points}"
      else
        [ -n "$(chal_get "$f" flag)" ] || die "$name: flag is empty"
      fi
      case " $seen_ports " in *" $pub "*) die "published port $pub is used by two challenges";; esac
      seen_ports="$seen_ports $pub"
    fi
    grep -Eiq '^\s*COPY .*flag' "$d/Dockerfile" && warn "$name: Dockerfile COPYs something named flag - flags must come from /run/secrets/flag, not the image"
    n=$((n+1))
  done
  [ "$n" -gt 0 ] || die "no challenge directories with challenge.yml under $CHAL_DIR"
  capacity_check >&2
  printf '%s' "$n"
}

# Challenges are long-running and shared, so the challenge host's load is the
# SUM of declared limits, fixed at deploy time - not a function of player
# count. Warn before deploying more than the node can hold.
node_mem_mb() {
  case "$TYPE_CHALLENGE" in
    g6-nanode-1) echo 1024;;  g6-standard-1) echo 2048;; g6-standard-2) echo 4096;;
    g6-standard-4) echo 8192;; g6-standard-6) echo 16384;; g6-standard-8) echo 32768;;
    *) echo 4096;;
  esac
}
node_vcpus() {
  case "$TYPE_CHALLENGE" in
    g6-nanode-1|g6-standard-1) echo 1;; g6-standard-2) echo 2;; g6-standard-4) echo 4;;
    g6-standard-6) echo 6;; g6-standard-8) echo 8;; *) echo 2;;
  esac
}
to_mb() {  # 256M -> 256, 1G -> 1024, 512 -> 512
  local v="$1"
  case "$v" in
    *[Gg]) echo $(( ${v%[Gg]} * 1024 ));;
    *[Mm]) echo "${v%[Mm]}";;
    *) echo "$v";;
  esac
}
capacity_check() {
  local d f mem cpus replicas tot_mem=0 tot_cpu=0 dyn_n=0 dyn_max_mem=0
  for d in $(challenge_dirs); do
    f="$d/challenge.yml"
    mem="$(chal_get "$f" memory)";     [ -n "$mem" ]      || mem="256M"
    cpus="$(chal_get "$f" cpus)";      [ -n "$cpus" ]     || cpus="0.5"
    if [ "$(chal_type "$f")" = "dynamic" ]; then
      dyn_n=$((dyn_n + 1))
      [ "$(to_mb "$mem")" -gt "$dyn_max_mem" ] && dyn_max_mem="$(to_mb "$mem")"
      continue
    fi
    replicas="$(chal_get "$f" replicas)"; [ -n "$replicas" ] || replicas=1
    tot_mem=$(( tot_mem + $(to_mb "$mem") * replicas ))
    tot_cpu="$(printf '%s %s %s' "$tot_cpu" "$cpus" "$replicas" | awk '{printf "%.2f", $1 + $2 * $3}')"
  done
  local node_mb; node_mb="$(node_mem_mb)"
  local budget=$(( node_mb - 1024 ))   # leave 1 GB for the OS, Docker and the agent
  local vc; vc="$(node_vcpus)"
  printf '%s[*]%s challenge host budget: %s MB / %s vCPU declared vs %s MB usable / %s vCPU on %s\n' \
    "$C_B" "$C_RST" "$tot_mem" "$tot_cpu" "$budget" "$vc" "$TYPE_CHALLENGE"
  if [ "$tot_mem" -gt "$budget" ]; then
    warn "declared memory limits ($tot_mem MB) exceed what $TYPE_CHALLENGE can hold ($budget MB usable)."
    warn "Trim per-challenge 'memory' values, or set TYPE_CHALLENGE=g6-standard-4 (8 GB) and redeploy node 3."
  fi
  if awk -v c="$tot_cpu" -v v="$vc" 'BEGIN{exit !(c > v*2)}'; then
    warn "declared CPU ceilings ($tot_cpu) are more than 2x the node's $vc vCPU - fine when idle, but under load challenges will contend."
  fi
  if [ "$dyn_n" -gt 0 ]; then
    # Dynamic instances are one-per-player-at-a-time (whale enforces one live
    # instance per user), so peak = concurrent players x largest instance.
    local headroom=$(( budget - tot_mem )); local fit=$(( headroom / (dyn_max_mem > 0 ? dyn_max_mem : 1) ))
    printf '%s[*]%s dynamic: %s challenge(s); whale runs one instance per player at a time, largest %s MB -> ~%s concurrent players fit alongside the static set (cap WHALE_MAX_INSTANCES=%s)\n' \
      "$C_B" "$C_RST" "$dyn_n" "$dyn_max_mem" "$fit" "$WHALE_MAX_INSTANCES"
    [ "$fit" -lt "$WHALE_MAX_INSTANCES" ] && warn "WHALE_MAX_INSTANCES ($WHALE_MAX_INSTANCES) exceeds what fits (~$fit); lower it or use TYPE_CHALLENGE=g6-standard-6 (16 GB) for a per-player event."
  fi
}

emit_stack() {
  local tag="$1" secdir="$2" d f name port pub proto flag mode replicas cpus memory pids ro caps
  mkdir -p "$secdir"
  echo "services:"
  for d in $(challenge_dirs); do
    f="$d/challenge.yml"
    [ "$(chal_type "$f")" = "static" ] || continue
    name="$(chal_get "$f" name)"; port="$(chal_get "$f" port)"; pub="$(chal_get "$f" published)"
    proto="$(chal_get "$f" protocol)"; flag="$(chal_get "$f" flag)"
    mode="$(chal_get "$f" flag_mode)";   [ -n "$mode" ]     || mode="0400"
    replicas="$(chal_get "$f" replicas)"; [ -n "$replicas" ] || replicas=1
    cpus="$(chal_get "$f" cpus)";        [ -n "$cpus" ]     || cpus="0.5"
    memory="$(chal_get "$f" memory)";    [ -n "$memory" ]   || memory="256M"
    pids="$(chal_get "$f" pids)";        [ -n "$pids" ]     || pids=128
    ro="$(chal_get "$f" read_only)";     [ "$ro" = "false" ] || ro="true"
    caps="$(chal_get "$f" caps)"
    # Question-set and info challenges carry no shared flag; their generators do
    # not read /run/secrets/flag. Swarm rejects a 0-byte secret, so write a
    # placeholder when the flag is empty.
    [ -n "$flag" ] || flag="clubeh{this-challenge-scores-by-question}"
    printf '%s' "$flag" > "$secdir/$name.flag"; chmod 600 "$secdir/$name.flag"
    cat <<EOF
  $name:
    image: $CTFD_VPC_IP:5000/$name:$tag
    networks:
      - $CHAL_NET_NAME
    ports:
      - target: $port
        published: $pub
        protocol: $proto
        mode: host
    read_only: $ro
    volumes:
      - type: tmpfs
        target: /tmp
        tmpfs:
          size: 67108864
    cap_drop:
      - ALL
EOF
    if [ -n "$caps" ]; then
      echo "    cap_add:"
      printf '%s\n' "$caps" | tr ',' '\n' | sed 's/^[ \t]*//; s/[ \t]*$//' | awk 'NF {print "      - " $0}'
    fi
    cat <<EOF
    secrets:
      - source: ${name}_flag_${tag}
        target: flag
        mode: $mode
    stop_grace_period: 5s
    deploy:
      mode: replicated
      replicas: $replicas
      placement:
        constraints:
          - node.role == worker
      resources:
        limits:
          cpus: "$cpus"
          memory: $memory
          pids: $pids
      restart_policy:
        condition: any
        delay: 5s
        max_attempts: 0
EOF
  done
  echo "secrets:"
  for d in $(challenge_dirs); do
    [ "$(chal_type "$d/challenge.yml")" = "static" ] || continue
    name="$(chal_get "$d/challenge.yml" name)"
    printf '  %s_flag_%s:\n    file: ./secrets/%s.flag\n' "$name" "$tag" "$name"
  done
  printf 'networks:\n  %s:\n    external: true\n' "$CHAL_NET_NAME"
}

cmd_challenges() {
  preflight
  [ -f "$STATE_FILE" ] || die "no $STATE_FILE - deploy the infrastructure first"
  local n; n="$(validate_challenges)"
  ok "$n challenge(s) validated"

  local gwpub; gwpub="$(jq -r '.nodes.gateway.public_ip' "$STATE_FILE")"
  resolve_gateway "$gwpub" || return 1

  local tag tmp
  tag="$(date -u +%Y%m%d%H%M%S)"
  tmp="$(mktemp -d -t ctfchal)"
  emit_stack "$tag" "$tmp/secrets" > "$tmp/stack.yml"

  log "shipping challenge sources to the CTFd node"
  # COPYFILE_DISABLE stops macOS bsdtar embedding xattr headers GNU tar warns about.
  COPYFILE_DISABLE=1 tar -C "$CHAL_DIR" --exclude _template --exclude README.md --exclude WRITEUP.md -czf - . \
    | ssh_via "$CTFD_VPC_IP" "$GW_ADDR" "rm -rf /opt/ctf/challenges/* && mkdir -p /opt/ctf/challenges && tar -C /opt/ctf/challenges -xzf -"

  local d name
  for d in $(challenge_dirs); do
    [ "$(chal_type "$d/challenge.yml")" = "info" ] && continue
    name="$(chal_get "$d/challenge.yml" name)"
    log "building $name"
    ssh_via "$CTFD_VPC_IP" "$GW_ADDR" \
      "cd /opt/ctf/challenges/$name && docker build -q -t $CTFD_VPC_IP:5000/$name:$tag . >/dev/null && docker push -q $CTFD_VPC_IP:5000/$name:$tag >/dev/null" \
      && ok "$name -> registry ($tag)" || die "$name: build or push failed (run it by hand on the CTFd node for the full log)"
  done

  log "deploying stack"
  COPYFILE_DISABLE=1 tar -C "$tmp" -czf - stack.yml secrets \
    | ssh_via "$CTFD_VPC_IP" "$GW_ADDR" "rm -rf /opt/ctf/stack && mkdir -p /opt/ctf/stack && tar -C /opt/ctf/stack -xzf - && chmod -R go-rwx /opt/ctf/stack/secrets && cd /opt/ctf/stack && docker stack deploy --prune -c stack.yml ctf" \
    && ok "stack 'ctf' deployed" || die "stack deploy failed"

  # `docker stack deploy --prune` can recreate the ctf_challenges overlay with a
  # new id. frpc (in the CTFd compose, NOT the swarm stack) stays attached to the
  # OLD overlay and can no longer resolve instance names - whale ports then accept
  # connections but forward no data (silent break, since hidden dynamics skip the
  # smoke test). Restart frpc so it re-attaches to the current overlay.
  ssh_via "$CTFD_VPC_IP" "$GW_ADDR" "cd /opt/ctf && docker compose up -d --force-recreate frpc >/dev/null 2>&1" \
    && ok "frpc re-attached to the current ctf_challenges overlay" \
    || warn "could not restart frpc - run 'cd /opt/ctf && docker compose up -d --force-recreate frpc' on the CTFd node or dynamic challenges will not serve"

  # Flag files served their purpose the moment the secrets were created.
  ssh_via "$CTFD_VPC_IP" "$GW_ADDR" "shred -u /opt/ctf/stack/secrets/*.flag 2>/dev/null || rm -rf /opt/ctf/stack/secrets" || true
  rm -rf "$tmp"

  # Dynamic (per-player) challenges are CTFd objects of type dynamic_docker;
  # whale spawns an instance from the registry image when a player clicks Start.
  local dyn=0 stat=0
  for d in $(challenge_dirs); do
    if [ "$(chal_type "$d/challenge.yml")" = "dynamic" ]; then dyn=$((dyn+1)); else stat=$((stat+1)); fi
  done
  [ "$REGISTER_STATIC" = "true" ] || stat=0
  if [ "$dyn" -gt 0 ] || [ "$stat" -gt 0 ]; then
    load_secrets 2>/dev/null || true
    CTFD_PUB="$(jq -r '.nodes.ctfd.public_ip' "$STATE_FILE")"
    if ctfd_admin_login; then
      local dyn_list=""
      for d in $(challenge_dirs); do
        f="$d/challenge.yml"
        if [ "$(chal_type "$f")" = "dynamic" ]; then
          register_dynamic_challenge "$f" "$tag"
          [ "$(chal_get "$f" hidden)" = "true" ] || dyn_list="$dyn_list $f"
        elif [ "$stat" -gt 0 ]; then
          # A failed registration must not abort the rest of the set.
          register_static_challenge "$f" || true
        fi
      done
      apply_gating
      ctfd_admin_logout
      for f in $dyn_list; do
        whale_smoke_test "$f" || warn "whale smoke test did not pass for $(chal_get "$f" name) - fix before opening registration"
      done
    else
      warn "could not log into CTFd; create the challenges by hand (see challenges/BEGINNER_SET.md)"
    fi
  fi

  sleep 8
  hr; printf '%sStatic challenges%s   (players reach these at %s over the VPN)\n' "$C_BOLD" "$C_RST" "$CHAL_VPC_IP"; hr
  ssh_via "$CTFD_VPC_IP" "$GW_ADDR" "docker service ls --filter label=com.docker.stack.namespace=ctf --format '  {{.Name}}\t{{.Replicas}}\t{{.Ports}}'" \
    | sed 's/^  ctf_/  /' | awk -F'\t' '{printf "  %-24s %-8s %s\n", $1, $2, $3}'
  hr
  printf '  Static - address to put in each CTFd challenge description:\n'
  for d in $(challenge_dirs); do
    [ "$(chal_type "$d/challenge.yml")" = "static" ] || continue
    name="$(chal_get "$d/challenge.yml" name)"
    printf '    %-24s %s:%s/%s\n' "$name" "$CHAL_VPC_IP" "$(chal_get "$d/challenge.yml" published)" "$(chal_get "$d/challenge.yml" protocol)"
  done
  if [ "$dyn" -gt 0 ]; then
    printf '  Dynamic - registered in CTFd; players press Start and get %s:<%s-%s> with a per-instance flag:\n' "$CTFD_VPC_IP" "$FRP_PORT_LO" "$FRP_PORT_HI"
    for d in $(challenge_dirs); do
      [ "$(chal_type "$d/challenge.yml")" = "dynamic" ] || continue
      printf '    %-24s image %s:5000/%s:%s  (%s)\n' "$(chal_get "$d/challenge.yml" name)" "$CTFD_VPC_IP" "$(chal_get "$d/challenge.yml" name)" "$tag" "$(chal_get "$d/challenge.yml" category)"
    done
  fi
  hr
  printf '  Not converging? %s\n' "ssh -J root@$GW_ADDR root@$CTFD_VPC_IP 'docker service ps ctf_<name> --no-trunc'"
}

# ---------------------------------------------------------------------------
# Static challenges in CTFd
#
# A static challenge is a long-running Swarm service on the challenge host with
# one shared flag. CTFd needs a matching `standard` challenge object plus a
# `static` flag before players can score it. Prose and hints live in the
# challenge's README.md (the author contract); the connection line is rebuilt
# here from challenge.yml so it can never drift from the deployed port.
# ---------------------------------------------------------------------------

# Prose of the "## Description (paste into CTFd)" block: everything between the
# heading and the fenced connection line. Blank lines are preserved so CTFd's
# markdown renderer keeps the paragraphing.
chal_desc() {
  local r="$1/README.md"
  [ -f "$r" ] || return 0
  awk '
    /^## Description \(paste into CTFd\)/ { grab=1; next }
    grab && /^```/                        { exit }
    grab && /^## /                        { exit }
    grab                                  { print }
  ' "$r" | sed -e 's/[[:space:]]*$//' | awk 'NF||n{print; n=1}' | sed -e :a -e '/^$/{$d;N;ba' -e '}'
}

# One hint per line. Items are "1. text" possibly wrapped onto indented
# continuation lines; the continuations are folded back onto the item.
chal_hints() {
  local r="$1/README.md"
  [ -f "$r" ] || return 0
  awk '
    /^## Hints/ { grab=1; next }
    grab && /^## / { exit }
    grab && /^[0-9]+\. / { if (buf != "") print buf; sub(/^[0-9]+\. /, ""); buf=$0; next }
    grab && /^[ \t]+[^ \t]/ && buf != "" { sub(/^[ \t]+/, ""); buf = buf " " $0; next }
    END { if (buf != "") print buf }
  ' "$r"
}

# The line a player copies. Derived from protocol + published port, never from
# the README, so it always matches what emit_stack actually published.
chal_connline() {
  local f="$1" pub proto
  pub="$(chal_get "$f" published)"; proto="$(chal_get "$f" protocol)"
  case "$(chal_get "$f" access)" in
    http) printf 'http://%s:%s/' "$CHAL_VPC_IP" "$pub"; return;;
  esac
  # No explicit `access:` - infer from the README's own fenced example.
  local r; r="$(dirname "$f")/README.md"
  if [ -f "$r" ] && grep -q 'http://[0-9].*:[0-9]' "$r"; then
    # NB: not `local path` - in zsh that name is tied to $PATH.
    local urlpath; urlpath="$(grep -m1 -oE 'http://[0-9.]+:[0-9]+[^ `]*' "$r" | sed -E 's#^http://[0-9.]+:[0-9]+##')"
    printf 'http://%s:%s%s' "$CHAL_VPC_IP" "$pub" "$urlpath"
  elif [ "$proto" = "udp" ]; then
    printf 'nc -u %s %s' "$CHAL_VPC_IP" "$pub"
  else
    printf 'nc %s %s' "$CHAL_VPC_IP" "$pub"
  fi
}

# Remove every flag/hint already attached to a challenge. Re-running [5] must
# not leave a player able to score twice off a stale duplicate flag.
ctfd_clear_children() {
  local cid="$1" kind="$2" id
  for id in $(ctfd_api GET "/challenges/$cid/$kind" | jq -r '.data[]?.id' 2>/dev/null); do
    ctfd_api DELETE "/$kind/$id" >/dev/null 2>&1 || true
  done
}

# Attach hints (one per line in $3) to challenge $1 worth $2 points. Cost is
# HINT_PCT % of the value per hint, or HINT_COST flat when that is set.
ctfd_attach_hints() {
  local cid="$1" points="$2" hints="$3" resp
  # Hints disabled: attach nothing. Existing hints are already cleared by the
  # caller before this runs, so a register with hints off strips them from CTFd.
  [ "$ATTACH_HINTS" = "true" ] || return 0
  local h n=0 idx=0 pct cost
  while IFS= read -r h; do
    [ -n "$h" ] || continue
    idx=$((idx+1))
    if [ "$HINT_COST" -gt 0 ]; then
      cost="$HINT_COST"
    else
      # nth word of HINT_PCT; the last value repeats for any extra hints
      pct="$(printf '%s\n' $HINT_PCT | sed -n "${idx}p")"
      [ -n "$pct" ] || pct="$(printf '%s\n' $HINT_PCT | tail -1)"
      cost=$(( points * pct / 100 ))
    fi
    resp="$(ctfd_api POST "/hints" "$(jq -nc --argjson c "$cid" --arg content "$h" --argjson cost "$cost" \
        '{challenge:$c, challenge_id:$c, content:$content, cost:$cost, type:"standard"}')")"
    printf '%s' "$resp" | jq -e '.success == true' >/dev/null 2>&1 && n=$((n+1))
  done <<EOHINT
$hints
EOHINT
  [ "$n" -gt 0 ] && ok "  $n hint(s) attached (costs: $HINT_PCT % of $points)"
  return 0
}

# Create or update ONE CTFd challenge object with exactly one static flag and the
# given hints (one per line in $7). Idempotent on name: a re-run PATCHes in
# place and recreates flags/hints, so a stale duplicate flag can never score.
#   ctfd_upsert NAME CATEGORY POINTS MAX_ATTEMPTS DESCRIPTION FLAG HINTS [case_insensitive]
ctfd_upsert() {
  local name="$1" cat="$2" points="$3" maxatt="$4" desc="$5" flag="$6" hints="$7" fdata="${8:-}"
  local cid body resp
  cid="$(ctfd_api GET '/challenges?view=admin' | jq -r --arg n "$name" '.data[]? | select(.name==$n) | .id' | head -1 || true)"
  body="$(jq -nc --arg name "$name" --arg cat "$cat" --arg desc "$desc" --argjson value "$points" \
      --argjson maxatt "$maxatt" \
      '{name:$name, category:$cat, description:$desc, value:$value,
        max_attempts:$maxatt, type:"standard", state:"visible"}')"
  if [ -n "$cid" ]; then
    resp="$(ctfd_api PATCH "/challenges/$cid" "$(printf '%s' "$body" | jq -c 'del(.type)')")"
    printf '%s' "$resp" | jq -e '.success == true' >/dev/null 2>&1 \
      || { warn "$name: CTFd update failed: $(printf '%s' "$resp" | cut -c1-200)"; return 1; }
    ctfd_clear_children "$cid" flags
    ctfd_clear_children "$cid" hints
    ok "$name: updated in CTFd (id $cid)"
  else
    resp="$(ctfd_api POST "/challenges" "$body")"
    printf '%s' "$resp" | jq -e '.success == true' >/dev/null 2>&1 \
      || { warn "$name: CTFd create failed: $(printf '%s' "$resp" | cut -c1-200)"; return 1; }
    cid="$(printf '%s' "$resp" | jq -r '.data.id')"
    ok "$name: created in CTFd (id $cid, $points pts, $cat)"
  fi

  # CTFd's own admin UI posts `challenge`; the schema also accepts
  # `challenge_id`. Send both so this survives either reading.
  resp="$(ctfd_api POST "/flags" "$(jq -nc --argjson c "$cid" --arg content "$flag" --arg data "$fdata" \
      '{challenge:$c, challenge_id:$c, content:$content, type:"static", data:$data}')")"
  printf '%s' "$resp" | jq -e '.success == true' >/dev/null 2>&1 \
    && ok "  flag attached" || warn "  $name: flag POST failed: $(printf '%s' "$resp" | cut -c1-160)"

  ctfd_attach_hints "$cid" "$points" "$hints"
  return 0
}

# Register whatever a challenge directory turns into in CTFd:
#   - questions.json present -> one CTFd challenge PER QUESTION (NCL style). The
#     scenario prose and data link go on every question; answers are plain
#     values (an IP, a username), matched case-insensitively.
#   - otherwise -> one challenge, flag from challenge.yml.
register_static_challenge() {
  local f="$1" d name cat points desc flag conn maxatt
  d="$(dirname "$f")"
  name="$(chal_get "$f" name)"
  cat="$(chal_get "$f" category)";  [ -n "$cat" ]    || cat="Misc"
  points="$(chal_get "$f" points)"; [ -n "$points" ] || points=100
  maxatt="$(chal_get "$f" max_attempts)"
  case "$maxatt" in ''|*[!0-9]*) maxatt=0 ;; esac

  desc="$(chal_desc "$d")"
  [ -n "$desc" ] || desc="Flag format: $FLAG_PREFIX{...}"
  # `hide_address: true` (and every info challenge) suppresses the generated
  # connection line.
  if [ "$(chal_type "$f")" != "info" ] && [ "$(chal_get "$f" hide_address)" != "true" ]; then
    conn="$(chal_connline "$f")"
    desc="$desc

\`$conn\`"
  fi

  if [ -f "$d/questions.json" ]; then
    local i qn qid qtext qans qpts qatt qhints old
    # A dataset that used to be a single flag challenge leaves its old object
    # behind under the bare name; it would still score. Remove it.
    old="$(ctfd_api GET '/challenges?view=admin' | jq -r --arg n "$name" '.data[]? | select(.name==$n) | .id' | head -1 || true)"
    [ -n "$old" ] && ctfd_api DELETE "/challenges/$old" >/dev/null 2>&1 && ok "$name: replaced single-flag challenge (id $old) with a question set"
    qn="$(jq 'length' "$d/questions.json")"
    i=0
    while [ "$i" -lt "$qn" ]; do
      qid="$(jq -r ".[$i].id" "$d/questions.json")"
      qtext="$(jq -r ".[$i].question" "$d/questions.json")"
      qans="$(jq -r ".[$i].answer" "$d/questions.json")"
      qpts="$(jq -r ".[$i].points" "$d/questions.json")"
      qatt="$(jq -r ".[$i].max_attempts // \"$maxatt\"" "$d/questions.json")"
      qhints="$(jq -r ".[$i].hints // [] | .[]" "$d/questions.json")"
      ctfd_upsert "$name: $qid" "$cat" "$qpts" "$qatt" "$desc

---

**Question:** $qtext" "$qans" "$qhints" "case_insensitive" || true
      i=$((i+1))
    done
    return 0
  fi

  flag="$(chal_get "$f" flag)"
  [ -n "$flag" ] || { warn "$name: no flag in challenge.yml - skipped"; return 1; }
  ctfd_upsert "$name" "$cat" "$points" "$maxatt" "$desc" "$flag" "$(chal_hints "$d")"
}

# Unlock order and visibility, applied after every registration so a fresh
# deploy reproduces it (it used to be set by hand and vanished on redeploy):
#   RULES_CHALLENGE  ->  GATE_CHALLENGE  ->  everything else
# `hidden: true` in challenge.yml hides a challenge from players entirely.
apply_gating() {
  local all rid gid id nm d f handled=" "
  all="$(ctfd_api GET '/challenges?view=admin' | jq -c '[.data[]? | {id, name}]')"
  rid="$(printf '%s' "$all" | jq -r --arg n "$RULES_CHALLENGE" '.[] | select(.name==$n) | .id' | head -1)"
  gid="$(printf '%s' "$all" | jq -r --arg n "$GATE_CHALLENGE" '.[] | select(.name==$n) | .id' | head -1)"
  [ -n "$gid" ] || { warn "gate challenge '$GATE_CHALLENGE' not in CTFd - nothing gated"; return 0; }
  req() {  # req CHALLENGE_ID PREREQ_ID|""
    local body
    if [ -n "$2" ]; then body="$(jq -nc --argjson p "$2" '{requirements:{prerequisites:[$p], anonymize:false}}')"
    else body='{"requirements":{"prerequisites":[]}}'; fi
    ctfd_api PATCH "/challenges/$1" "$body" >/dev/null 2>&1 || warn "could not set requirements on challenge $1"
  }
  cid_by_name() { printf '%s' "$all" | jq -r --arg n "$1" '.[] | select(.name==$n) | .id' | head -1; }

  [ -n "$rid" ] && req "$rid" ""
  req "$gid" "$rid"
  handled="$handled$gid ${rid:+$rid }"

  # Question-set challenges (a questions.json beside challenge.yml) register one
  # CTFd object per question, named "<name>: <qid>". Chain them in file order so
  # a player must solve question 1 to unlock question 2, and so on - the first
  # question gates on start-here like everything else.
  for d in $(challenge_dirs); do
    f="$d/challenge.yml"
    [ -f "$d/questions.json" ] || continue
    nm="$(chal_get "$f" name)"
    local prev="$gid" qid qcid first=""
    while IFS= read -r qid; do
      [ -n "$qid" ] || continue
      qcid="$(cid_by_name "$nm: $qid")"
      [ -n "$qcid" ] || continue
      req "$qcid" "$prev"
      handled="$handled$qcid "
      prev="$qcid"; [ -n "$first" ] || first="$qid"
    done <<EOQ
$(jq -r '.[].id' "$d/questions.json")
EOQ
    [ -n "$first" ] && ok "$nm: $(jq 'length' "$d/questions.json") questions chained in sequence"
  done

  # On-site tracks (categories "Physical" and "Scavenger" - the router flags and
  # the NFC hunt) gate on the rules challenge directly, not on start-here: those
  # players solve in the room and never touch the VPN/netcat gate.
  if [ -n "$rid" ]; then
    for d in $(challenge_dirs); do
      f="$d/challenge.yml"
      case "$(chal_get "$f" category)" in Physical|Scavenger) ;; *) continue;; esac
      nm="$(chal_get "$f" name)"
      for id in $(printf '%s' "$all" | jq -r --arg n "$nm" '.[] | select(.name==$n or (.name|startswith($n + ": "))) | .id'); do
        req "$id" "$rid"; handled="$handled$id "
      done
    done
  fi

  # Everything else gates on start-here directly.
  for id in $(printf '%s' "$all" | jq -r '.[].id'); do
    case "$handled" in *" $id "*) continue;; esac
    req "$id" "$gid"
  done

  # Hidden challenges (every CTFd object whose name is the challenge or one of
  # its questions) are set to state=hidden.
  for d in $(challenge_dirs); do
    f="$d/challenge.yml"
    [ "$(chal_get "$f" hidden)" = "true" ] || continue
    nm="$(chal_get "$f" name)"
    for id in $(printf '%s' "$all" | jq -r --arg n "$nm" '.[] | select(.name==$n or (.name|startswith($n + ": "))) | .id'); do
      ctfd_api PATCH "/challenges/$id" '{"state":"hidden"}' >/dev/null 2>&1 && ok "$nm: hidden from players"
    done
  done
  ok "unlock order applied: ${RULES_CHALLENGE:-<none>} -> $GATE_CHALLENGE -> challenges (question sets chained per question)"

  # Registration code: gate CTFd signup behind REGISTRATION_CODE (empty clears it).
  local rc_resp
  rc_resp="$(ctfd_api PATCH /configs "$(jq -nc --arg c "$REGISTRATION_CODE" '{registration_code:$c}')")"
  if printf '%s' "$rc_resp" | jq -e '.success == true' >/dev/null 2>&1; then
    [ -n "$REGISTRATION_CODE" ] && ok "registration code enforced on CTFd signup" || ok "registration code cleared (open signup)"
  else
    warn "could not set registration code: $(printf '%s' "$rc_resp" | cut -c1-140)"
  fi
}

# Create or update a whale challenge in CTFd from challenge.yml. Idempotent on
# name: an existing challenge of the same name is updated (new image tag etc.).
register_dynamic_challenge() {
  local f="$1" tag="$2"
  local name cat points desc port redirect mem cpus image
  name="$(chal_get "$f" name)"; cat="$(chal_get "$f" category)"; points="$(chal_get "$f" points)"
  desc="$(chal_get "$f" description)"; port="$(chal_get "$f" port)"
  redirect="$(chal_get "$f" redirect)"; [ -n "$redirect" ] || redirect="direct"
  mem="$(chal_get "$f" memory)"; [ -n "$mem" ] || mem="128M"
  cpus="$(chal_get "$f" cpus)"; [ -n "$cpus" ] || cpus="0.5"
  image="$CTFD_VPC_IP:5000/$name:$tag"
  # README "## Description (paste into CTFd)" wins over the one-line yml field.
  local rdesc; rdesc="$(chal_desc "$(dirname "$f")")"
  [ -n "$rdesc" ] && desc="$rdesc

Press **Start** to get your own private instance. Its flag is unique to you."
  [ -n "$desc" ] || desc="Press Start to get your own instance. Flag format: $FLAG_PREFIX{...}"

  local existing etype
  existing="$(ctfd_api GET '/challenges?view=admin' | jq -r --arg n "$name" '.data[]? | select(.name==$n) | .id' | head -1)"
  # A challenge converted from static still exists as type "standard". CTFd does
  # not change a challenge's type on PATCH, so the whale fields would be silently
  # dropped and players would get a challenge with no Start button. Recreate it.
  if [ -n "$existing" ]; then
    etype="$(ctfd_api GET "/challenges/$existing" | jq -r '.data.type // empty')"
    if [ "$etype" != "dynamic_docker" ]; then
      ctfd_api DELETE "/challenges/$existing" >/dev/null 2>&1 \
        && ok "$name: removed old '$etype' challenge (id $existing) to recreate it as a per-player instance"
      existing=""
    fi
  fi
  local body
  body="$(jq -nc --arg name "$name" --arg cat "$cat" --arg desc "$desc" --argjson value "$points" \
      --arg image "$image" --arg rt "$redirect" --argjson port "$port" --arg mem "$(printf '%s' "$mem" | tr 'M' 'm' | tr 'G' 'g')" --argjson cpus "$cpus" \
      '{name:$name, category:$cat, description:$desc, value:$value, initial:$value, minimum:$value, decay:0,
        type:"dynamic_docker", docker_image:$image, redirect_type:$rt, redirect_port:$port,
        memory_limit:$mem, cpu_limit:$cpus, dynamic_score:0, state:"visible"}')"
  local resp
  if [ -n "$existing" ]; then
    resp="$(ctfd_api PATCH "/challenges/$existing" "$(printf '%s' "$body" | jq -c 'del(.type,.initial)')")"
    printf '%s' "$resp" | jq -e '.success == true' >/dev/null 2>&1 \
      && ok "$name: updated in CTFd (id $existing, image $image)" || warn "$name: CTFd update failed: $(printf '%s' "$resp" | cut -c1-160)"
    ctfd_clear_children "$existing" hints
    ctfd_attach_hints "$existing" "$points" "$(chal_hints "$(dirname "$f")")"
  else
    resp="$(ctfd_api POST "/challenges" "$body")"
    printf '%s' "$resp" | jq -e '.success == true' >/dev/null 2>&1 \
      && ok "$name: created in CTFd (id $(printf '%s' "$resp" | jq -r '.data.id'), $points pts, $cat)" \
      || warn "$name: CTFd create failed: $(printf '%s' "$resp" | cut -c1-200)"
    existing="$(printf '%s' "$resp" | jq -r '.data.id // empty')"
    [ -n "$existing" ] && ctfd_attach_hints "$existing" "$points" "$(chal_hints "$(dirname "$f")")"
  fi
}

# End-to-end proof that whale works: start an instance of the first dynamic
# challenge as the admin, wait for its port to answer on the CTFd VPC address
# (probed from the gateway, the same path a player's packets take), destroy it.
whale_smoke_test() {
  local f="$1" name cid resp port i
  name="$(chal_get "$f" name)"
  ctfd_admin_login || { warn "smoke test skipped: no admin session"; return 1; }
  cid="$(ctfd_api GET '/challenges?view=admin' | jq -r --arg n "$name" '.data[]? | select(.name==$n) | .id' | head -1)"
  [ -n "$cid" ] || { warn "smoke test: challenge $name not found in CTFd"; ctfd_admin_logout; return 1; }
  log "whale smoke test: starting an instance of $name (challenge $cid)"
  resp="$(ctfd_api POST "/plugins/ctfd-whale/container?challenge_id=$cid" '{}')"
  if ! printf '%s' "$resp" | jq -e '.success == true' >/dev/null 2>&1; then
    warn "instance start failed: $(printf '%s' "$resp" | jq -r '.message // .' 2>/dev/null | cut -c1-200)"
    warn "on the CTFd node: docker compose logs ctfd | grep -A20 Traceback"
    ctfd_admin_logout; return 1
  fi
  port=""
  for i in 1 2 3 4 5 6; do
    resp="$(ctfd_api GET "/plugins/ctfd-whale/container?challenge_id=$cid")"
    # `|| true`: on the first polls the instance has no access info yet, grep
    # matches nothing, and pipefail would abort the whole run mid-retry.
    port="$(printf '%s' "$resp" | jq -r '.data.user_access // ""' | grep -oE '[0-9]{4,5}' | tail -1 || true)"
    [ -n "$port" ] && break; sleep 3
  done
  [ -n "$port" ] || { warn "instance started but no access info returned: $(printf '%s' "$resp" | cut -c1-160)"; ctfd_api DELETE "/plugins/ctfd-whale/container" >/dev/null; ctfd_admin_logout; return 1; }
  ok "instance up: players would be told '$(printf '%s' "$resp" | jq -r '.data.user_access')'"
  local up=0
  for i in $(seq 1 12); do
    ssh_gw "$GW_ADDR" "timeout 4 bash -c 'exec 3<>/dev/tcp/$CTFD_VPC_IP/$port' 2>/dev/null" && { up=1; break; }
    sleep 5
  done
  if [ "$up" = 1 ]; then ok "verified: $CTFD_VPC_IP:$port answers from the gateway (frps -> frpc -> instance on the challenge host)"
  else warn "VERIFY FAILED: $CTFD_VPC_IP:$port never answered - check 'docker compose logs frpc' on the CTFd node and 'docker service ls' on it"; fi
  # Instance must not leak its flag through the environment.
  local envleak
  envleak="$(ssh_via "$CHAL_VPC_IP" "$GW_ADDR" "c=\$(docker ps -q --filter label=whale_id | head -1); [ -n \"\$c\" ] && docker exec \$c cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' | grep -c '^FLAG=' || echo 0" 2>/dev/null | tail -1 || true)"
  case "$envleak" in 0) ok "verified: FLAG scrubbed from the instance environment";; *) warn "instance still exposes FLAG in /proc/1/environ - the image must pop it (see challenges/README.md)";; esac
  # Whale rate-limits container API calls per user (frequency_limited); a
  # destroy right after the start is refused with 403. Back off and retry.
  local tries=0
  while :; do
    resp="$(ctfd_api DELETE "/plugins/ctfd-whale/container")"
    printf '%s' "$resp" | jq -e '.success == true' >/dev/null 2>&1 && { ok "instance destroyed"; break; }
    tries=$((tries+1)); [ "$tries" -ge 4 ] && { warn "destroy returned: $(printf '%s' "$resp" | cut -c1-120)"; break; }
    sleep 12
  done
  ctfd_admin_logout
  [ "$up" = 1 ]
}

# Sync CTFd challenge objects with the challenge/ directory WITHOUT rebuilding
# or redeploying anything. Safe to run mid-event: it only touches CTFd, so a
# reworded description or a repriced hint needs no image churn.
# Turn hints on or off on the live scoreboard, then re-sync CTFd. Hint text is
# never lost - it stays in each challenge's README.md / questions.json.
cmd_hints() {
  case "$1" in
    on|true)   ATTACH_HINTS=true ;;
    off|false) ATTACH_HINTS=false ;;
    *) die "usage: $(basename "$0") hints on|off" ;;
  esac
  export ATTACH_HINTS
  log "hints -> $ATTACH_HINTS (re-syncing CTFd)"
  cmd_register
}

cmd_register() {
  preflight
  [ -f "$STATE_FILE" ] || die "no $STATE_FILE - deploy the infrastructure first"
  local n; n="$(validate_challenges)"
  ok "$n challenge(s) validated"
  load_secrets 2>/dev/null || true
  CTFD_PUB="$(jq -r '.nodes.ctfd.public_ip' "$STATE_FILE")"
  ctfd_admin_login || die "could not log into CTFd as $CTFD_ADMIN_USER"
  local d f done_n=0
  for d in $(challenge_dirs); do
    f="$d/challenge.yml"
    if [ "$(chal_type "$f")" = "dynamic" ]; then
      # register does not rebuild dynamic images, but it DOES sync their hints so
      # `hints on/off` covers them: find the existing CTFd object and clear (then
      # re-attach when hints are on) without touching the running image.
      local dname dcid dpts
      dname="$(chal_get "$f" name)"; dpts="$(chal_get "$f" points)"; [ -n "$dpts" ] || dpts=100
      dcid="$(ctfd_api GET '/challenges?view=admin' | jq -r --arg n "$dname" '.data[]? | select(.name==$n) | .id' | head -1 || true)"
      if [ -n "$dcid" ]; then
        ctfd_clear_children "$dcid" hints
        ctfd_attach_hints "$dcid" "$dpts" "$(chal_hints "$d")"
        ok "$dname: dynamic - hints synced (image left as-is; use [5] to rebuild)"
      else
        warn "$dname: dynamic and not yet in CTFd - run [5] to build and register it"
      fi
    else
      register_static_challenge "$f" && done_n=$((done_n+1)) || true
    fi
  done
  apply_gating
  ctfd_admin_logout
  hr
  # load_secrets does not export CTFD_URL; derive it the same way cmd_deploy does.
  local url; url="$( [ -n "$CTF_DOMAIN" ] && echo "https://$CTF_DOMAIN" || echo "https://$CTFD_PUB" )"
  ok "$done_n static challenge(s) present in CTFd at $url/challenges"
  printf '  Players reach them at %s over the VPN.\n' "$CHAL_VPC_IP"
  hr
}

cmd_challenges_rm() {
  preflight
  [ -f "$STATE_FILE" ] || die "no $STATE_FILE"
  printf 'Remove every running challenge? Players lose in-progress state. [y/N]: '
  local a; read -r a
  [ "$a" = "y" ] || [ "$a" = "Y" ] || { warn "aborted"; return 1; }
  local gwpub; gwpub="$(jq -r '.nodes.gateway.public_ip' "$STATE_FILE")"
  resolve_gateway "$gwpub" || return 1
  ssh_via "$CTFD_VPC_IP" "$GW_ADDR" "docker stack rm ctf" && ok "stack removed" || warn "stack rm failed"
}

# ================================ SELF TEST ==================================
# Offline validation: builds a throwaway PKI, assembles profiles, and renders
# every cloud-init template so placeholder and size problems surface here
# rather than as a rejected API call halfway through a deploy.
cmd_selftest() {
  local missing=""
  for c in openssl jq perl; do command -v "$c" >/dev/null 2>&1 || missing="$missing $c"; done
  [ -z "$missing" ] || die "missing:$missing"

  local sandbox; sandbox="$(mktemp -d -t ctfselftest)"
  # EVERYTHING the selftest writes goes into the sandbox. generate_secrets
  # persists to SECRETS_FILE; pointing it at the real file once clobbered a
  # live deployment's credentials 25 seconds after that deployment finished.
  PKI_DIR="$sandbox/pki"; PROFILE_DIR="$sandbox/profiles"
  SECRETS_FILE="$sandbox/ctf_secrets.env"; STATE_FILE="$sandbox/ctf_state.json"
  ADMIN_IP_V4="203.0.113.10"; ADMIN_IP_V6="2001:db8:1:2::/64"

  hr; printf '%sSELF TEST (offline - no Linode API calls)%s\n' "$C_BOLD" "$C_RST"; hr

  generate_secrets
  local t0 t1
  t0=$(date +%s); generate_pki; t1=$(date +%s)
  ok "PKI built in $((t1-t0))s"

  # Verify the chain actually validates, and that the CRL parses.
  openssl verify -CAfile "$PKI_DIR/ca/ca.crt" "$PKI_DIR/server/server.crt" >/dev/null \
    && ok "server cert verifies against CA" || die "server cert does not verify"
  openssl verify -CAfile "$PKI_DIR/ca/ca.crt" "$PKI_DIR/clients/player01.crt" >/dev/null \
    && ok "client cert verifies against CA" || die "client cert does not verify"
  openssl x509 -in "$PKI_DIR/server/server.crt" -noout -text \
    | grep -q "TLS Web Server" && ok "server cert has serverAuth EKU" || die "server EKU wrong"
  openssl x509 -in "$PKI_DIR/clients/player01.crt" -noout -text \
    | grep -q "TLS Web Client" && ok "client cert has clientAuth EKU" || die "client EKU wrong"
  openssl crl -in "$PKI_DIR/crl.pem" -noout -text >/dev/null \
    && ok "CRL parses" || die "CRL malformed"

  # tls-crypt key must be exactly 16 lines of 32 hex chars between markers.
  local kl; kl=$(sed -n '/BEGIN OpenVPN Static key/,/END OpenVPN Static key/p' "$PKI_DIR/tls-crypt.key" \
    | grep -c '^[0-9a-f]\{32\}$')
  [ "$kl" = "16" ] && ok "tls-crypt key well-formed (16x32 hex = 2048 bits)" \
    || die "tls-crypt key has $kl body lines, expected 16"

  build_profiles "198.51.100.20"
  local n; n=$(ls -1 "$PROFILE_DIR"/*.ovpn | wc -l | tr -d ' ')
  [ "$n" = "$((PLAYER_COUNT + 1))" ] && ok "$n profiles assembled" || die "expected $((PLAYER_COUNT+1)) profiles, got $n"
  for tag in ca cert key tls-crypt; do
    grep -q "<$tag>" "$PROFILE_DIR/player01.ovpn" || die "player01.ovpn missing <$tag> block"
  done
  ok "profile inline blocks present (ca, cert, key, tls-crypt)"
  local bytes; bytes=$(du -sk "$PROFILE_DIR" | awk '{print $1}')
  ok "profile bundle is ${bytes}KB - delivered over SSH, not cloud-init"

  # Render every template with realistic substitutions.
  local subs="$sandbox/subs.tsv"
  write_common_subs "$subs"
  {
    printf 'CA_CRT_B64\t%s\n'     "$(b64 "$PKI_DIR/ca/ca.crt")"
    printf 'SERVER_CRT_B64\t%s\n' "$(b64 "$PKI_DIR/server/server.crt")"
    printf 'SERVER_KEY_B64\t%s\n' "$(b64 "$PKI_DIR/server/server.key")"
    printf 'TLS_CRYPT_B64\t%s\n'  "$(b64 "$PKI_DIR/tls-crypt.key")"
    printf 'CRL_B64\t%s\n'        "$(b64 "$PKI_DIR/crl.pem")"
  } >> "$subs"
  build_caddyfile "$sandbox/Caddyfile"
  printf 'MYSQL_ROOT_PASSWORD=x\nMYSQL_PASSWORD=y\nCTFD_SECRET_KEY=z\nFRP_TOKEN=t\nFRPC_ADMIN_PASSWORD=p\nVPN_ISOLATION_TOKEN=i\n' > "$sandbox/ctfd.env"
  {
    printf 'CADDYFILE_B64\t%s\n' "$(b64 "$sandbox/Caddyfile")"
    printf 'CTFD_ENV_B64\t%s\n'  "$(b64 "$sandbox/ctfd.env")"
  } >> "$subs"

  local t sz
  for t in node1-gateway node2-ctfd node3-challenge node4-wazuh; do
    render_template "$TPL_DIR/$t.yaml.tpl" "$subs" > "$sandbox/$t.yaml"
    sz="$(render_check "$sandbox/$t.yaml")"
    printf '  %s[ok]%s %-18s %6s B gzipped  (%d%% of the 16384 B decoded limit)\n' \
      "$C_G" "$C_RST" "$t" "$sz" "$((sz * 100 / 16384))"
  done
  ok "all templates render clean and fit in user_data"

  local cn; cn="$(validate_challenges)"
  ok "$cn challenge definition(s) in challenges/ validate"
  emit_stack selftest "$sandbox/secrets" > "$sandbox/stack.yml"
  grep -q 'mode: host' "$sandbox/stack.yml" && ok "stack renders with host-mode publishing (no routing mesh)" \
    || die "stack missing mode: host"
  grep -q 'cap_drop' "$sandbox/stack.yml" && ok "stack drops all capabilities by default" || die "stack missing cap_drop"
  grep -q 'FLAG' "$sandbox/stack.yml" && die "flag leaked into stack environment" || ok "flags delivered as secrets, not env"

  printf '\n  Rendered cloud-init kept for inspection: %s\n' "$sandbox"
  hr
  ok "self test passed"
}

# ================================== MENU =====================================
menu() {
  while true; do
    hr
    printf '%s%s - infrastructure control%s\n' "$C_BOLD" "$EVENT_NAME" "$C_RST"
    if [ -f "$STATE_FILE" ]; then
      printf '  state: %sdeployed%s %s   region %s\n' "$C_G" "$C_RST" \
        "$(jq -r '.created' "$STATE_FILE")" "$CTF_REGION"
    else
      printf '  state: %snot deployed%s   region %s\n' "$C_Y" "$C_RST" "$CTF_REGION"
    fi
    hr
    printf '  [1] Deploy Infrastructure\n'
    printf '  [2] Status Check\n'
    printf '  [3] Teardown Infrastructure\n'
    printf '  [4] Revoke Player VPN Certificate\n'
    printf '  [5] Deploy / Update Challenges\n'
    printf '  [6] Remove All Challenges\n'
    printf '  [7] Sync Challenges to CTFd  (no rebuild)\n'
    printf '  [8] Exit\n\n'
    printf 'Select: '
    local c; read -r c || exit 0
    echo
    case "$c" in
      1) cmd_deploy   || warn "deploy did not complete";;
      2) cmd_status   || warn "status incomplete";;
      3) cmd_teardown || warn "teardown incomplete";;
      4) cmd_revoke   || warn "revoke incomplete";;
      5) cmd_challenges    || warn "challenge deploy incomplete";;
      6) cmd_challenges_rm || warn "challenge removal incomplete";;
      7) cmd_register      || warn "challenge registration incomplete";;
      8) exit 0;;
      *) warn "choose 1-8";;
    esac
  done
}

case "${1:-}" in
  deploy)   cmd_deploy;;
  status)   cmd_status;;
  resume)   cmd_resume;;
  teardown) cmd_teardown;;
  revoke)   cmd_revoke;;
  challenges)    cmd_challenges;;
  challenges-rm) cmd_challenges_rm;;
  register)      cmd_register;;
  hints)         cmd_hints "${2:-}";;
  whale-config)  cmd_whale_config;;
  selftest) cmd_selftest;;
  "")       menu;;
  *)        die "usage: $(basename "$0") [deploy|resume|status|teardown|revoke|challenges|challenges-rm|register|hints on|off|whale-config|selftest]";;
esac

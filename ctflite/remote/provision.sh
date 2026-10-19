#!/usr/bin/env bash
# Runs ON the Linode as root. Fresh Debian 12 box, one host, no VPC, no VPN.
#
# Expects from the caller:
#   EVENT_NAME EVENT_DESC CTF_USER_MODE CTF_TEAM_SIZE CTFD_VERSION
#   CTFD_ADMIN_USER CTFD_ADMIN_EMAIL CTFD_ADMIN_PW CTFD_REGISTRATION_CODE
#   CTFD_DB_PW CTFD_DB_ROOT_PW CTFD_SECRET_KEY
#   FLAG_PREFIX HINT_COST ADMIN_CIDR PLAYER_CIDR
#   RESTORE_ARCHIVE   (optional; path to a ctflite backup tarball on the box)
#
# Challenge sources are expected at /opt/ctflite/challenges (uploaded before
# this runs).

set -euo pipefail

BASE=/opt/ctflite
SRC=$BASE/challenges
SECRETS=$BASE/secrets
COMPOSE=$BASE/compose

say() { printf '\n\033[1;36m[provision]\033[0m %s\n' "$*"; }

# ---------------------------------------------------------------- packages
say "Installing base packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  ca-certificates curl gnupg jq ufw python3 python3-yaml rsync >/dev/null

if ! command -v docker >/dev/null 2>&1; then
  say "Installing Docker"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
fi
docker --version

say "Adding 2G swap (a 4 GB box running CTFd + 10 challenges has little slack)"
if [[ ! -f /swapfile ]]; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap -q /swapfile && swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# ---------------------------------------------------------------- firewall
# Ordered deliberately: the challenge ports are read out of the challenge
# definitions, so adding a challenge opens exactly one more port and no range.
say "Firewall"
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
# ADMIN_CIDR may carry several CIDRs (v4 and v6); each needs its own rule.
for c in ${ADMIN_CIDR}; do
  ufw allow from "$c" to any port 22 proto tcp >/dev/null
done
# Players are NOT let in yet. Until ctfd_init has run, CTFd is unconfigured and
# /setup is an open, unauthenticated wizard: anyone who loads it can create
# their own admin account and take over the event. On a fresh deploy that
# window is as long as the image builds. :80 and the challenge ports are opened
# to PLAYER_CIDR by open_to_players() at the very end, so a provisioning run
# that dies half way leaves the box closed rather than hijackable.
for c in ${ADMIN_CIDR}; do
  ufw allow from "$c" to any port 80 proto tcp >/dev/null
done

CHAL_PORTS=()
for d in "$SRC"/*/; do
  [[ -f "$d/challenge.yml" ]] || continue
  [[ "$(basename "$d")" == "_template" ]] && continue
  t=$(awk -F': *' '$1=="type"{print $2; exit}' "$d/challenge.yml" | tr -d '"'"'"' \r')
  [[ "$t" == "dynamic" ]] && continue
  p=$(awk -F': *' '$1=="published"{print $2; exit}' "$d/challenge.yml" | tr -d '"'"'"' \r')
  pr=$(awk -F': *' '$1=="protocol"{print $2; exit}' "$d/challenge.yml" | tr -d '"'"'"' \r')
  [[ -z "$p" ]] && continue
  [[ -z "$pr" ]] && pr=tcp
  for c in ${ADMIN_CIDR}; do
    ufw allow from "$c" to any port "$p" proto "$pr" >/dev/null
  done
  CHAL_PORTS+=("$p/$pr")
done
ufw --force enable >/dev/null
echo "  ssh 22 <- ${ADMIN_CIDR}"
echo "  ctfd 80, challenges ${CHAL_PORTS[*]:-none} <- ${ADMIN_CIDR} (players admitted at the end)"

# Docker publishes past ufw by writing its own DOCKER-USER chain rules, so ufw
# alone does NOT protect a published container port. Close that gap explicitly.
say "Constraining Docker's own iptables chain to PLAYER_CIDR"
cat > /etc/docker/daemon.json <<'DJSON'
{ "log-driver": "json-file", "log-opts": { "max-size": "10m", "max-file": "3" } }
DJSON
systemctl restart docker
sleep 3
iptables -F DOCKER-USER 2>/dev/null || true
if [[ "${PLAYER_CIDR}" != "0.0.0.0/0" ]]; then
  iptables -I DOCKER-USER -i eth0 ! -s "${PLAYER_CIDR}" -j DROP
  echo "  DOCKER-USER drops non-${PLAYER_CIDR} traffic to published ports"
else
  echo "  PLAYER_CIDR is the whole internet - no DOCKER-USER restriction applied"
fi
iptables -A DOCKER-USER -j RETURN 2>/dev/null || true

# ---------------------------------------------------------------- layout
mkdir -p "$SECRETS" "$COMPOSE" "$BASE/data/CTFd/logs" "$BASE/data/CTFd/uploads"
# The CTFd container runs as uid 1001 and cannot read root-owned 0700 dirs.
chown -R 1001:1001 "$BASE/data/CTFd"
chmod 700 "$SECRETS"

# ---------------------------------------------------------------- CTFd stack
say "Writing the CTFd stack"
cat > "$COMPOSE/docker-compose.yml" <<'CEOF'
services:
  ctfd:
    image: ctfd/ctfd:CTFD_VERSION_HERE
    restart: always
    environment:
      - UPLOAD_FOLDER=/var/uploads
      - DATABASE_URL=mysql+pymysql://ctfd:CTFD_DB_PW_HERE@db/ctfd
      - REDIS_URL=redis://cache:6379
      - WORKERS=2
      - LOG_FOLDER=/var/log/CTFd
      - ACCESS_LOG=-
      - ERROR_LOG=-
      - SECRET_KEY=CTFD_SECRET_KEY_HERE
      - REVERSE_PROXY=false
    volumes:
      - ../data/CTFd/logs:/var/log/CTFd
      - ../data/CTFd/uploads:/var/uploads
    ports:
      - "80:8000"
    depends_on:
      - db
      - cache
    networks:
      - ctfd_internal

  db:
    image: mariadb:10.11
    restart: always
    environment:
      - MARIADB_ROOT_PASSWORD=CTFD_DB_ROOT_PW_HERE
      - MARIADB_USER=ctfd
      - MARIADB_PASSWORD=CTFD_DB_PW_HERE
      - MARIADB_DATABASE=ctfd
      - MARIADB_AUTO_UPGRADE=1
    volumes:
      - ../data/mysql:/var/lib/mysql
    networks:
      - ctfd_internal
    command: [mysqld, --character-set-server=utf8mb4, --collation-server=utf8mb4_unicode_ci, --wait_timeout=28800, --log-warnings=0]

  cache:
    image: redis:4
    restart: always
    volumes:
      - ../data/redis:/data
    networks:
      - ctfd_internal

networks:
  # No `internal: true` here - ctfd publishes :80, and a published port cannot
  # come from an internal network.
  ctfd_internal:
    driver: bridge
CEOF

sed -i "s|CTFD_VERSION_HERE|${CTFD_VERSION}|; s|CTFD_DB_PW_HERE|${CTFD_DB_PW}|g; \
        s|CTFD_DB_ROOT_PW_HERE|${CTFD_DB_ROOT_PW}|; s|CTFD_SECRET_KEY_HERE|${CTFD_SECRET_KEY}|" \
    "$COMPOSE/docker-compose.yml"
chmod 600 "$COMPOSE/docker-compose.yml"

say "Starting CTFd"
cd "$COMPOSE" && docker compose -p ctfd up -d
echo "  waiting for CTFd to answer on :80"
# curl -w '%{http_code}' ALREADY prints 000 when it cannot connect, so a
# trailing `|| echo 000` yields "000000" - which is != "000", breaks the loop on
# the first attempt and slips past the final guard. The probe then always
# "passes". Never add a fallback echo to a -w '%{http_code}' capture.
code=000
for i in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 http://127.0.0.1/ 2>/dev/null) || code=000
  [[ -z "$code" ]] && code=000
  # Any real HTTP status means gunicorn is serving; 302 to /setup is expected.
  [[ "$code" =~ ^[2345][0-9][0-9]$ ]] && break
  sleep 5
done
echo "  CTFd HTTP $code after ${i} attempt(s)"
if [[ ! "$code" =~ ^[2345][0-9][0-9]$ ]]; then
  docker compose -p ctfd logs --tail 40 ctfd
  echo "CTFd never answered on :80" >&2
  exit 1
fi

# ---------------------------------------------------------------- restore
RESTORED=0
if [[ -n "${RESTORE_ARCHIVE:-}" && -f "${RESTORE_ARCHIVE}" ]]; then
  say "Restoring from $(basename "$RESTORE_ARCHIVE")"
  rm -rf /root/restore && mkdir -p /root/restore
  tar xzf "$RESTORE_ARCHIVE" -C /root/restore
  [[ -f /root/restore/ctfd-db.sql ]] || { echo "archive has no ctfd-db.sql" >&2; exit 1; }

  echo "  importing the database"
  docker compose -p ctfd exec -T db sh -c "exec mysql -uroot -p'${CTFD_DB_ROOT_PW}' ctfd" < /root/restore/ctfd-db.sql

  if [[ -d /root/restore/uploads ]]; then
    echo "  restoring uploads"
    rsync -a --delete /root/restore/uploads/ "$BASE/data/CTFd/uploads/"
    chown -R 1001:1001 "$BASE/data/CTFd/uploads"
  fi

  # CTFd memoizes its config in Redis. The cache was filled moments ago, when
  # CTFd first started against an EMPTY database, so it holds "setup = not
  # done". Restarting the container does not clear Redis, so CTFd keeps
  # redirecting to /setup even though the restored config table says setup=1 -
  # and the whole event looks unconfigured while its data sits there intact.
  # Flush first, restart second.
  echo "  flushing the config cache (Redis still holds the pre-restore state)"
  docker compose -p ctfd exec -T cache redis-cli FLUSHALL >/dev/null 2>&1 || true
  echo "  restarting CTFd so it picks up the restored schema"
  docker compose -p ctfd restart ctfd
  echo "  waiting for CTFd to answer again"
  for i in $(seq 1 40); do
    rc=$(curl -s -o /dev/null -w '%{http_code}' -m 5 http://127.0.0.1/ 2>/dev/null) || rc=000
    [[ "$rc" =~ ^[23][0-9][0-9]$ ]] && break
    sleep 5
  done
  echo "  CTFd HTTP $rc after restore"
  RESTORED=1
  rm -rf /root/restore
fi

# ---------------------------------------------------------------- challenges
say "Building challenges"
BUILT=()
for d in "$SRC"/*/; do
  [[ -f "$d/challenge.yml" && -f "$d/Dockerfile" ]] || continue
  name=$(basename "$d")
  [[ "$name" == "_template" ]] && continue
  t=$(awk -F': *' '$1=="type"{print $2; exit}' "$d/challenge.yml" | tr -d '"'"'"' \r')
  if [[ "$t" == "dynamic" ]]; then
    echo "  skip $name (dynamic - needs ctfd-whale, not in this build)"
    continue
  fi
  echo -n "  $name ... "
  if docker build -q -t "ctflite/$name:latest" "$d" >/dev/null 2>"$BASE/build-$name.log"; then
    echo "built"; BUILT+=("$name")
  else
    echo "FAILED"; tail -20 "$BASE/build-$name.log" >&2; exit 1
  fi
done
echo "  ${#BUILT[@]} challenge image(s)"

# Two compose files in ONE directory share a project name derived from that
# directory, so `-f challenges.yml up --remove-orphans` treated ctfd/db/cache
# as orphans and deleted them. Each stack gets an explicit -p project name.
say "Writing challenge flags and compose file"
python3 "$BASE/gen_compose.py" "$SRC" "$SECRETS" > "$COMPOSE/challenges.yml"
chmod 600 "$COMPOSE"/challenges.yml
# Reclaim the published ports from any container left behind by an earlier run
# under a different compose project. Without this, `up` dies with "port is
# already allocated" and the event comes up with no challenges at all - while
# the stale containers keep serving the OLD images and flags, which is worse
# than failing. Only containers publishing a CHALLENGE port are touched, so
# ctfd (:80) is never a candidate.
for p in "${CHAL_PORTS[@]:-}"; do
  port="${p%%/*}"
  [[ -z "$port" ]] && continue
  for cid in $(docker ps -aq --filter "publish=$port" 2>/dev/null); do
    cname=$(docker inspect -f '{{.Name}}' "$cid" 2>/dev/null | sed 's|^/||')
    case "$cname" in
      chal-*) : ;;   # ours, compose will recreate it
      *) echo "  reclaiming port $port from stale container $cname"
         docker rm -f "$cid" >/dev/null 2>&1 || true ;;
    esac
  done
done

# Always recreate: challenges are stateless, and compose will otherwise REUSE a
# container it created earlier. A container created while its port was still
# held by a previous run starts fine but never gets its host-side publish - the
# process listens inside, PortBindings look right, and `docker port` is empty.
# A down/up pair removes that whole class of ghost.
cd "$COMPOSE" && docker compose -p chal -f challenges.yml down --remove-orphans >/dev/null 2>&1 || true
cd "$COMPOSE" && docker compose -p chal -f challenges.yml up -d --remove-orphans
docker compose -p chal -f challenges.yml ps --format '  {{.Name}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || true

# ---------------------------------------------------------------- CTFd init
say "Initialising CTFd and registering challenges"
EVENT_NAME="$EVENT_NAME" EVENT_DESC="$EVENT_DESC" \
CTF_USER_MODE="$CTF_USER_MODE" CTF_TEAM_SIZE="$CTF_TEAM_SIZE" \
CTFD_ADMIN_USER="$CTFD_ADMIN_USER" CTFD_ADMIN_EMAIL="$CTFD_ADMIN_EMAIL" \
CTFD_ADMIN_PW="$CTFD_ADMIN_PW" CTFD_REGISTRATION_CODE="${CTFD_REGISTRATION_CODE:-}" \
FLAG_PREFIX="$FLAG_PREFIX" HINT_COST="$HINT_COST" \
GATE_CHALLENGE="${GATE_CHALLENGE:-}" \
PUBLIC_HOST="${PUBLIC_HOST:-127.0.0.1}" ALREADY_SETUP="$RESTORED" \
  python3 "$BASE/ctfd_init.py" "$SRC"

# Only now is CTFd configured, so the wizard is closed and it is safe to admit
# the public. If anything above failed, set -e stopped us and these rules were
# never added - the box stays reachable only from ADMIN_CIDR.
say "Admitting players (${PLAYER_CIDR})"
ufw allow from "${PLAYER_CIDR}" to any port 80 proto tcp >/dev/null
for p in "${CHAL_PORTS[@]:-}"; do
  port="${p%%/*}"; proto="${p##*/}"
  [[ -z "$port" ]] && continue
  ufw allow from "${PLAYER_CIDR}" to any port "$port" proto "$proto" >/dev/null
done
# Paranoia: refuse to finish claiming success if CTFd somehow still wants setup.
setup_code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 http://127.0.0.1/setup 2>/dev/null) || setup_code=000
if [[ "$setup_code" == "200" ]]; then
  echo "REFUSING TO OPEN: /setup still serves the wizard - CTFd is not configured." >&2
  for p in "${CHAL_PORTS[@]:-}"; do
    ufw delete allow from "${PLAYER_CIDR}" to any port "${p%%/*}" proto "${p##*/}" >/dev/null 2>&1 || true
  done
  ufw delete allow from "${PLAYER_CIDR}" to any port 80 proto tcp >/dev/null 2>&1 || true
  exit 1
fi
echo "  /setup returns $setup_code (302 = configured, wizard closed)"

say "Provisioning complete"

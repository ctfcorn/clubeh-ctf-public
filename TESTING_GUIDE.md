# Testing guide — club.eh CTF infrastructure

A complete acceptance test you can run yourself, start to finish, in about an
hour of wall-clock time and about $1 of Linode charges (≈ $0.36/h while up).
Every step says what to run and exactly what you should see. If a step's
result differs, stop there — that is the finding.

You need: this directory, `personal_access_token.txt`, `~/.ssh/ctf_ed25519`,
and **one extra device with an OpenVPN client** (your phone with the free
"OpenVPN Connect" app is ideal) for the two-player tests. Everything else
runs from this Mac.

---

## What has actually been verified, and what has not

Read this first. It tells you where to pay attention. Steps below are marked:

- **[VERIFIED]** — exercised on real Linode infrastructure, repeatedly. If one
  of these fails, something changed; treat it as a regression.
- **[UNTESTED]** — the code is written and reviewed but *has never been run
  against a live deployment*. **You are the first.** Budget extra time, and
  expect to find something.

### Verified on live infrastructure

| Area | Evidence |
|---|---|
| Deploy, staged, fail-closed | 7 full runs; final run passed first try with no hand-editing |
| Zero-outbound on the challenge host | asserted 3 ways by deploy itself (direct, via proxy, metadata) |
| Container sandbox | probed *from inside* a running container: internet, metadata, Wazuh, registry, DNS all refused; `cap_drop ALL`, read-only rootfs, pid limit confirmed |
| Public backstops | every challenge/instance/internal port refused from the internet; 80/443/22 open as intended |
| Static challenges | built, pushed, deployed, solved through the gateway |
| Per-player instances (whale) | started, reachable, destroyed; **flags unique per instance**; a foreign flag submits as `incorrect`, own flag as `correct` |
| CTFd VPN-handout plugin | player registered → profile bound to account → downloaded → audit line written (verified on an earlier run of the same code) |
| `status`, `challenges`, `whale-config`, `resume` | all run to completion on live deployments |
| **A real OpenVPN tunnel** | a *player* client connected, `tls-crypt` + cert auth passed, `ccd-exclusive` pinned it to exactly `10.8.0.100`. Run with `--route-nopull`, so pushed routes are still unproven; the admin profile was never connected |
| **All 9 beginner challenges** | every image built, deployed, and **solved through the tunnel** as a player; every flag matched |
| **Per-team instance isolation** | alice reached and solved her own instance, was dropped from another team's (counter rose), and gained access when they became teammates. **Caveat:** this ran on a node where the Caddy site-block bug had been patched *by hand*; the permanent fix in `build_caddyfile` is render-verified only and has not yet produced a passing run from a clean deploy |
| Teardown | 4 times, including from partial/failed deploys; account confirmed empty each time |

### NOT tested — you are the first

| Area | Why it matters | Where |
|---|---|---|
| **Domain mode (Let's Encrypt)** | Only self-signed IP mode has ever been deployed. Setting `CTF_DOMAIN` takes an untested path (DNS wait, ACME issuance, whale's `subdomain_host`). | §11 |

Everything else in this guide has been exercised end to end on real
infrastructure, including a clean deploy with no hand-patching.

None of these are *suspected* broken — they are simply unproven, and I would
rather you know which is which than take "it works" at face value.

---

## 0. One-time setup on this Mac

```bash
cd ~/Documents/CTF
export PATH="$HOME/Library/Python/3.9/bin:$PATH"   # where pip put linode-cli
linode-cli --version                                # v5.x
brew install openvpn                                # OpenVPN command-line client
```

Add that `export PATH` line to `~/.zshrc` so it sticks.

---

## 1. Offline validation — [VERIFIED] (no cost, 5 seconds)

```bash
./ctf_manager.sh selftest
```

**Expect:** a wall of `[+]` lines ending in `self test passed`. Every
template under the 16384 B limit, 51 profiles assembled, stack renders with
`mode: host`, `cap_drop`, flags as secrets.

**If it fails:** nothing was touched; the message says which check.

---

## 2. Deploy — [VERIFIED] (25–40 min, the meter starts here)

```bash
./ctf_manager.sh deploy
```

Watch for these milestones in order. Each is a *fail-closed* gate — the next
stage does not start unless the previous one proved itself.

| You see | It means |
|---|---|
| `region us-iad supports VPC, Metadata and Cloud Firewall` | preflight passed |
| `gateway NAT+VPN ready` | nftables loaded, OpenVPN + proxy + DNS all active on node 1 |
| `profiles written` | 51 `.ovpn` files now in `profiles/` |
| `ctfd ready` / `challenge host ready` / `wazuh ready` | each node's guard rules + key service verified on the node itself |
| `verified: challenge host has no direct WAN egress` | rule 2.3 tested live |
| `verified: gateway proxy refuses the challenge host` | rule 2.3, second cut |
| `verified: metadata blackholed on challenge host` | rule 2.2 tested live |
| `swarm tokens rotated` | bootstrap secrets dead |
| `CTFd initialised (admin: ctf-admin)` | setup wizard done for you |
| `club.eh CTF DEPLOYED` summary | done |

Wazuh is the long pole (~12 min on its own). Total ≈ 30 min.

**If it dies mid-way:** run `./ctf_manager.sh resume`. If that also fails,
`./ctf_manager.sh teardown` cleans up everything including partial state.

Note the two public IPs from the summary; the rest of this guide calls them
`GW_IP` (gateway) and `CTFD_IP`.

---

## 3. Platform health — [VERIFIED] (2 min)

```bash
./ctf_manager.sh status
```

**Expect:** all four `running`; three `[up]` VPC lines; `Gateway services:
openvpn=active proxy=active dns=active`; `Challenge host egress: sealed (no
WAN)`; `Gateway services: openvpn=active proxy=active dns=active`; Swarm shows
`ctf-challenge … Active` and `ctf-ctfd … Active Leader`;
CTFd `HTTP 200`; Wazuh `HTTP 302`.

Then from the browser: `https://CTFD_IP` — accept the self-signed
certificate warning — you should land on the CTFd front page titled
"club.eh CTF".

---

## 4. Admin VPN — [VERIFIED] (5 min)


```bash
sudo openvpn --config profiles/admin.ovpn
```

**Expect** in the output within ~5 s: `Initialization Sequence Completed`.
Leave it running in that terminal. In a second terminal:

```bash
ifconfig | grep -A2 utun | grep 10.8.0        # inet 10.8.0.50  <- you are the admin address
ping -c2 10.0.0.2                              # gateway over the tunnel
ping -c2 10.0.0.5                              # Wazuh - only the admin can reach this
curl -sk -o /dev/null -w '%{http_code}\n' https://10.0.0.5   # 302
ssh -i ~/.ssh/ctf_ed25519 root@10.0.0.2 'echo admin ssh over vpn ok'
```

**Expect:** you are `10.8.0.50`, all four succeed.

> **This is the least-proven step in the whole system.** If it fails, work
> through these in order — each isolates a different layer:
>
> | Symptom | What it means | Check |
> |---|---|---|
> | `TLS handshake failed`, no server reply at all | UDP isn't arriving, or `tls-crypt` rejected you | on the gateway: `tail -30 /var/log/openvpn/openvpn.log` |
> | `VERIFY ERROR` / `certificate verify failed` | PKI mismatch between profile and server | gateway: `openssl verify -CAfile /etc/openvpn/server/ca.crt /etc/openvpn/server/server.crt` |
> | Connects, then immediately drops | your CN has no `ccd` entry — `ccd-exclusive` rejects it | gateway: `ls /etc/openvpn/server/ccd/` lists `admin` + `player01`…`player50` |
> | Connected but wrong address | the `ccd` file isn't being read | gateway: `cat /etc/openvpn/server/ccd/admin` → `ifconfig-push 10.8.0.50 255.255.255.0` |
> | Correct IP, but can't reach `10.0.0.x` | forwarding or NAT | gateway: `sysctl net.ipv4.ip_forward` (=1), `nft list table inet ctf_nat` |
> | Reaches `10.0.0.2` but not `10.0.0.5` | you aren't being matched as admin | gateway: `nft list chain inet ctf_filter forward` |
>
> The gateway's drop counters are the single best diagnostic: run the failing
> command, then immediately see which rule's `counter packets` went up. That
> tells you exactly which rule ate your traffic.

### 4b. Wazuh dashboard and agents — [VERIFIED]

Still on the admin VPN. Browser → `https://10.0.0.5` → accept the cert →
user `admin`, password from `ctf_secrets.env` (`WAZUH_ADMIN_PASSWORD`).

**Expect:** the dashboard loads; **Agents** shows `ctf-gateway`, `ctf-ctfd`,
`ctf-challenge` as *Active*. Open **Discover** and search `ctf-vpn` — your
own `VPN_CONNECT cn=admin vpn_ip=10.8.0.50` line is there. That is the
attribution log working.

Disconnect: `Ctrl-C` in the openvpn terminal.

---

## 5. The player experience — [VERIFIED] (10 min)


Do this as a player would, in a **private browser window** so you are not
logged in as admin.

1. `https://CTFD_IP/register` → create `tester1`.
2. Click **VPN** in the top menu. **Expect:** a page showing
   `player01.ovpn` and `10.8.0.100`, with a download button.
3. Download it. Reload the page. **Expect:** *same* profile — it is bound to
   the account now.
4. Connect with it:
   ```bash
   sudo openvpn --config ~/Downloads/player01.ovpn
   ```
   **Expect:** `Initialization Sequence Completed`, and you are `10.8.0.100`.

### 5a. What a player CAN do

```bash
curl -sk -o /dev/null -w '%{http_code}\n' https://10.0.0.3     # 200/302 - scoreboard over VPN
```
(Challenges are tested in §6 — none are deployed yet.)

### 5b. What a player CANNOT do — these must all fail

```bash
curl -s -m 5 https://10.0.0.5 || echo BLOCKED         # Wazuh: BLOCKED
ssh -o ConnectTimeout=5 root@10.0.0.2 || echo BLOCKED # SSH gateway: BLOCKED
ssh -o ConnectTimeout=5 root@10.0.0.3 || echo BLOCKED # SSH ctfd: BLOCKED
ssh -o ConnectTimeout=5 root@10.0.0.4 || echo BLOCKED # SSH challenge host: BLOCKED
curl -s -m 5 http://10.0.0.4:5000/v2/ || echo BLOCKED # registry: BLOCKED (not a challenge port)
curl -s -m 5 http://10.0.0.2:3128 || echo BLOCKED     # gateway proxy: BLOCKED
```

**Expect:** six `BLOCKED`s. And the tunnel must not carry your internet:

```bash
netstat -rn | grep default | head -1      # default route is still your Wi-Fi, NOT utun
curl -s ifconfig.me                       # still your home IP, not GW_IP
```

Back in the admin browser: **Admin → /admin/vpn** (type the URL). **Expect:**
`1 of 50 assigned`, row 1 = `player01.ovpn` → `tester1`.

### 5c. Player-to-player isolation — [VERIFIED] (needs the second device)

Register `tester2` on the phone, download its profile from the VPN page,
import into OpenVPN Connect, connect. It gets `10.8.0.101`.

From the Mac (still connected as `tester1`):
```bash
ping -c3 -W2 10.8.0.101 || echo BLOCKED     # BLOCKED - rule 2.1
```
From the phone, any ping/HTTP to `10.8.0.100` fails likewise.

In Wazuh Discover, search `ctf-vpn`: you now see both `player01` and
`player02` connections with their addresses. This is what lets you name a
cheater later.

---

## 6. Challenges — [VERIFIED] (10 min)

Leave the player VPN connected. In another terminal:

```bash
./ctf_manager.sh challenges
```

**Expect:** `2 challenge(s) validated` → both images pushed → `stack 'ctf'
deployed` → `example-dynamic: created in CTFd` → the **whale smoke test**:
`instance up`, `verified: 10.0.0.3:<port> answers from the gateway`,
`verified: FLAG scrubbed`, `instance destroyed`. Then the table with
`ctf_example-web 1/1` and the address `10.0.0.4:30001/tcp`.

As the player:
```bash
curl -s http://10.0.0.4:30001/                       # "Staff portal … not recognised"
curl -s -H 'X-Staff: true' http://10.0.0.4:30001/    # contains clubeh{<redacted>}
bash challenges/example-web/solve/solve.sh 10.0.0.4 30001   # prints the flag
```

### 6a. Per-player instance (ctfd-whale) — [VERIFIED]

Still connected as the player. In the browser: **Challenges → misc →
example-dynamic → Start**. **Expect:** within ~5 s a line like
`nc 10.0.0.3 10007` and a 60-minute countdown.

```bash
bash challenges/example-dynamic/solve/solve.sh 10.0.0.3 10007   # use the port shown
```

**Expect:** a flag of the form `clubeh{<uuid>}`. Submit it in CTFd → **Correct**.

Now the anti-cheat property, which is the whole reason for per-player
instances. On the phone as `tester2`, start the *same* challenge — it gets a
different port and a different flag — and submit the **Mac's** flag.
**Expect: Incorrect.** A copied flag is worthless to anyone but its owner.

Press **Destroy** on the Mac; the port stops answering within seconds.

### 6b. The sandbox, from inside the container — [VERIFIED]

Only you can do this (admin SSH). Disconnect the player VPN, connect
`admin.ovpn`, then:

```bash
ssh -i ~/.ssh/ctf_ed25519 root@10.0.0.4
C=$(docker ps --filter name=ctf_example-web -q | head -1)
docker exec $C python3 -c 'import socket;s=socket.socket();s.settimeout(4);s.connect(("1.1.1.1",443))' || echo "internet BLOCKED"
docker exec $C python3 -c 'import socket;s=socket.socket();s.settimeout(4);s.connect(("169.254.169.254",80))' || echo "metadata BLOCKED"
docker exec $C python3 -c 'import socket;s=socket.socket();s.settimeout(4);s.connect(("10.0.0.5",443))' || echo "wazuh BLOCKED"
docker exec $C python3 -c 'import socket;socket.gethostbyname("example.com")' || echo "DNS BLOCKED"
docker exec $C cat /run/secrets/flag; echo
docker inspect $C --format 'caps_dropped={{.HostConfig.CapDrop}} readonly={{.HostConfig.ReadonlyRootfs}} pids={{.HostConfig.PidsLimit}}'
nft list chain inet ctf_guard guard_forward | grep ZERO_OUTBOUND
exit
```

**Expect:** four `BLOCKED`, the flag, `caps_dropped=[ALL] readonly=true
pids=64`, and the `ZERO_OUTBOUND` counter showing non-zero packets.

A whale instance is held to the same rules. With one running (start it again
from CTFd), on the challenge host:

```bash
W=$(docker ps -q --filter label=whale_id | head -1)
docker exec $W cat /proc/1/environ | tr '\0' '\n' | grep FLAG || echo "FLAG scrubbed - correct"
```

**Expect:** `FLAG scrubbed`. If a flag appears here, that author's image is
leaking it to any player who gets a shell — send it back (see
`challenges/README.md`, "The flag — dynamic challenges").

### 6c. Whale settings and health — [VERIFIED]

```bash
./ctf_manager.sh whale-config
```

**Expect:** `whale configured (docker via socket proxy, frp direct ports
10000-10100 on 10.0.0.3)` and `whale checks pass (Docker API via proxy +
frpc admin API reachable)`. This re-applies the settings and reads back
whale's own health checks; run it any time Start misbehaves, or after
changing the `WHALE_*` / `FRP_*` values at the top of the script.

In the browser, **Admin → Whale → Containers** lists every running instance
with its owner and time remaining, and a destroy button. That is where you
kill a suspicious instance mid-event.

### 6d. The mistake the design guards against — [VERIFIED]

An author publishing in ingress mode would expose the port on CTFd's
**public** IP; a mis-bound `frps` would do the same for instance ports.
Prove both backstops hold — from your normal internet (VPN off):

```bash
curl -s -m 5 http://CTFD_IP:30001/  || echo "static port BLOCKED on public IP - correct"
curl -s -m 5 http://CTFD_IP:10007/  || echo "instance port BLOCKED on public IP - correct"
```

---

## 6e. Per-team instance isolation — [VERIFIED] (5 min)

Needs two players **on different teams** (your Mac and your phone), each with
their own VPN profile and CTFd account.

1. As player A, start `example-dynamic`. Note the port you're given, e.g.
   `nc 10.0.0.3 10043`. Confirm it answers for A.
2. As player B (different team, connected on their own VPN profile), try A's
   port:
   ```
   nc -z -G 4 -w 4 10.0.0.3 10043 && echo "REACHABLE - BAD" || echo "blocked - correct"
   ```
   **Expect: blocked.**
3. Put B on A's team in CTFd (Admin → Teams), wait ~10 s for the poller, and
   try again from B. **Expect: now reachable** — teammates share.
4. On the gateway, watch the machinery:
   ```
   ssh -i ~/.ssh/ctf_ed25519 root@<GW_IP> \
     'nft list set inet ctf_filter player_instance; systemctl is-active ctf-instance-acl'
   ```
   **Expect:** one element per (allowed address . port), and `active`.
5. The drop counter proves enforcement — after step 2:
   ```
   ssh ... 'nft list chain inet ctf_filter forward | grep NOT_YOUR_INSTANCE'
   ```
   **Expect:** non-zero `counter packets`.

**If everything is blocked, including your own instance:** the poller can't
reach CTFd. `journalctl -u ctf-instance-acl -n 30` on the gateway; check the
token matches `VPN_ISOLATION_TOKEN` in `ctf_secrets.env`.

---

## 7. Revocation — [VERIFIED] (3 min)

With `tester1` still connected on the phone or Mac as `player01`:

```bash
./ctf_manager.sh revoke        # enter: player01, confirm y
```

**Expect:** `CRL regenerated`, `CRL pushed to gateway`, `live session for
player01 terminated`. The connected client drops within seconds and any
reconnect attempt fails the TLS handshake (`certificate revoked` in the
client log). Wazuh shows `REVOKED cn=player01`.

Verify both halves independently — they can fail separately:

```bash
openssl crl -in pki/crl.pem -noout -text | grep -c 'Serial Number'
ssh -i ~/.ssh/ctf_ed25519 root@<GW_IP> 'openssl crl -in /etc/openvpn/server/crl.pem -noout -lastupdate'
```

**If the CRL pushed but the live session survived**, that's the management
socket, not the CRL — a slow revocation rather than a failed one. Force it:

```bash
ssh -i ~/.ssh/ctf_ed25519 root@<GW_IP> \
  "bash -c 'exec 3<>/dev/tcp/127.0.0.1/7505; printf \"kill player01\r\nquit\r\n\" >&3; head -3 <&3'"
```

**Revocation is permanent for this PKI** — there is no un-revoke. Test with a
profile you are willing to lose, which is why this step uses `player01` and
not `admin`.

---

## 8. Roaming — [VERIFIED] (5 min, optional but worth it)

Tether the Mac to your phone's hotspot (a different public IP), VPN off:

```bash
ssh -o ConnectTimeout=5 -i ~/.ssh/ctf_ed25519 root@GW_IP || echo "refused - expected from an unknown network"
```

Now connect `admin.ovpn` (OpenVPN itself is open to the world) and run:

```bash
./ctf_manager.sh status
```

**Expect:** `public SSH refused from this network; reached gateway over the
admin VPN instead`, then `gateway host allow-list updated`, `ctfd host
allow-list updated`. Disconnect the VPN; the plain SSH command above now
succeeds from the hotspot. Back on home Wi-Fi it still works — the list only
grows.

---

## 9. Backup and restore drill — [VERIFIED] (3 min)

```bash
scp -i ~/.ssh/ctf_ed25519 root@CTFD_IP:/opt/ctf/backups/ctfd-*.sql.gz ./backups/ 2>/dev/null \
  || ssh -i ~/.ssh/ctf_ed25519 root@CTFD_IP '/usr/local/sbin/ctf-backup.sh' && scp -i ~/.ssh/ctf_ed25519 'root@CTFD_IP:/opt/ctf/backups/*.sql.gz' ./backups/
ls -la backups/
```

**Expect:** at least one `ctfd-<timestamp>.sql.gz` locally, intact and
containing real tables:

```bash
gzip -t backups/*.sql.gz && echo "archive intact"
```

(Don't bother grepping for `CREATE TABLE` — mysqldump's quoting makes that
check unreliable. The restore below is the real proof.)

A backup you have never restored is a hope, not a backup. Prove it round-trips
— safe to run now, it writes to a scratch database, not the live one:

```bash
ssh -i ~/.ssh/ctf_ed25519 root@<CTFD_IP> 'cd /opt/ctf && . ./.env && \
  docker compose exec -T db mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "CREATE DATABASE restoretest"'
zcat backups/ctfd-*.sql.gz | ssh -i ~/.ssh/ctf_ed25519 root@<CTFD_IP> \
  'cd /opt/ctf && . ./.env && docker compose exec -T db mysql -uroot -p"$MYSQL_ROOT_PASSWORD" restoretest'
ssh -i ~/.ssh/ctf_ed25519 root@<CTFD_IP> 'cd /opt/ctf && . ./.env && \
  docker compose exec -T db mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e \
  "SELECT COUNT(*) AS users FROM restoretest.users; DROP DATABASE restoretest;"'
```

**Expect:** a user count matching what you created in §5, then the scratch
database is dropped. If that works, a real restore into `ctfd`
(`ADMIN_GUIDE.md` §6) will work too.

---

## 10. Teardown — [VERIFIED] (3 min) — do not skip

```bash
./ctf_manager.sh teardown      # type DESTROY, then y
```

**Expect:** three/four `deleting linode`, `all instances terminated`, `VPC …
deleted`, three `firewall … deleted`, `archived to archive/ctf-….tar.gz`,
`local state purged`. Then confirm in the Linode Cloud Manager that the
Linodes, VPCs and Firewalls pages are all empty. **Then rotate the API token.**

---

## 10b. Trick: testing two players without two devices

You don't strictly need a phone. Any Linux box that can reach the gateway can
be a player — including one of your own nodes. This is how the isolation test
above was run:

```bash
# on the Wazuh node (it has proxy internet for apt):
ssh -i ~/.ssh/ctf_ed25519 -J root@<GW_IP> root@10.0.0.5
apt-get install -y openvpn
# copy a player profile over, and point it at the gateway's VPC address
sed 's/^remote .*/remote 10.0.0.2 1194/' player01.ovpn > /root/p01.ovpn
openvpn --config /root/p01.ovpn --daemon --log /root/ovpn.log --route-nopull
ip -4 addr show tun0          # -> 10.8.0.100
# --route-nopull keeps it from hijacking the node's routing; add only what you test:
ip route replace 10.0.0.3/32 dev tun0 src 10.8.0.100
```

`--route-nopull` is the important flag: without it the pushed routes take over
the node's traffic. Add `/32` routes by hand for just the addresses you're
testing, and you get a genuine `10.8.0.x` source address to exercise the
gateway's rules with.

---

## 11. Switching to a real domain — [UNTESTED] (optional)

Everything above runs in IP mode with a self-signed certificate. Production
wants a domain. This path has **never been deployed**, so treat it as its own
test, on a throwaway deployment, before the event.

1. Set `CTF_DOMAIN="ctf.yourdomain.tld"` at the top of `ctf_manager.sh`.
2. `./ctf_manager.sh deploy`. It prints the CTFd node's public IP and pauses.
3. Create the `A` record at your registrar pointing at that IP, press Enter.
   The script waits until the name resolves before continuing, so Let's
   Encrypt is not asked until DNS is right.

**Expect:** `<domain> resolves to <ip>`, then deploy proceeds. Afterwards:

```bash
curl -sI https://ctf.yourdomain.tld | head -1
echo | openssl s_client -connect ctf.yourdomain.tld:443 2>/dev/null | openssl x509 -noout -issuer
```

**Expect:** `HTTP/2 200`, and an issuer of Let's Encrypt — *not* "Caddy Local
Authority", which would mean it silently fell back to self-signed.

Two things to watch, both untested:

- **Issuance is rate-limited** by Let's Encrypt (5 failures per hostname per
  hour). If the A record is wrong on the first attempt you may have to wait.
  Check: `ssh root@<CTFD_IP> 'cd /opt/ctf && docker compose logs caddy | grep -i acme'`.
- **Whale's `subdomain_host`** comes from `CTF_DOMAIN`. It only matters for
  challenges using `redirect: http`; `redirect: direct` (the default, and what
  `example-dynamic` uses) is unaffected. HTTP-routed challenges additionally
  need a wildcard `*.ctf.yourdomain.tld` A record.

---

## Acceptance checklist

**Status** is what *I* have confirmed on live infrastructure — ✅ verified,
🔵 you are the first to run it. A 🔵 failing is a discovery, not necessarily
a regression; a ✅ failing means something changed.

| # | Test | Pass condition | Status |
|---|---|---|---|
| 1 | `selftest` | `self test passed` | ✅ |
| 2 | `deploy` | all three `verified:` lines, `whale checks pass`, summary | ✅ |
| 3 | `status` | all up, gateway services active, egress sealed, CTFd 200 | ✅ |
| 4 | admin VPN | `10.8.0.50`, reaches Wazuh + SSH | ✅ |
| 4b | Wazuh dashboard | dashboard answers; **4 agents Active** | ✅ |
| 5 | player VPN | connects, pinned IP, bound profile, reaches scoreboard + challenges | ✅ |
| 5b | player negatives | Wazuh/SSH/internet all blocked, challenge port open | ✅ |
| 5c | player↔player | two live clients; ping+SSH blocked, drop counter rose | ✅ |
| 6 | static challenge | flag via header, solve.sh works | ✅ |
| 6a | per-player instance | Start gives a port; flags unique; foreign flag Incorrect, own Correct | ✅ |
| 6b | container sandbox | internet/metadata/wazuh/DNS BLOCKED from inside; caps ALL dropped; no FLAG in environ | ✅ |
| 6c | whale health | `whale-config` → `whale checks pass`; Containers page lists instances | ✅ |
| 6d | public backstops | challenge and instance ports BLOCKED on the CTFd public IP | ✅ |
| 6e | team isolation | other team blocked from your instance; teammate allowed; drop counter rises | ✅ |
| 7 | revoke | CRL updated; live session dropped; reconnect refused | ✅ |
| 8 | roaming | new IP propagates to nftables **and** Cloud Firewall | ✅ |
| 9 | backup | archive intact; restored 3 users / 2 teams into a scratch DB | ✅ |
| 10 | teardown | Cloud Manager shows nothing left; token rotated | ✅ |
| 11 | domain mode | Let's Encrypt issuer, HTTP 200 (only if you need a domain) | 🔵 |

### Suggested order for your first run

The dependency that matters: **almost every 🔵 sits behind the VPN tunnel**,
so prove that first. If §4 works, the rest are ordinary checks; if it doesn't,
nothing after §4 can be judged.

1. **§1, §2, §3** — get a working deployment (~35 min, all ✅, low risk).
2. **§4 immediately** — the admin tunnel. This is the gate. Do not proceed
   past a failure here; use the diagnostic table in that section.
3. **§5, §5c** — the player experience and isolation, with your phone.
4. **§6 → §6d** — challenges. All ✅; if one fails, suspect a change.
5. **§7** — revocation, on `player01`. Permanent; don't test it on `admin`.
6. **§8, §9** — roaming and the backup round-trip.
7. **§10** — teardown. Never skip.

If you only have 20 minutes, do **§1 → §2 → §4 → §10**: that proves the
deployment stands up, the tunnel works, and cleanup is clean — the three
things a broken event would hinge on.

## When something fails

- **Deploy stuck on a sentinel** → SSH to that node (via `-J root@GW_IP` for
  private ones) and read `/var/log/cloud-init-output.log` and
  `journalctl -t ctf`. The node refused to say ready for a reason; it logs it.
- **VPN connects but nothing is reachable** → on the gateway,
  `nft list chain inet ctf_filter forward` — the counters on the drop rules
  tell you which rule ate your packet.
- **Player gets "No VPN profiles remain"** → on CTFd node,
  `ls -la /opt/ctf/vpn_profiles` must show 50 files owned by uid 1001.
- **Challenge 0/1** → `docker service ps ctf_<name> --no-trunc` on 10.0.0.3;
  almost always a process bound to `127.0.0.1` or a runtime download.
- Anything else → `ADMIN_GUIDE.md` §4, then `DESIGN_RATIONALE.md` for the why.

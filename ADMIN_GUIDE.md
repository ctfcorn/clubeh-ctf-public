# Administrator guide — club.eh CTF infrastructure

For whoever is running the event. Assumes you have this directory, the
Linode token in `personal_access_token.txt`, and `~/.ssh/ctf_ed25519`.
`README.md` has the topology diagram; `DESIGN_RATIONALE.md` has the
engineering rationale. This document is about *operating* it.

---

## 1. How it fits together

Four Linodes in one private network (VPC `10.0.0.0/24`). Only two have a
public address.

| Node | Address | Public? | What it does |
|---|---|---|---|
| **Gateway** | 10.0.0.2 | yes | OpenVPN server (1194/udp). The only door into the network. Also the firewall that decides who may talk to what, the web proxy and DNS the private nodes use to install software during setup, and your SSH jump host. |
| **CTFd** | 10.0.0.3 | yes | The scoreboard (CTFd), its database, HTTPS (Caddy), a private Docker registry, and the Swarm manager that schedules challenges. Players see this on the public internet. |
| **Challenge host** | 10.0.0.4 | **no** | Runs every challenge container. Has **no internet access at all** after setup. Treated as hostile. |
| **Wazuh** | 10.0.0.5 | **no** | The SIEM. Collects logs from all three other nodes. Dashboard reachable only by you, over VPN. |

### The traffic rules, in plain terms

- **A player** connects to the VPN, gets a fixed address in `10.8.0.100–149`,
  and can reach exactly two things: challenge ports `30000–32767` on the
  challenge host, and the scoreboard. Nothing else. Not other players, not
  Wazuh, not SSH on anything, not the internet through the tunnel.
- **You** (`admin.ovpn`, always `10.8.0.50`) can reach every node on every
  port, including the Wazuh dashboard and SSH.
- **A challenge container** can talk to other challenge containers and to
  the players who connect to it. It cannot reach the internet, the other
  nodes, or the cloud metadata service. A player who gets a shell in a
  container cannot phone home, pull tools, or pivot.
- **The public internet** can reach the VPN port on the gateway and HTTPS on
  CTFd. SSH is only accepted from IP addresses you have used to run the
  script (see §5). Everything else is closed at two layers: Linode's Cloud
  Firewall outside the machine, and nftables inside it.

### Two things you should know about how players get their VPN

Each player gets their own `.ovpn`, permanently tied to their CTFd account.
They log into CTFd and click **VPN** in the menu; the plugin assigns the next
free profile and records who took it. That mapping — account → profile →
VPN IP — is what lets you find out *who* did something in the Wazuh logs,
and it is what makes revocation surgical. `admin.ovpn` is never served
through CTFd; it lives only in `profiles/` on your machine.

---

## 2. Before the event

```bash
./ctf_manager.sh selftest   # 5 seconds, no cost — validates everything offline
./ctf_manager.sh            # → [1] Deploy Infrastructure
```

Deploy takes 25–40 minutes, most of it Wazuh installing. It is staged: the
gateway comes up first, the other three only once it is confirmed working.
If it stops with a red `[x]`, nothing after that point was created; read the
message, fix, and either re-run or tear down.

When it finishes you get a summary with the CTFd URL, admin credentials
location, and profile paths. Then:

1. **Import `profiles/admin.ovpn`** into your VPN client and connect. Check
   you can open `https://10.0.0.5` (Wazuh; password in `ctf_secrets.env`).
2. **Log into CTFd** as `ctf-admin` (password in `ctf_secrets.env`). Change
   it. Set the event start/end times under Admin → Config.
3. **Deploy challenges** — §3.
4. **Do a full dry run as a player.** Register a throwaway account, download
   its VPN profile, connect, solve `example-web`. If that works end to end,
   the platform works.
5. **Pull a backup** (§6) so you know the procedure works before you need it.
6. **Set a registration code** — CTFd → Admin → Config → Accounts →
   *Registration Code*. Without it, anyone on the internet can register and
   claim a VPN profile; fifty strangers could drain the pool before your
   players arrive. Share the code only with real participants (or enable
   email verification instead).
7. **Lock the Linode account**: enable 2FA, set LISH to *keys only*
   (Profile → LISH), and make sure the API token is scoped to Linodes,
   VPCs, Firewalls and IPs only.
8. **Decide where backups live.** The hourly dumps sit on the CTFd node.
   Either set `ENABLE_LINODE_BACKUPS="true"` before deploying, or plan to
   `scp` the dumps down during the event (§6).

Costs ~$0.36/hour while up. Deploy the day before, not the week before.

---

## 2b. Teams mode and instance isolation

This range deploys CTFd in **teams mode** (`CTF_USER_MODE="teams"`), which
changes player onboarding: each player registers, then **creates or joins a
team** before they can play. Team size is capped by `CTF_TEAM_SIZE` (4).

**CTFd cannot change this after setup.** If you want individual scoring, set
`CTF_USER_MODE="users"` *before* deploying.

Teams mode is what per-team instance isolation keys on. With
`INSTANCE_ISOLATION="true"` (the default), a player may reach only the whale
instance ports **their own team owns** — other teams' instances are dropped at
the gateway. In users mode the same machinery gives per-player isolation
instead; nothing to configure either way.

Check it from `[2] Status`:

```
  Per-team instance ACL: active
    6 source/port pair(s) allowed right now
```

That count should be roughly (live instances x members of the owning team).
Zero while instances are running means the poller can't reach CTFd — look at
`journalctl -u ctf-instance-acl -n 30` on the gateway.

To turn it off (falls back to the old open port range), set
`INSTANCE_ISOLATION="false"` and redeploy the gateway.

## 3. Challenges

Authors follow `challenges/README.md`. You receive a directory per challenge.

```bash
cp -r ~/Downloads/their-challenge challenges/
./ctf_manager.sh            # → [5] Deploy / Update Challenges
```

The script validates every `challenge.yml` (it refuses duplicate ports, ports
outside the player-reachable range, missing flags, `COPY`ing a flag into the
image), builds the images on the CTFd node, and deploys them to the challenge
host with the sandbox settings hard-wired — no capabilities, read-only
filesystem, CPU/memory/process limits, flag mounted as a secret. It prints
the address for each challenge; paste that into the CTFd challenge
description. Re-run **[5]** any time; it updates changed challenges in place.

Static challenges are shared, always-on containers. Dynamic ones are
per-player and expire; their load is concurrent players × instance size. The host's load is the sum of
the limits declared in each `challenge.yml`; **[5]** prints that total
against the node (about 12 challenges at 256 MB on the default 4 GB host)
and warns if you are over. The default challenge host is 8 GB; for a large
per-player event set `TYPE_CHALLENGE="g6-standard-6"` (16 GB).

**[6] Remove All Challenges** stops the static stack. Players lose in-progress state.

### Per-player instances (ctfd-whale)

Challenges marked `type: dynamic` are registered in CTFd automatically by **[5]**.
Players open the challenge and press **Start**; whale creates a private
container for them on the challenge host and shows `10.0.0.3:<port>` plus a
countdown. Each instance has its own flag — a friend's flag is simply wrong.

Where to look:
- **Admin → Whale** (`/plugins/ctfd-whale/admin/settings`): health checks
  (Docker API via the socket proxy, frpc reachable) and every setting. The
  deploy script filled these in; you should not need to change them.
- **Admin → Whale → Containers** (`/plugins/ctfd-whale/admin/containers`):
  every running instance, who owns it, how long it has left, and a destroy
  button. This is where you kill a suspicious instance.

Knobs, all at the top of `ctf_manager.sh` (change them, then run
`./ctf_manager.sh whale-config` to push them live — no redeploy needed): `WHALE_INSTANCE_TIMEOUT` (default
3600 s), `WHALE_MAX_RENEW` (5), `WHALE_MAX_INSTANCES` (60 concurrent, the
global cap), `FRP_PORT_LO/HI` (10000–10100 — also the ceiling on concurrent
instances). **[5]** prints how many concurrent players fit on the host.

**[5]** ends with an automatic smoke test: it starts an instance as you,
checks the port answers from the gateway, checks the flag is scrubbed from
the container's environment, and destroys it. A green smoke test means
players will be able to press Start.

If Start fails for everyone — or, more tellingly, fails for *some* players
and works for others — run `./ctf_manager.sh whale-config`. It re-applies the
settings **and restarts CTFd**, which is the actual fix: whale builds its
Docker client once per worker process at startup, and a worker that started
before the configuration existed will answer Start with "Container creation
failed" forever. If it still fails, on the CTFd node:
`docker compose logs ctfd --tail 200 | grep -A20 Traceback`. If it fails for one player: their previous instance is
probably still winding down; **Destroy** it from the Containers page.

Something not starting?
```bash
ssh -i ~/.ssh/ctf_ed25519 -J root@<gateway-ip> root@10.0.0.3 'docker service ps ctf_<name> --no-trunc'
ssh -i ~/.ssh/ctf_ed25519 -J root@<gateway-ip> root@10.0.0.3 'docker service logs ctf_<name> --tail 50'
```
Nine times out of ten it is the author's process listening on `127.0.0.1`
instead of `0.0.0.0`, or a runtime `pip install`/`apt-get` that cannot
succeed with no network.

---

## 4. During the event

### Watching it
- **[2] Status** — instance states, VPC reachability, OpenVPN clients
  currently connected, drop counters on the isolation rules, a live check
  that the challenge host still has no internet, Swarm node health.
- **Wazuh** at `https://10.0.0.5` over VPN. Useful searches:
  - `ctf-vpn` — every VPN connect/disconnect with CN and assigned IP
  - `ctfd-vpn` — every profile assignment and download, with CTFd username
  - `rule.groups: authentication_failed` — SSH brute-force attempts
  - `ctf-fw` — firewall reload events

### Someone is sharing flags / a profile / attacking other players
1. Find who. Wazuh `ctf-vpn` logs give you the CN behind a VPN IP; CTFd
   **Admin → /admin/vpn** gives you the account behind a profile name.
2. `./ctf_manager.sh` → **[4] Revoke Player** → enter e.g. `player17`.
   Their certificate is added to the revocation list, the list is pushed to
   the gateway, and their live session is killed. Takes effect immediately.
   It is permanent for this event.
3. Ban the CTFd account in Admin → Users.

### Something is on fire
- **CTFd down**: `ssh root@<ctfd-ip> 'cd /opt/ctf && docker compose ps && docker compose logs --tail 100 ctfd'`.
  `docker compose restart ctfd` fixes most things. The database persists on disk.
- **VPN down**: `ssh root@<gateway-ip> 'systemctl status openvpn-server@server; tail -50 /var/log/openvpn/openvpn.log'`.
- **Challenge host unresponsive**: it has no public IP; go via the gateway
  (`-J root@<gateway-ip> root@10.0.0.4`). `docker ps`, `free -m`, `dmesg | tail`.
  A challenge exceeding its memory limit is restarted automatically.
- **Locked out of SSH entirely**: the Linode LISH console —
  `ssh <your-linode-username>@lish-us-iad.linode.com`, then pick the node.
  Root passwords are in `ctf_secrets.env`.

Do not "quickly" edit nftables rules by hand on a node. If you must change
policy, edit the template, tear down, redeploy. A hand edit on the gateway
is lost on reboot anyway (the ruleset is regenerated at boot).

---

## 5. Working from a different network

The gateway and CTFd node only accept SSH from IP addresses the script has
seen you use. From a new café / campus / hotel:

1. Connect `admin.ovpn` first.
2. Run **[2] Status**. It detects the new IP, updates the Cloud Firewall,
   reaches the gateway over the VPN, pushes the new address into every
   host's allow-list, and remembers it. Public SSH now works from here too.

The list only grows; it is stored in `ctf_state.json` (`known_admin_ips`).

---

## 6. Backups

The CTFd node dumps the scoreboard database **hourly** to
`/opt/ctf/backups/ctfd-<timestamp>.sql.gz` (7 days kept). Pull one:

```bash
scp -i ~/.ssh/ctf_ed25519 'root@<ctfd-ip>:/opt/ctf/backups/*.sql.gz' ./backups/
```

Do this before teardown. **Teardown destroys the database.** Restoring:
```bash
zcat ctfd-<ts>.sql.gz | ssh root@<ctfd-ip> 'cd /opt/ctf && . ./.env && docker compose exec -T db mysql -uroot -p"$MYSQL_ROOT_PASSWORD" ctfd'
```

---

## 7. After the event

```bash
./ctf_manager.sh            # → [3] Teardown Infrastructure   (type DESTROY)
```

Deletes the Linodes, waits for them to actually terminate (the VPC cannot be
removed while an interface still references it), deletes the VPC and the
firewalls, and archives `pki/`, `profiles/`, state and secrets into
`archive/ctf-<timestamp>.tar.gz`. It then offers to purge the live copies.

Then, not optional: **rotate the Linode API token** in Cloud Manager and
replace `personal_access_token.txt`. The old token has been on disk in
cleartext for the whole event.

---

## 8. Switching to a real domain

Right now CTFd serves a self-signed certificate on the node's IP; players
will click through a warning. For the real event:

1. Put your hostname in `CTF_DOMAIN=` at the top of `ctf_manager.sh`.
2. Deploy. When the CTFd node exists the script prints its IP and pauses:
   create the A record at your registrar, press Enter. It waits until the
   name resolves before Caddy asks Let's Encrypt for a certificate.

Let's Encrypt is free and needs no account — Caddy handles all of it. The
email in `ACME_EMAIL` only receives expiry warnings.

---

## 9. Cheat sheet

| Task | Command |
|---|---|
| Validate everything, no cost | `./ctf_manager.sh selftest` |
| Deploy | `./ctf_manager.sh deploy` |
| Health + connected players | `./ctf_manager.sh status` |
| Ship challenges | `./ctf_manager.sh challenges` |
| Remove all challenges | `./ctf_manager.sh challenges-rm` |
| Re-apply whale settings | `./ctf_manager.sh whale-config` |
| Continue an interrupted deploy | `./ctf_manager.sh resume` |
| Kick a cheater | `./ctf_manager.sh revoke` |
| Tear down | `./ctf_manager.sh teardown` |
| SSH to gateway | `ssh -i ~/.ssh/ctf_ed25519 root@<gateway-ip>` |
| SSH to private node | `ssh -i ~/.ssh/ctf_ed25519 -J root@<gateway-ip> root@10.0.0.4` |
| Wazuh dashboard | `https://10.0.0.5` (over admin VPN) |
| Running instances | CTFd → Admin → Whale → Containers |
| All credentials | `ctf_secrets.env` (never commit, never paste in chat) |

# Design rationale — why the club.eh CTF range is built this way

This is the "why" document. `README.md` says what exists, `ADMIN_GUIDE.md`
says how to run it, `TESTING_GUIDE.md` says how to prove it. This one
explains the reasoning behind each decision, how the parts interact, and
answers the questions people ask when they first see the architecture.

---

## 1. What we are defending against

A CTF is an unusual thing to host: you invite people to attack your
infrastructure and you give them shells on it. The threats, in the order
they matter:

1. **A player breaks out of a challenge and reaches something real** — the
   scoreboard database, the SIEM, another player, your cloud account.
2. **A player uses a challenge container as a launchpad** — reverse shells to
   the internet, crypto-mining, scanning other people's networks from your IP.
3. **Players attack each other** through the VPN instead of solving puzzles.
4. **Cheating** — shared flags, shared VPN profiles, one person running many
   accounts — with no way to tell who did it.
5. **Ordinary internet attackers** who find the public services and try the
   usual things.
6. **Losing the event** — the scoreboard dies mid-competition, or you lock
   yourself out.

Every structural choice below traces back to one of these six.

---

## 2. The four machines, and why there are four

| Node | Why it is a separate machine |
|---|---|
| **Gateway** | One place where every player packet enters and one place where policy is decided. If the firewall logic were spread across nodes, a mistake on any one of them would be a hole. Here there is one forward chain to get right. |
| **CTFd** | The only thing the public internet needs to see. It is also the Swarm manager; challenges are kept off it by placement constraints (whale schedules only onto the node labelled `linux-1`, static stacks only onto workers), and its firewall drops every challenge/instance port range for non-VPC sources. |
| **Challenge host** | Runs hostile code by design. It has no public interface and no route to the internet at all, so a container escape lands on a machine that can reach nothing interesting. Threats 1 and 2 are contained by geography. |
| **Wazuh** | Sees every log from every node. Putting the SIEM on a box that players could reach would let a successful attacker erase their own footprints. It is VPC-only and only the admin VPN address can open it. |

They share one **VPC** (`10.0.0.0/24`), a private network that only these
four machines are on. Traffic between them never touches the internet.

---

## 3. How a packet moves

### A player
1. Connects to the gateway on UDP 1194. The first packet must carry a
   `tls-crypt` authentication tag; without it OpenVPN drops the packet and
   says nothing. A port scanner sees a closed port.
2. Presents a client certificate. It must be signed by our CA, not on the
   revocation list, *and* have a `ccd` entry mapping its name to a fixed
   address — otherwise `ccd-exclusive` refuses it. The player is now, say,
   `10.8.0.117`, and always will be.
3. Their client receives two routes only: the scoreboard and the challenge
   host. Their normal internet traffic keeps using their own connection —
   we are not their ISP and do not want to be (bandwidth, liability, and it
   would let them attack the internet from our address).
4. A packet to `10.0.0.4:31337` enters the gateway's `forward` chain, whose
   default policy is DROP. It matches the rule "player range → challenge
   host, ports 30000–32767" and is allowed. The source is translated to the
   gateway's VPC address because Linode's VPC fabric has no route back to
   `10.8.0.0/24`.
5. The challenge host receives it on a host port that Docker forwards into
   a container. The reply follows the connection-tracking state back.

A packet from that same player to `10.0.0.5` (Wazuh), to `10.8.0.118`
(another player), to port 22 anywhere, or out to the internet through the
tunnel hits an explicit drop rule and a counter increments. `[2] Status`
shows those counters.

### The admin
Same door, same handshake, but the certificate named `admin` maps to
`10.8.0.50`, and the forward chain has one rule for that address: anything
in the VPC. The Wazuh node itself only accepts connections that arrive from
the gateway's address — which, after translation, is what admin traffic
looks like. Players never arrive there at all; they are dropped one hop
earlier.

### A challenge container
Lives on an overlay network (`172.30.0.0/16`) on the challenge host. Its
packets to another container are allowed. Its packets to *anything else* —
the internet, the metadata service, any VPC node, the gateway's proxy — hit
the `ZERO_OUTBOUND` rule and die. The host itself has no default route, so
even if that rule vanished there is nowhere for the packet to go. That is
two independent reasons a reverse shell cannot happen.

### Bootstrap (the first 30 minutes of a node's life)
The challenge host and Wazuh node have no internet, but they need to
install Docker and Wazuh. They do it through an HTTP proxy and a DNS
forwarder running on the gateway. When installation finishes, the deploy
script deletes the challenge host's proxy configuration *and* tells the
gateway to stop accepting proxy connections from it. Wazuh keeps its access
so it can fetch updates.

---

## 3b. How the network is created, step by step

`ctf_manager.sh deploy` is one linear script, but the *order* of its steps is
itself a security decision. Nothing is created until the thing it depends on
has proven it works. This is the sequence, what happens at each step, and why
it is in that position.

### Phase A — on your Mac, before Linode is touched (≈ 5 s)

| # | Step | What it produces | Why here |
|---|---|---|---|
| A1 | **Preflight** | Confirms `linode-cli`, `jq`, `openssl`, `perl`, the SSH key and all four templates exist; probes the API with the token; checks the region actually advertises *VPCs*, *Metadata* and *Cloud Firewall*. | Fail in five seconds on your laptop, not five minutes into a billable run. The region check exists because `us-east` has no VPC and the API only says so when you ask. |
| A2 | **Detect your public IPs** | Your IPv4 (`/32`) and IPv6 prefix (`/64`). | These become the SSH allow-lists in both firewall layers. Every later run re-detects them. |
| A3 | **Generate secrets → disk** | DB passwords, CTFd secret key, CTFd admin password, Wazuh enrolment password, root passwords; written to `ctf_secrets.env` (0600) *immediately*. | If the deploy is interrupted at any later point, nothing is lost and `resume` can pick up. |
| A4 | **Build the PKI** | An EC P‑384 CA, a server certificate, `admin` + 50 player certificates (`clientAuth` EKU), a 2048‑bit `tls-crypt` key, an empty CRL. All with plain `openssl`; the CA private key never leaves this directory. | Certificates must exist before the gateway boots (its cloud‑init carries the server cert, CA cert, CRL and `tls-crypt` key) and before profiles can be assembled. |

### Phase B — the container the network lives in (≈ 10 s)

| # | Step | What it produces | Why here |
|---|---|---|---|
| B1 | **Three Cloud Firewalls** (REST API) | `ctf-gw`: inbound DROP except 1194/udp from anywhere, 22 from your IPs, everything from `10.0.0.0/24`. `ctf-web`: 22 from your IPs, 80/443 from anywhere, VPC. `ctf-int`: VPC only, nothing from the internet. State file saved. | Firewalls must exist *before* the Linodes so they can be attached at the instant of creation. A Linode created first and firewalled later has an unprotected window of several minutes while cloud‑init runs. |
| B2 | **The VPC and its subnet** (REST API) | `ctf-vpc` in `us-iad` with one subnet, `10.0.0.0/24`. State saved. | Every interface below references this subnet id. Linode's VPC is a private layer‑3 network: members reach each other on‑link, the fabric router is `10.0.0.1`, and — measured, not assumed — the fabric will not forward a packet *through* a member to somewhere else. |

### Phase C — the gateway, alone (≈ 6 min)

| # | Step | What it produces | Why here |
|---|---|---|---|
| C1 | **Render node 1's cloud‑init** | The template's `__PLACEHOLDERS__` are replaced (addresses, port ranges, your IPs as nftables sets, the base64 PEM blobs). The result is checked for leftovers and gzip'd; it must be under 16 384 bytes decoded. | Linode rejects larger user‑data. Gzip is transparent to cloud‑init. |
| C2 | **Create the gateway Linode** | One interface: VPC, fixed address `10.0.0.2`, `nat_1_1 = any` (Linode maps a public IPv4 onto it). Firewall `ctf-gw` attached. Your SSH key installed by Linode. Tag `ctf-event`. Public IP recorded in state. | The private nodes cannot install anything without this host's proxy and DNS, so it goes first and alone. `nat_1_1` is what gives a single‑interface Linode public reachability; nodes 3 and 4 will simply omit it. |
| C3 | **Cloud‑init on the gateway** (autonomous, on the node) | In order: files written (certs, `server.conf`, tinyproxy/dnsmasq/chrony configs, the firewall generator, systemd units, your allow‑list files); packages installed and upgraded; then `runcmd`: `ip_forward` on → `ccd` map generated (51 files: `admin` → `.50`, `playerNN` → `.100+N‑1`) → `ctf-firewall.sh` detects the WAN interface and writes/applies the full nftables ruleset (`forward` policy DROP) → OpenVPN starts → Wazuh agent installs → proxy and DNS start → user‑data scrubbed from disk → **sentinel**. | The sentinel `/run/ctf-nat-ready` is written only if the nftables table exists **and** OpenVPN, tinyproxy and dnsmasq are all active **and** forwarding is on. Any failure and the file never appears. |
| C4 | **Wait for the sentinel** | The script polls over SSH every 20 s, up to 30 min. | This is the gate. Nothing else is created behind an unfirewalled gateway. |
| C5 | **Assemble the 51 `.ovpn` profiles** | Each embeds the CA cert, that client's cert and key, the `tls-crypt` key, and `remote <gateway public IP> 1194`. | The gateway's address is only known now. Profiles are far too large for cloud‑init; they travel by SSH in Phase E. |

### Phase D — the other three, in parallel (≈ 12–15 min, Wazuh is the long pole)

| # | Step | What it produces | Why here |
|---|---|---|---|
| D1 | **Render node 2/3/4 cloud‑init** | Node 2 gets the Caddyfile and `.env` (base64). Nodes 3 and 4 get `apt: proxy: http://10.0.0.2:3128` at the top level so even cloud‑init's own package phase uses the gateway. | Templates can only be rendered once the gateway exists (they reference it) and must be rendered before the nodes are created. |
| D2 | **Create CTFd** | VPC `10.0.0.3` + `nat_1_1` (public), firewall `ctf-web`. | It needs its own internet for images and Let's Encrypt, and it is the one public service. |
| D3 | **Create the challenge host and Wazuh** | VPC `10.0.0.4` and `10.0.0.5`, **no** `nat_1_1`, firewall `ctf-int`. Linode still allocates them a public IPv4 in the account, but it is not configured on the interface and nothing routes to it. | No public interface = no inbound path at all, and no default route = no outbound path. Their only way to fetch packages is the proxy on `.2`. |
| D4 | **Cloud‑init on node 2** | Docker; `ctf_guard` table loaded *before* Docker starts (policy accept, denials only, so Docker's own chains keep working); `docker swarm init` bound to `10.0.0.3`; overlay `ctf_challenges 172.30.0.0/16` created; registry bound to `10.0.0.3:5000`; ctfd-whale cloned at a pinned commit and baked into a derived CTFd image (with a build-time assertion that Flask stayed at 2.1); a placeholder VPN plugin so CTFd starts; public IP resolved into the Caddyfile; `docker compose up` brings up CTFd, Caddy, MariaDB, Redis, the Docker socket proxy, `frps` (instance ports published on the VPC address only) and `frpc`; the sentinel waits until all five core services are *running*. | The overlay is swarm‑scoped, so it is created on the manager and materialises on the worker when a service lands there. The manager is **not** drained: `frpc` must attach to that overlay from this node, which needs a schedulable manager; placement constraints keep challenges off it. |
| D5 | **Cloud‑init on node 3** | DNS pointed at `10.0.0.2`; Docker installed *through the proxy*; `ctf_guard` loaded before Docker (metadata drop, `ZERO_OUTBOUND`, container→host‑service drop); Wazuh agent; sentinel. It does **not** join the swarm yet. | Docker will not accept a pre‑shared join token — the manager mints them — so the join is orchestrated in Phase E over SSH instead of racing here. |
| D6 | **Cloud‑init on node 4** | Wazuh's own installer runs through the proxy (`-a` all‑in‑one); indexer heap set to 8 GB; generated credentials stashed for collection; enrolment password enabled (edits scoped to the `<auth>` block); the two log files that contain the admin password locked to 0600; sentinel gated on firewall + `wazuh-manager` active. | The agents on nodes 1–3 have been retrying enrolment every 30 s since they booted; they succeed the moment this node is up. |
| D7 | **Wait for all three sentinels** | CTFd over its public IP; nodes 3 and 4 through the gateway as an SSH jump host (an explicit `ProxyCommand`, because `-J` does not carry the key and known‑hosts options to the inner hop). | Same rule as C4: proceed only past nodes that proved their firewall loaded. |

### Phase E — post‑provision: the things that could only happen once everything exists (≈ 2 min)

| # | Step | Why in this order |
|---|---|---|
| E1 | **Swarm join + label** — read the *worker* token from the CTFd node over SSH; run `docker swarm join` on node 3 through the jump; label it `name=linux-1`, which is how whale chooses where instances run. | Needs both nodes up. The token never touches user‑data or node 3's disk. |
| E2 | **Deliver plugin + 50 player profiles** by SCP to `/opt/ctf/…` on CTFd; ownership set to uid 1001 (the CTFd process); `docker compose restart ctfd`. | 204 KB cannot ride in cloud‑init. `admin.ovpn` stays on your Mac. |
| E3 | **Wazuh: collect the admin password, then seal enrolment** — the enrolment service is disabled on the manager and the shared password shredded everywhere. | All four agents are registered by now; the secret has no further use. |
| E4 | **Revoke node 3's egress** — its proxy configuration is deleted; on the gateway a flag file is dropped and the ruleset regenerated without the challenge‑host proxy/DNS lines. | Node 3 is fully bootstrapped and joined; from here it needs only the VPC. The flag file makes this survive gateway reboots. |
| E5 | **Verify** — from node 3: direct `curl https://1.1.1.1` must fail, `curl` *via* the proxy must fail, `curl` to the metadata address must fail. | A control that has not been exercised is a hope. Deploy warns loudly on any pass. |
| E6 | **Rotate both Swarm tokens.** | The values that existed during bootstrap are now dead. |
| E7 | **CTFd first‑run setup, then whale configuration** — the wizard is posted with the event name and admin credentials; then whale's settings (Docker via the socket proxy, the overlay, the frp admin API, the instance port range, timeouts, the flag template) are pushed through CTFd's config API and whale's own health checks are read back. | Only possible once the plugin restart in E2 has settled. `whale-config` re-runs this step alone at any later time. |
| E8 | **Write state + secrets, print the summary.** | Public URLs, profile paths, where the credentials are. |

### The network that results

```
internet ── Cloud Firewall ──► gateway 10.0.0.2  (+public via 1:1 NAT)
                                 ├─ tun0  10.8.0.0/24   VPN pool: admin .50, players .100–.149
                                 ├─ tinyproxy :3128, dnsmasq :53, chrony :123   → VPC only
                                 └─ nftables forward DROP  ← every player/admin decision
internet ── Cloud Firewall ──► CTFd    10.0.0.3  (+public via 1:1 NAT)
                                 ├─ docker bridge ctf_web   (Caddy, CTFd, MariaDB, Redis)
                                 ├─ registry 10.0.0.3:5000  (VPC only)
                                 ├─ swarm manager (not drained; constraints keep challenges off it)
                                 ├─ ctfd-whale via docker socket proxy · frps :10000–10100 on the VPC IP · frpc on the overlay
                                 └─ overlay ctf_challenges 172.30.0.0/16 (defined here)
            (no public path)   challenge 10.0.0.4   no default route · label name=linux-1
                                 ├─ swarm worker · overlay ctf_challenges materialises here · whale instances land here
                                 ├─ docker_gwbridge 172.18.0.0/16 (host‑mode publish path)
                                 └─ ctf_guard: containers ↔ containers only; ZERO_OUTBOUND
            (no public path)   wazuh     10.0.0.5   egress only via gateway proxy
```

Five address spaces, and only the gateway can see more than one of them:
the VPC (`10.0.0.0/24`), the VPN pool (`10.8.0.0/24`, terminated on the
gateway and translated to `.2` before it enters the VPC), the challenge
overlay (`172.30.0.0/16`, exists only inside Docker on node 3), Docker's
own bridges on nodes 2 and 3, and the public internet, which touches exactly
two of the four machines.

### Why this order and not another

- **Firewalls before Linodes**: attach‑at‑create is the only way to avoid an
  unprotected first boot.
- **Gateway before everything**: the private nodes cannot install a single
  package without its proxy.
- **Profiles after the gateway**: they must name its public address.
- **Plugin and profiles after CTFd exists, by SSH**: user‑data is capped at
  16 KB and secrets in user‑data outlive their usefulness.
- **Swarm join after both nodes**: Docker mints tokens on the manager; there
  is nothing to pre‑share.
- **Seal Wazuh after all agents are up**: sealing earlier would strand an
  agent that had not enrolled yet.
- **Revoke node 3 last**: everything it will ever download must already be
  on it.
- **Verify after revoke, not before**: the test must exercise the final
  state, not an intermediate one.

If the process dies after Phase C, `resume` re‑enters at D7 using the saved
state and secrets. If it dies before that, `teardown` finds whatever was
created by tag and label and removes it.

---

## 4. The decisions, one by one

### Why a VPN at all, rather than exposing challenges on public ports?
Because attribution and revocation require identity. On a public port a
challenge sees thousands of anonymous IPs; behind the VPN every packet comes
from an address that is bound to one certificate that is bound to one CTFd
account. When someone cheats, you know who, and you can cut exactly them.
It also shrinks the internet-facing surface from "fifty challenge ports" to
"one UDP port that ignores strangers".

### Why OpenVPN and not WireGuard?
WireGuard is simpler and faster. OpenVPN was chosen because it works
through hostile campus/hotel networks that block UDP (it can fall back to
TCP/443), has a mature revocation model (CRL), and has `tls-crypt`, which
makes the port invisible to scanners. For a player-facing service where
"my client can't connect" is a support ticket, OpenVPN's reach won.

### Why is the gateway the *only* firewall that matters for players?
Because a policy in one place can be read, tested, and reasoned about. The
gateway's forward chain is about forty lines; every allow and every deny is
in it, in order, with counters. The other nodes have their own rules, but
they are backstops, not the policy.

### Why Linode Cloud Firewall *and* nftables on every host?
They fail differently. Cloud Firewall is enforced by Linode outside the
machine: it is attached at the moment of creation (so there is no
unprotected window while cloud-init runs) and survives anything an attacker
does to the host. nftables on the host is expressive enough for the
player/admin/container distinctions Cloud Firewall cannot make. Two layers
that fail independently are worth more than one thick one.

### Why does the challenge host have no default route instead of "a firewall that blocks the internet"?
A firewall rule is one line an operator could delete at 2 a.m. while
debugging. A missing route is structural: there is no path. We keep the
firewall rule too, so the guarantee holds even if someone adds a route.

### Why a proxy on the gateway rather than a NAT gateway?
We tried NAT first. Linode's VPC routes at layer 3 and will not deliver a
packet to another member Linode acting as a next hop — we measured this
(packets to the gateway itself arrived; packets *through* it never reached
its forward chain). A proxy's destination *is* the gateway, so it works, and
it has a nice property: it only speaks HTTP, so the private nodes can fetch
packages but cannot open arbitrary connections.

### Why "mode=host" publishing, and why isn't the manager drained?
Docker Swarm's default (ingress) publishing makes a service reachable on
*every* node in the swarm, including the CTFd node's public IP. That would
put challenge ports on the internet, bypassing the VPN entirely. `mode=host`
binds only on the node the container runs on; placement constraints keep
every challenge on the challenge host; and the CTFd node's firewall drops
the challenge and instance port ranges for any source outside the VPC.
An earlier design also *drained* the manager, but whale's `frpc` has to
attach to the overlay from that node, which needs a schedulable manager —
so the drain was removed and the other two guards carry the load. (The
firewall backstop is keyed on source address, not interface: on a 1:1-NAT
Linode the VPC and the public traffic arrive on the same `eth0`.)

### Why both shared and per-player challenges?
Shared, always-on containers are cheap and robust and suit stateless
services. But they cannot host a challenge whose state one player can spoil
for another, and a shared flag is the easiest thing in a CTF to copy.
Per-player instances (ctfd-whale) give every player a private container with
a **unique flag**: a copied flag is wrong for anyone but its owner, which
removes the incentive to share at all. Whale was chosen over a bespoke
spawner for parity with other CTFs and its player-facing UI (Start / Renew /
Destroy, countdown, admin container list).

### How frp actually works here, in four steps

frp is a reverse tunnel in two halves. `frps` (server) and `frpc` (client) both
run on the CTFd node; the challenge instance runs on the challenge host with
**no published ports at all** and a `dnsrr` endpoint, so nothing on that host
is listening for a player.

1. **At startup**, `frpc` dials *out* to `frps` on port 7000 over an internal
   Docker network, authenticating with a shared token. That one connection
   stays open and is the only channel between them.
2. **When a player presses Start**, whale creates the Swarm service, allocates
   a port from 10000–10100, and rewrites `frpc`'s *entire* configuration over
   its admin HTTP API (`PUT /api/config`, then `GET /api/reload`), adding a
   stanza like `local_ip = 7-3f9a…, local_port = 9000, remote_port = 10043`.
3. **`frpc` then dials *into* the container** by its Swarm service name,
   resolved through Docker's overlay DNS — which is precisely why `frpc` is
   attached to the `ctf_challenges` overlay.
4. **`frps` begins listening on 10043** (on the VPC address only) and relays
   anything that arrives down the existing tunnel to `frpc`, which passes it
   to the container.

The direction in steps 1 and 3 is the whole security argument: **the container
is dialled into, never out of.** It initiates nothing, so the challenge host's
`ZERO_OUTBOUND` rule is untouched and the zero-outbound guarantee survives.

### Per-team instance isolation

frps publishes instance ports in one range on the CTFd node, and ports are
sequential — so without help, any player could scan the range and reach any
other player's instance. Flags stay unforgeable (they're per-instance), but
interference is possible. That gap is now closed at the gateway.

**How it works.** Three systems each hold one third of the answer, and they
share a database:

- whale knows **user → instance port** (`whale_container`)
- the `vpn_handout` plugin knows **user → VPN address** (it already recorded
  this for attribution — that table turned out to be the enabler)
- CTFd knows **user → team**

The plugin joins all three and exposes the result at
`/vpn/isolation-map`, guarded by a shared token (constant-time compared; the
endpoint sits on the public port). A poller on the gateway fetches it every
few seconds and rewrites an nftables set:

```
set player_instance { type ipv4_addr . inet_service ; flags timeout ; }

ip daddr $CTFD ip saddr . tcp dport @player_instance accept
ip saddr $VPN_PLAYERS ip daddr $CTFD tcp dport $FRP_PORTS counter drop
```

A team's members may reach their own team's instance ports and nothing else
in the range; every other attempt hits the counted drop.

**Why a reconciling poller rather than event hooks.** Hooks would have to live
inside whale, which is pinned to a community commit and is the most
upgrade-fragile component here. A poller that rewrites the whole set each pass
cannot "miss an event", and its failure direction is right: if CTFd is briefly
unreachable the poller leaves the set untouched, so players keep the access
they have and nothing *new* opens. It never flushes on error.

**It serves both CTFd modes with one code path.** In teams mode the set is
expanded to every teammate's address; in users mode `team_id` is null, so the
set contains only the owner — i.e. per-player isolation. A player who hasn't
joined a team yet gets only their own instance. (All three cases unit-tested.)

**Consequence you must accept:** team membership only exists if CTFd runs in
**teams mode**, and CTFd fixes that at first-run setup — it cannot be changed
later. `CTF_USER_MODE` is therefore a deploy-time decision.

### What frp costs

It is a hole-punching proxy — its purpose is to reach something the network was
arranged not to reach — so it necessarily returns some isolation:

- **`frpc` bridges two zones.** It sits on the challenge overlay *and* the CTFd
  internal network. Separation between them is now enforced by an application
  proxy rather than the kernel; a compromised `frpc` could reach any container
  on the overlay on any port. It runs no player code and parses only frp's own
  protocol, but it is the most security-relevant process in the deployment.
- **Its configuration is rewritable over HTTP.** Anything reaching `frpc:7400`
  with the credential can rewrite every proxy rule, including ones pointing at
  internal addresses. Whale's own documentation warns against exposing this.
  Here it is bound to an internal network with no host port, behind basic auth
  with a generated password — reachable from neither the VPN nor the internet.
- **Hostile traffic now lands on the public node.** Before whale, every packet
  a player aimed at a challenge terminated on the isolated challenge host. Now
  instance traffic terminates on the node that also runs the scoreboard, its
  database and the Swarm manager. `frps` only relays, but an `frps` bug has a
  larger blast radius than one on the challenge host would.
- **Pinned to frp 0.42.0 (2022).** Whale speaks the INI-era admin API; frp
  ≥ 0.52 moved to TOML and is incompatible. This is a four-year-old network
  daemon that will get no security fixes. It is reachable only inside the VPC,
  and it is the strongest argument for tearing the range down between events.
- **Players can reach each other's instances** — see the residual-risk table.

### How whale is fitted without breaking the isolation rules
Whale's stock deployment mounts the Docker socket into CTFd and publishes
instance ports on the CTFd host's public interface. Here:
- CTFd talks to Docker through a **socket proxy** that exposes only the Swarm
  endpoints whale uses (services, networks, tasks, nodes, info, containers).
  No exec, images, volumes or host calls. A CTFd compromise cannot run
  arbitrary containers with host mounts.
- `frps` publishes the instance port range **on the VPC address only**; the
  node's firewall additionally drops that range on the public interface.
  Players reach instances only through the VPN, like everything else.
- Instances are created with no published ports and `dnsrr` endpoints; `frpc`
  reaches them **by dialling in** over the overlay. The container never
  initiates a connection, so `ZERO_OUTBOUND` is untouched.
- Instance networks for grouped challenges are carved from `172.31.0.0/16`,
  inside the range the challenge host's guard already treats as "container".
- Whale's 2019 dependency pins clash with CTFd 3.8; a derived image installs
  modern equivalents (`docker` 7.x, `Flask-APScheduler` 1.13) at build time,
  which is when CTFd installs plugin requirements — with `--no-deps` on the
  Flask extensions and a build-time assertion that Flask is still 2.1, because
  the first attempt silently pulled Flask 3 and broke CTFd.
- frp is `frankli0324/frp` 0.42, configured by command-line flags (that image
  ignores config files); `frps` sits on a non-internal network so its ports
  can publish, bound to the VPC address only.

The one property whale weakens is flag delivery: it injects the flag as an
environment variable. The author guide makes scrubbing it from the
environment mandatory, and the acceptance test checks `/proc/1/environ`.

### Why one VPN profile per CTFd account, served by a plugin?
CTFd has no per-user file delivery; a shared download lets one person take
all fifty profiles, which destroys attribution and lets them appear as
fifty players. The plugin binds the next free profile to the account on
first click, records the mapping, and logs every download for Wazuh. It is
about a hundred lines and it is what makes "who was `10.8.0.117`?" a
two-second question.

### Why are the profiles copied over SSH instead of baked into cloud-init?
Linode caps instance user-data at 16 KB (decoded). Fifty-one profiles are
about 200 KB. Also, secrets that ride in user-data sit in the metadata
service for the life of the instance; the fewer of them, the better.

### Why does the CA private key never leave your Mac?
Whoever holds the CA key can mint a certificate that the gateway trusts.
Nothing on any server needs it — servers verify, they do not sign. Signing
happens locally; the servers receive only certificates, the CRL and the
`tls-crypt` key. A full compromise of every node still cannot forge a
client.

### Why gzip the cloud-init payload?
See the 16 KB limit above. PEM certificates barely compress, but the YAML
and shell around them do; the gateway's payload fits with room to spare.

### Why do nodes refuse to say "ready" unless their firewall loaded?
cloud-init does not stop when a command fails. Without the gate, a node
whose firewall script had a typo would come up unprotected and the deploy
would proceed as if everything were fine. The sentinel file is written only
if the rules table exists and the key service is active; the deploy script
waits for it and gives up loudly if it never appears. "Fail closed" means
the safe state is also the default state.

### Why is the Wazuh enrolment password thrown away after deploy?
Agents need a shared secret to register. Once the four agents are
registered, that secret has no legitimate use, and a compromised node that
still held it could register rogue agents or read others' keys. The script
shreds it on every node and disables the enrolment service on the manager.

### Why are Swarm join tokens rotated?
The worker token was used once, over SSH, and never written to a node's
disk. Rotating both tokens afterwards means the values that existed during
bootstrap cannot be replayed by anything that observed them.

### Why is metadata blocked in `forward` but not on the host itself?
Linode's cloud-init re-reads the metadata service on every boot to
configure the network. Blocking it host-wide bricks the node on its first
reboot. The threat — a container or a VPN client reading metadata — only
ever passes through the `forward` chain, so that is where it is blocked.
The host's root process can still reach it, and root on the host can
already read the same data from disk anyway.

### Why `us-iad` and not Newark?
Newark (`us-east`) has no VPC capability. The API says so; we checked.

### Why keep `unattended-upgrades` on during an event?
Because the gateway and CTFd node face the internet and security patches
matter. It is limited to the security repository, will never reboot on its
own, and Docker packages are pinned so an upgrade cannot restart every
challenge. Patch OpenVPN/kernel by hand between rounds if you want zero
risk of a reconnect.

---

## 5. What we deliberately did not do

- **No user-namespace remapping or daemon-wide `no-new-privileges`.** They
  break setuid binaries, which privilege-escalation challenges depend on.
  The sandbox instead drops all capabilities, mounts the root filesystem
  read-only, limits processes, and isolates the network.
- **No encrypted Swarm overlay.** It uses ESP (IP protocol 50), which
  Linode Cloud Firewall cannot express, so it would silently fail. The VPC
  is a private network; nothing outside it sees the traffic.
- **No `redirect-gateway`.** Players' general internet traffic stays on
  their own connection. See "A player" above.
- **No raw Docker socket in CTFd.** Whale gets a filtered proxy instead; the
  convenience of the stock layout is not worth handing the Swarm manager to
  a public web application.
- **No public SSH from anywhere.** Roaming is handled by connecting the
  admin VPN first and running `status`, which updates every allow-list.

---

## 6. Residual risks, honestly

| Risk | Why it remains | What to do about it |
|---|---|---|
| Shared `tls-crypt` key | One key protects the port for all 51 profiles; a leaked profile lets an attacker reach the TLS handshake (not past it). | Move to `tls-crypt-v2` (per-client keys) before a large public event. Regenerate the PKI for every event regardless. |
| `admin.ovpn` theft | It is a static address with reach into everything. | Treat it like a root password. Never in a synced folder, never emailed. |
| Profile-pool drain | Anyone on the internet can register on CTFd and claim a profile. | **Set a CTFd registration code** (Admin → Config → Accounts) or enable email verification before opening registration. |
| CTFd itself | The largest public surface is a web application. | Keep the image tag current between events; CTFd has built-in login rate limits; consider Cloudflare in front for a large event. |
| Player↔player traffic via a *shared* challenge | Two players in the same static container can see each other's effects. | Mark it `type: dynamic` — each player then gets their own. |
| ~~Players can reach each other's instances~~ **(closed)** | Was: the gateway allowed the whole player range to the whole instance port range, so a player could scan and reach someone else's instance. | **Closed** by the per-team instance ACL: the gateway now permits only `(source address . port)` pairs that CTFd says belong to that player's own team. See "Per-team instance isolation" below. Set `INSTANCE_ISOLATION="false"` to revert to the old open range. |
| Flag in the environment (dynamic) | Whale injects `FLAG` as an env var; a player with a shell inside can read `/proc/1/environ` unless the image scrubs it. | Mandatory pattern in the author guide; tested in the acceptance guide. |
| Whale ↔ CTFd version drift | Whale is a community plugin whose internals track CTFd's; an upgrade can break it. | Both are pinned (CTFd 3.8.7, whale commit `2cc84a90`). Re-test before changing either. |
| Backups live on the CTFd node | An hourly dump on the node that might die. | Enable Linode Backups on it, or `scp` dumps down during the event. |
| Linode account | LISH console and the API token are root on everything. | 2FA on the account, LISH keys-only, narrow token scopes, rotate after each event. |
| Operator IPv6 prefix | Allow-listed as a /64; an ISP prefix change locks public SSH out. | Connect the admin VPN and run `status`; it heals itself. |

---

## 7. Questions people ask

**Can someone on the internet get into the gateway?**
They can send packets to UDP 1194 and nothing else. Without the `tls-crypt`
key those packets are dropped before OpenVPN even parses them, so the port
looks closed. With a leaked profile they could complete a handshake but not
authenticate once the certificate is revoked. SSH is not reachable from
addresses you have not used. Everything else the gateway runs is bound to
the private network.

**How do per-player instances work, and are they isolated the same way?**
The player presses Start; CTFd (through the socket proxy) asks Swarm to
create a service on the challenge host from the registry image, with a
unique flag. `frpc` on the CTFd node is told to forward a port in
10000–10100 to that service over the overlay; the player is shown
`10.0.0.3:<port>`. The container sits on the same overlay with the same
guard rules as a static challenge: no internet, no VPC, no metadata. It is
removed after 60 minutes (renewable) or when the player presses Destroy.

**What if a player gets root inside a challenge container?**
They have root in a container with no capabilities, a read-only filesystem,
a process limit, and a network that reaches only other containers. The
host has no route to the internet. The Docker socket is not mounted. This
is the expected outcome for a privilege-escalation challenge and the design
assumes it happens constantly.

**What if they escape the container onto the challenge host?**
They are root on a machine with no public IP, no default route, and a
firewall that admits nothing from it except Swarm control traffic to the
CTFd node and agent events to Wazuh. They could disrupt other challenges on
that host. They cannot reach the scoreboard database, the SIEM's data, or
the internet. Wazuh's agent on that host will have logged the escape.

**Can a player see or attack another player?**
No. OpenVPN's `client-to-client` is not enabled, so all inter-client
traffic goes through the kernel, where the forward chain drops any packet
whose source *and* destination are both in the VPN range.

**Can a player reach Wazuh, the registry, or SSH on anything?**
No. Those are denied by rules that sit *before* the allow rules in the
forward chain, and they only match the admin address. Players are not even
given routes to those addresses.

**How do I know who did something?**
Wazuh receives the OpenVPN connect log (certificate name ↔ VPN address ↔
real IP) and the CTFd plugin's log (account ↔ profile ↔ VPN address).
Together they answer "who was `10.8.0.117` at 14:32?" with a name.

**How do I remove a cheater mid-event?**
`[4] Revoke Player`. The certificate goes on the revocation list, the list
is pushed to the gateway, and their current session is killed through
OpenVPN's management socket. Reconnecting fails. Then ban the CTFd account.

**Why can't I SSH from a new café?**
Both firewall layers only know the IPs you have used. Connect the admin VPN
(that door is open from anywhere) and run `[2] Status`; it adds the new
address everywhere. This is deliberate: an allow-list that any network can
join is not an allow-list.

**What happens if the gateway reboots?**
nftables is regenerated from the same script at boot, including the
"challenge host revoked" state, which is a flag file. OpenVPN, the proxy
and DNS come back as services. Players reconnect automatically.

**What happens if the challenge host reboots?**
It comes back with no default route (there never was one), the guard rules
load before Docker starts, Swarm reschedules the services, and the
gateway still refuses it proxy access. Nothing to do.

**Why is my browser warning about the CTFd certificate?**
Because there is no domain yet, so Caddy signs its own certificate. Set
`CTF_DOMAIN` and Caddy will obtain a free Let's Encrypt certificate
automatically — no account, no cost.

**Why does the scoreboard have a public IP at all?**
Players need to register and read challenges before they have a VPN
profile — the profile comes *from* the scoreboard. It is the one service
that must be public.

**Why is Wazuh a 16 GB machine?**
Wazuh's single-node bundle (indexer + manager + dashboard) documents 8 GB
as the bare minimum and it swaps under load. 16 GB gives the indexer an
8 GB heap and leaves the dashboard responsive while you are searching logs
in the middle of an incident.

**Could the whole thing be cheaper?**
Yes: drop Wazuh to 8 GB (works, tight) and tear down between events.
Running cost is about $0.36/hour; a weekend event costs a few dollars.

**What is the single most important thing to get right on event day?**
Run `[2] Status` and look at the line *Challenge host egress: sealed*. Then
look at the isolation counters. If those two are right, the architecture
is doing its job; everything else is a support ticket, not a breach.

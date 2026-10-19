# club.eh CTF — Linode infrastructure

Automated, VPN-gated CTF range on Linode. One control script, four cloud-init
templates, one CTFd plugin.

```bash
./ctf_manager.sh            # interactive menu
./ctf_manager.sh selftest   # offline validation: PKI, templates, schema, stack. No API calls, no cost.
./ctf_manager.sh deploy | resume | status | teardown | revoke | challenges | challenges-rm | whale-config
```

Menu: `[1] Deploy  [2] Status  [3] Teardown  [4] Revoke Player  [5] Deploy/Update Challenges  [6] Remove Challenges  [7] Sync Challenges to CTFd  [8] Exit`

## Topology

```
                internet
                    |
       [ Cloud Firewall: 1194/udp world, 22 from your IPs ]
                    |
  Node 1  ctf-gateway    10.0.0.2 + 1:1 NAT public
          OpenVPN 1194 · nftables choke point · HTTP proxy + DNS for private nodes · bastion
                    |
        ============ VPC 10.0.0.0/24 ============
          |                    |                  |
  Node 2 ctf-ctfd        Node 3 ctf-challenge   Node 4 ctf-wazuh
  10.0.0.3 + public      10.0.0.4 VPC-ONLY      10.0.0.5 VPC-ONLY
  CTFd/Caddy/registry    Swarm worker, 8GB      Wazuh 4.14 single-node
  Swarm manager          ZERO WAN egress        16GB, admin-VPN only
  ctfd-whale + frps/frpc per-player instances
```

VPN pool `10.8.0.0/24` — admin pinned to `.50`, players `.100`–`.149`.

## Where this deviates from the original spec, and why

| Spec said | What was built | Reason |
|---|---|---|
| All secrets ride in cloud-init | PKI + config in user-data; **51 .ovpn profiles delivered over SSH** | Linode caps `metadata.user_data` at 16 KB decoded (verified live); the payload is gzip'd. The profile bundle is ~204 KB. Verified by `selftest`. |
| Pre-shared Docker Swarm join token | Control script reads the worker token from the manager over SSH and issues the join, then rotates both tokens | Docker generates join tokens on the manager; they cannot be pre-set. This is race-free and keeps the token off the worker's disk. |
| Nodes 3/4 are VPC-only | Same, but **Node 1 is created first** and runs an HTTP proxy + DNS forwarder the private nodes use to bootstrap; script waits for a ready sentinel before 2/3/4 launch | A VPC-only Linode has no internet at all, and **Linode VPC does not transit-forward through a member Linode** (verified live: forwarded packets never arrive), so a NAT gateway is impossible. A proxy whose destination *is* the gateway works. |
| Block 169.254.169.254 on all nodes | Blocked in `forward` / container chains; host `output` left open | Linode cloud-init re-reads metadata on **every** boot. A host-wide block bricks the node on first reboot. Containers and VPN clients — the actual threat — are still blocked. |
| CTFd serves profiles from a web directory | Custom CTFd plugin binds one profile per account | CTFd has no per-user file delivery. A shared directory lets any player take all 51 profiles and destroys VPN-IP attribution. |
| Challenges on an `--internal` Docker network | Enforced in nftables by container source subnet | `--internal` is bypassed by attaching a second network or publishing a port. A firewall rule survives container churn. |
| — | Cloud Firewalls attached **at creation** | Closes the exposure window between first boot and cloud-init applying nftables, and survives a host-level ruleset flush. |
| Static shared challenges | **Both**: static Swarm services *and* per-player instances via ctfd-whale | Per-instance flags make flag-sharing worthless and allow stateful / root-on-a-box challenges. Whale is driven through a Docker socket proxy, its frps is bound to the VPC address only, and instances never dial out (frpc dials in), so zero-outbound holds. |

## Security controls, and where each lives

| Requirement | Enforcement point |
|---|---|
| 2.1 Player-to-player isolation | `client-to-client` absent from `server.conf`; nftables drops VPN→VPN in `forward`. Two independent layers. |
| 2.2 Metadata blackhole | `forward` chain on every node, plus container chains on the Docker hosts. IPv6 metadata blocked too. |
| 2.3 Challenge zero-outbound | Node 3 `ctf_guard`: container subnets may reach each other and nothing else. The host itself has no default route by construction; its only egress was the gateway proxy, and after bootstrap the gateway refuses it and the host's proxy config is removed. **Verified post-deploy** three ways (direct, via proxy, DNS) — deploy warns loudly if any check passes when it should not. |
| 2.4 Admin vs player | `ccd-exclusive` static IP map; deny-first rules drop every VPN source except `10.8.0.50` to the SIEM and to port 22, before any allow. Players reach only `10.0.0.4:30000-32767` and CTFd web. |

`ccd-exclusive` means a client whose CN has no ccd entry is rejected outright,
so the static IP map *is* the access policy rather than a hint.

## Hosting challenges

Authors follow [challenges/README.md](challenges/README.md) and hand you a
directory. Drop it under `challenges/`, run `[5]`. The script validates every
`challenge.yml` (unique names, ports inside the player-reachable range, flag
present), ships the sources to the CTFd node, builds and pushes each image to
the private registry, renders a Swarm stack with the sandbox hard-wired, and
deploys it to the challenge host. No Docker needed on your laptop.

What the stack enforces regardless of what an author writes:

| Control | Setting |
|---|---|
| Publishing | `mode: host` only — routing mesh never used |
| Placement | `node.role == worker` (static) / `node.labels.name == linux-1` (whale) — never the public-facing node |
| Capabilities | `cap_drop: ALL`; authors opt back in per-cap, and you see it in the diff |
| Filesystem | read-only rootfs, 64 MB tmpfs at `/tmp` |
| Limits | CPU, memory, and **pids** (fork-bomb protection), per challenge |
| Flag | Swarm secret at `/run/secrets/flag`, mode `0400` by default — never in env, never in the image |
| Network | overlay `ctf_challenges`; nftables on the host denies every egress except container↔container |

Dynamic (`type: dynamic`) challenges are registered in CTFd as `dynamic_docker`; a player presses **Start**, whale creates a Swarm service on node 3 with a unique flag, and `frps` on the CTFd node hands the player `10.0.0.3:<10000–10100>`. Instances expire after an hour (renewable), one live instance per player, a global cap. See `challenges/README.md`.

`challenges/example-web/` is a complete working challenge you can deploy as a
smoke test.

## Operational notes

- **Publish challenges with `mode=host`, never ingress.** Swarm's routing mesh
  makes ingress-published ports reachable on *every* node, including Node 2's
  public IP — that would bypass the VPN entirely.
- **Push challenge images to `10.0.0.3:5000`** (the private registry). Node 3
  has no internet after deploy and cannot pull from Docker Hub.
- **Revocation** (`[4]`) regenerates the CRL, pushes it, and kills the live
  session through OpenVPN's localhost management socket. Use `/admin/vpn` in
  CTFd to find which account holds a profile.
- **Roaming**: `[2] Status` re-detects your public IP, syncs the Cloud
  Firewall, and pushes the new allow-list into each host's nftables. From a
  network the hosts have never seen, public SSH is refused by the host rules
  until that push happens — so connect `admin.ovpn` first; Status will reach
  the gateway over the VPN, update the allow-lists, and public SSH works again.
  The IPv6 allow-list uses your /64, since SLAAC privacy addresses rotate.
- **Time and names**: the VPC-only nodes have no internet, so the gateway serves
  NTP and DNS to the VPC. Wazuh timestamps stay coherent; Wazuh can still fetch
  updates through the proxy.
- **Break-glass**: if VPN and SSH both fail, use the Linode LISH console.
- **Backups**: hourly `mysqldump` on Node 2 at `/opt/ctf/backups`, 7-day
  retention. Pull one before teardown — teardown destroys the scoreboard.
- **Self-signed TLS** until you set `CTF_DOMAIN` at the top of the script.
  Let's Encrypt is free and needs no account registration; Caddy handles it.

## Docs

- `ARCHITECTURE.html` — the full topology diagram, deploy sequence, and access matrix (open in a browser)
- `ADMIN_GUIDE.md` — operating the event
- `DESIGN_RATIONALE.md` — why every decision was made, how the parts interact, residual risks, FAQ
- `TESTING_GUIDE.md` — the full acceptance test you can run yourself (~1 h, <$1)
- `challenges/README.md` — the contract for challenge authors

## Files

```
ctf_manager.sh                     control plane (bash 3.2, openssl PKI, no easy-rsa)
cloud-init/node1-gateway.yaml.tpl  OpenVPN + nftables + NAT
cloud-init/node2-ctfd.yaml.tpl     CTFd + Caddy + registry + Swarm manager
cloud-init/node3-challenge.yaml.tpl Swarm worker, zero-outbound guard
cloud-init/node4-wazuh.yaml.tpl    Wazuh 4.14 single-node
plugins/vpn_handout/               CTFd per-user VPN profile plugin
ctf_state.json                     0644, IDs and IPs only
ctf_secrets.env                    0600, credentials — never committed
```

Generated at deploy: `pki/` (CA key never leaves this machine), `profiles/`.

## Cost

~$255/month running (16GB + 8GB + 4GB×2), ~$0.36/hour. Tear down between events.

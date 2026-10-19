# Wazuh monitoring for the club.eh CTF range

Custom decoders, rules and per-node log sources for the four-node range.
`post_provision` installs all of this automatically on every `deploy`, so in
normal use you never run anything here by hand.

```
local_decoders.xml          CTFd, VPN session, VPN handout, nftables drop
local_rules.xml             25 rules, id space 100100-100199
agent-node1-gateway.conf    VPN + firewall + proxy log sources
agent-node2-ctfd.conf       CTFd app logs + docker events + FIM
agent-node3-challenge.conf  kernel + docker events + FIM
install.sh                  install.sh manager   |   install.sh agent node1
```

## What it watches, and why those things

Formats were taken from a **running** CTFd 3.8.7 and from the gateway's own
`ovpn-connect.sh`, not from documentation.

| Source | Path | Catches |
|---|---|---|
| CTFd submissions | `/opt/ctf/data/CTFd/logs/submissions.log` | flag brute force, solves |
| CTFd logins | `…/logins.log` | admin logins, credential use |
| CTFd registrations | `…/registrations.log` | bulk/scripted sign-ups |
| VPN handout | `…/vpn_handout.log` | who was issued which profile |
| VPN sessions | gateway `auth.log`, tag `ctf-vpn` | shared certificates, roaming |
| nftables drops | `/var/log/kern.log` | isolation violations, egress attempts |
| Docker events | `docker events` every 60 s | crash loops, exploited challenges |
| FIM | `/opt/ctf/stack`, `/etc/ctf`, ccd dir | flag or config tampering |

## The alerts worth paging on

Three rules are level 14 — they describe things that **cannot happen** unless
an invariant has already broken:

- **100133 `CHAL_EGRESS`** — the challenge host tried to reach the internet.
  Invariant 4 says it has no route at all, so this means code is running in a
  container and calling home.
- **100134 `METADATA`** — something tried to read `169.254.169.254`. That is
  the shortest path from container RCE to Linode API credentials.
- **100160 FIM on flags/stack** — the flag secrets or compose stack changed
  outside a deployment.

Level 12: `100113` sustained flag brute force, `100132` a player sweeping other
teams' instance ports, `100140` any successful SSH (the firewall allows only
your IP, so a login that is not you means the allow-list or a key is gone).

Level 10: `100102` admin login, `100104` bulk registration, `100112` flag brute
force, `100121` one VPN certificate used from 3+ addresses in 10 minutes —
which, because `ccd` pins each tunnel IP, is the only place profile sharing
becomes visible.

## Firewall logging — the part that had to change

The nftables rules enforced correctly but were **completely silent**: every
critical drop used an nft `comment`, which appears only in `nft list ruleset`
and never in a log. Five drops now carry a kernel log prefix
(`NOT_YOUR_INSTANCE`, `METADATA`, `CHAL_EGRESS`, `CHAL_HOSTSVC`).

Each is written as **two rules**, deliberately:

```
<match> limit rate 5/second burst 10 packets log prefix "ctf-drop NAME "
<match> counter drop
```

`limit` is a *matcher*. Had the log rule also carried the drop verdict, every
packet over the rate limit would stop matching that rule and fall through to
`accept` — a rate-limited log would have silently become a rate-limited
firewall. The log rule has no verdict, so traffic always reaches the drop.

`rsyslog` was added to nodes 2 and 3 for this: without it there is no
`/var/log/kern.log` and the prefixes go nowhere.

## Using it

Dashboard is on node 4, reachable only over the admin VPN:
`https://10.0.0.5` (credentials in `ctf_secrets.env`).

Useful filters during an event:

```
rule.groups:ctf_bruteforce              who is hammering the submit box
rule.groups:isolation_violation         who is poking at other teams
rule.level:>=12                         everything that needs you now
rule.groups:vpn_connect                 live session map, CN to source IP
rule.id:100133 OR rule.id:100134        invariant breaches
```

Test a rule without waiting for the real thing:

```bash
echo '[10/09/2026 04:38:53] alice submitted b"x" on 11 with kpm 0 [WRONG]' \
  | /var/ossec/bin/wazuh-logtest
```

## After editing rules

`install.sh manager` runs `wazuh-logtest -t` first and **refuses to restart**
on a bad ruleset — a manager that will not start is worse than one with no
custom rules. If it rejects your change it prints the parser error and leaves
the running config alone.

# ctflite — a whole CTF on one box, for the length of one event

The full range in the parent directory is four Linodes, a VPC, OpenVPN, Wazuh
and per-player Docker instances. This is the opposite: **one 4 GB Linode**
running CTFd and every static challenge side by side, reachable directly over
the internet. No VPN, no VPC, no SIEM, no whale.

It exists so you can stand up the beginner set in ten minutes, play with it,
change things, and throw it away — while the real range stays untouched.

```
./ctfl preflight    # free, creates nothing
./ctfl up           # ~8 min: Linode -> Docker -> CTFd -> 10 challenges -> registered
./ctfl down         # dump + download + VERIFY + delete. This is what stops billing.
```

## The billing shape

A powered-off Linode still bills, because its disk is still allocated. Only
**deletion** stops the charge — so the event has to leave the box before the box
goes away. That is the whole design of `down`:

```
./ctfl down
   1. docker compose stop ctfd      -> nothing is mid-write
   2. mysqldump --single-transaction + copy uploads, on the server
   3. tar, record size + sha256, download
   4. FOUR CHECKS:  size == remote
                    sha256 == remote
                    archive opens locally
                    ctfd-db.sql is actually inside it
   5. only if all four pass -> DELETE /v4/linode/instances/{id}
```

If any check fails the Linode is left **running and untouched** and the script
says so. It will never trade your event for a saved dollar.

`./ctfl up` restores the newest backup automatically, so users, teams, solves
and scores survive across teardowns. `--fresh` starts empty; `--from <archive>`
picks a specific one.

## Cost

| plan | RAM | $/hr | 8-hour event | between events |
|---|---|---|---|---|
| `g6-standard-2` (default) | 4 GB / 2 vCPU | $0.036 | **$0.29** | **$0.00** |
| `g6-standard-1` | 2 GB / 1 vCPU | $0.018 | $0.14 | $0.00 |
| `g6-standard-4` | 8 GB / 4 vCPU | $0.072 | $0.58 | $0.00 |

Backups live on your Mac, so there is no object-storage bill either.

## What gets deployed

CTFd (official image) + MariaDB + Redis on `:80`, and one container per static
challenge on its own published port, straight from `../challenges`:

| Challenge | Port | Category | Pts |
|---|---|---|---|
| start-here | 30009 | Start Here | 10 |
| misc-warmup-encoding | 30010 | Misc | 50 |
| example-web | 30001 | Web | 50 |
| web-cookie-admin | 30011 | Web | 75 |
| crypto-caesar | 30012 | Crypto | 75 |
| logs-bruteforce | 30013 | Logs | 100 |
| forensics-exif | 30014 | Forensics | 100 |
| forensics-fake-png | 30018 | Forensics | 100 |
| rev-checker | 30016 | Reverse Engineering | 125 |
| pwn-overflow | 30017 | Binary Exploitation | 150 |

`GATE_CHALLENGE` in `config.env` (default `start-here`) makes every other
challenge a CTFd prerequisite of that one, shown as `???` until it is solved.
Set it to `""` to unlock everything from the start.

Each one is created in CTFd automatically with its category, points,
description, static flag and hints — the description prose and hints come from
that challenge's `README.md`, and the connection line is rebuilt from the port
it is actually published on, so it cannot drift.

**Dynamic (ctfd-whale) challenges are skipped.** Per-player instances need frp,
a socket proxy and a second Docker host; that is what the full range is for.

## Customising it

Everything lives in `config.env`:

- `LINODE_TYPE` / `LINODE_REGION` — any region works; this build needs no VPC,
  so it is not restricted to `us-iad` like the full range.
- `EVENT_NAME`, `EVENT_DESC`, `CTF_USER_MODE` (`users` or `teams`).
  **`CTF_USER_MODE` is irreversible** once CTFd is set up — changing it means
  `./ctfl up --fresh`.
- `CHALLENGES_DIR` — defaults to the main project's `challenges/`. Point it at
  your own folder to run a different event; the format is
  `challenges/README.md` in the parent project.
- `CTFD_REGISTRATION_CODE` — set it before you share the URL, or anyone who
  finds the IP can sign up.
- `HINT_COST` — points per hint. `0` (default) makes them free.
- `PLAYER_CIDR` — who may reach CTFd and the challenges. Leave it at your own
  `/32` while you are building; open it to `0.0.0.0/0` for the event.

After editing a challenge: `./ctfl challenges` rebuilds the images on the
running box and re-syncs CTFd. After editing only a description, points or a
hint: `./ctfl register` — no rebuild. After fixing a bug in
`remote/provision.sh`: `./ctfl reprovision` re-runs provisioning against the
**existing** box instead of paying to recreate one.

## Security, honestly

This is **weaker than the full range, on purpose**, and you should know exactly
how:

- Challenges are on the **public internet**, not behind a VPN. Anyone who
  port-scans the box finds them. There is no player-to-player isolation and no
  per-team instance separation.
- CTFd is served over **HTTP**, not HTTPS. Passwords cross the network in the
  clear. Do not reuse a password you care about, and do not run a scored,
  public event on it without putting a TLS terminator in front.
- CTFd and the challenges share one kernel. A container escape reaches the
  scoreboard. The full range puts them on separate hosts for this reason.
- There is no Wazuh, no audit log shipping, and no intrusion detection.

What it *does* keep from the big build: every challenge drops all capabilities,
runs on a read-only rootfs with a tmpfs `/tmp`, gets pids/CPU/memory caps and
`no-new-privileges`, and reads its flag from a bind-mounted `/run/secrets/flag`
so the flag is never in the image. SSH is firewalled to your own IP (both
address families), and `DOCKER-USER` is constrained so `PLAYER_CIDR` actually
applies to published container ports — ufw alone does not do that.

Use it for building, testing and small trusted events. Use the parent project
for anything real.

## Files

```
ctfl                  the CLI. up / down / backup / status / challenges / register / ...
config.env            every knob
lib/common.sh         logging, Linode API, state, ssh, the 4-check verifier
remote/provision.sh   runs on the box: docker, CTFd, firewall, build, start
remote/gen_compose.py emits the challenge compose file + writes the flag files
remote/ctfd_init.py   CTFd setup wizard + creates challenges/flags/hints
state/                current.json (live server), credentials.env, ssh key
backups/              ctflite-<ts>.tar.gz + a .json manifest each
```

`state/credentials.env` deliberately **survives teardown**: a restored backup
still contains the password hashes from when it was taken, so rotating the
admin password locally would lock you out of your own archive.

## Verified

A full `up` → play → `down` cycle was run live on 2026-09-14 (Linode 105264166,
`g6-standard-2`, us-east, total cost $0.01):

- all 10 challenge images built on the box and published on their own ports,
  reachable from the open internet;
- **all 10 solved end to end over the network** against the deployed services —
  the flag each container serves matches the flag CTFd grades;
- CTFd registration worked, a correct flag graded `correct` and a wrong flag
  graded `incorrect`;
- every challenge ended with exactly **one** flag row and its hints after three
  registration passes, so re-running is genuinely idempotent;
- sandbox confirmed on a live container: read-only rootfs, `CapDrop=[ALL]`,
  `no-new-privileges`, `PidsLimit=64`, 64 MB cap, flag bind-mounted read-only,
  absent from the image and from `/proc/1/environ`;
- `down` passed all four checks, captured 2 users and 1 solve, and deleted the
  Linode; `./ctfl orphans` then reported nothing billing.

**Restore verified 2026-09-15.** A later `./ctfl up` on a brand new Linode
(105298481) loaded that archive: the registered player, their solve and all ten
challenges came back, and the warm-up still graded against the same flag. The
full `up -> play -> down -> up` round trip is now proven.

### The setup window (fixed 2026-09-15)

CTFd answers on :80 several minutes before the setup wizard runs. `:80` used to
be opened to `PLAYER_CIDR` at the start of provisioning, so during that window
anyone loading the URL got an **open, unauthenticated `/setup` wizard** and
could have made themselves admin of the event. On a fresh deploy that window is
as long as the image builds.

Provisioning now opens `:80` and the challenge ports to `ADMIN_CIDR` only, and
admits `PLAYER_CIDR` in a final step *after* CTFd is configured - which it
refuses to do if `/setup` still answers 200. A run that dies half way leaves the
box reachable only from your own IP instead of hijackable.

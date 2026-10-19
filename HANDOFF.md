# club.eh CTF — Handoff

Everything to run, extend, or rebuild this CTF. Start here, then dive into the
deeper docs below.

## What this is
A full CTF platform: a 4-node Linode range driven entirely by `ctf_manager.sh`
(gateway/VPN, CTFd+whale, isolated challenge host, Wazuh SIEM), ~45 challenges
across Crypto / Web / Reverse Engineering / Binary Exploitation / Misc / Logs /
SOC Triage, plus on-site **Physical** (Actiontec V1000H router) and **Scavenger**
(NFC) tracks. Players connect over OpenVPN; challenges run with zero internet
egress; Wazuh watches everything.

## Read these (in order)
1. `README.md` — topology and what ships.
2. `ADMIN_GUIDE.md` — day-to-day operation. `TESTING_GUIDE.md` — validation.
3. `DESIGN_RATIONALE.md` / `ARCHITECTURE.html` — the security model, why it's
   built this way, and the traps to know before editing.
4. `challenges/README.md` — the author contract for writing challenges.

## Current state (post-event)
- **The live range was torn down** (`teardown`) to stop billing. The repo is the
  full source of truth; re-deploy brings an identical range back.
- **Secrets are NOT in the repo** (gitignored): `ctf_secrets.env`,
  `personal_access_token.txt` (Linode token), `pki/` (CA key), `profiles/` (VPN),
  `ctf_state.json`. A fresh deploy regenerates all of them.
- **Flags live in each `challenges/<name>/challenge.yml`**, so the challenge set
  is fully reproducible from the repo.
- **Wazuh forensic logs** from the event were saved to
  `wazuh-evidence-2026-10-10/` (gitignored — player IPs + flags).

## Deploy a fresh range
```bash
# prerequisites: a Linode API token in personal_access_token.txt (0600),
#   an SSH key at ~/.ssh/ctf_ed25519, jq, openssl, linode-cli, docker (for builds)
./ctf_manager.sh selftest        # PKI, templates, stack render — all offline
./ctf_manager.sh deploy          # ~15-20 min: 4 nodes, VPN, CTFd, whale, Wazuh
./ctf_manager.sh challenges       # build + register every challenge, apply gating
```
`deploy` writes `ctf_state.json` + `ctf_secrets.env` (admin password, DB creds,
Wazuh creds, VPN isolation token, root passwords — keep 0600, never commit).
`resume` continues a deploy that stopped mid-way. `status` reaches the gateway
over the admin VPN. `printf 'DESTROY\ny\n' | ./ctf_manager.sh teardown` removes
everything (bills ~$0.32–0.36/hr while up).

## Operating the event (what we learned running it)
- **Hints**: off by default. `./ctf_manager.sh hints on|off` toggles them on the
  live scoreboard; hint text always stays in each README / questions.json.
- **Gating**: `rules` → `start-here` → everything; question sets unlock one
  question at a time; Physical/Scavenger gate on `rules`. Locked challenges are
  **hidden** (anonymize:false). Re-applied on every register/deploy.
- **Registration code**: `REGISTRATION_CODE` in `ctf_secrets.env`, enforced on
  CTFd signup. Change it and run `./ctf_manager.sh register`.
- **Multiple admins**: 9 concurrent admin VPN seats (admin, admin2..admin9 on
  10.8.0.50-58). `scripts/extra-admins.sh` re-provisions them after a redeploy.
- **Dynamic (per-player) challenges** use whale+frp. **After any
  `./ctf_manager.sh challenges`, frpc is auto-restarted** so instances keep
  routing (a stale overlay silently breaks them). Never rebuild a
  dynamic image while instances are live; it orphans them.
- **Public domain**: to front CTFd with a domain via Cloudflare, add an
  `https://<domain>` block to the CTFd node's `/opt/ctf/Caddyfile` (`tls internal`)
  and set Cloudflare SSL mode to **Full**; restart caddy with
  `docker compose up -d --force-recreate caddy` (admin API is off, so `reload`
  won't apply). For Full (strict), install a Cloudflare Origin cert instead.
- **Scoreboard refresh**: CTFd caches standings. Clear CTFd's own cache — do NOT
  `redis-cli FLUSHALL` (it wipes whale's port state and breaks new instances).

## Off-range materials
- `physical-challenges/V1000H/` — the on-site router challenges (SMB share +
  firmware ID), with `SCENARIO.md` (player briefing) and `ORGANIZER.md` (setup,
  the real firmware's capability notes, restore).
- `physical-challenges/nfc-scavenger/make_tags.py` — generates the NFC tag texts
  (progressively encoded) + the assembled flag. `TAGS.txt` is the write list.
- `router-challenge/SCHEMA.md` — build spec for new physical router challenges.
- `wolf-track/` — design spec + how-to-run for the rev-wolf track (writeups excluded).
- `ctflite/` — a separate single-box CTF (see its own README).

## Validate after any change
```bash
./ctf_manager.sh selftest
bash -n ctf_manager.sh && shellcheck -s bash -S warning ctf_manager.sh
```

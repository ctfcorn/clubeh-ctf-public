# Challenge author guide — club.eh CTF

Every challenge is a Docker container that runs on an isolated host with
**no internet access** and is reached by players over VPN at
`10.0.0.4:<published port>`. You give us a directory; we build, push and run it.

## What to submit

One directory per challenge, named the same as the challenge:

```
my-challenge/
├── challenge.yml      required — metadata (format below)
├── Dockerfile         required — must build with no network at *runtime*
├── README.md          required — description for CTFd, hints, intended solve
├── solve/             recommended — a working solve script; we test it
└── src/ …             whatever the Dockerfile needs
```

Copy `_template/` to start. `example-web/` is a complete working challenge.

## Two kinds of challenge

| | `type: static` | `type: dynamic` |
|---|---|---|
| What runs | One always-on container shared by every player | A **private instance per player**, created when they press *Start* in CTFd (ctfd-whale) |
| Address | Fixed: `10.0.0.4:<published>` | Shown in CTFd after Start: `10.0.0.3:<random 10000–10100>` |
| Flag | Shared, from `challenge.yml`, mounted at `/run/secrets/flag` | **Unique per instance**, injected as the `FLAG` environment variable |
| Lifetime | The whole event | 60 min, renewable a few times; players can destroy and restart |
| Use it for | Stateless services, downloads, anything where players don't interfere | Anything stateful, "get root on this box", anything where flag-sharing must be impossible |
| Registered in CTFd by | You (description gets the address) | The deploy script, from `category`, `points`, `description` |

**Default to dynamic** unless the challenge is a pure download or a stateless
oracle. Per-instance flags are the single strongest anti-cheating measure the
platform has.

## challenge.yml

One `key: value` per line. No nesting. Quote strings containing spaces.

```yaml
name: my-challenge          # [a-z0-9-], unique across the event; becomes the service name
port: 8080                  # port your process LISTENS on inside the container
published: 30001            # port players connect to on 10.0.0.4 — 30000-32767, unique
protocol: tcp               # tcp or udp
flag: "clubeh{example_flag_here}"
flag_mode: "0400"           # 0400 = only root inside the container can read /run/secrets/flag
                            # 0444 = anyone in the container can read it (for "just find it" challenges)
replicas: 1                 # more = more concurrent players, same published port (host mode: max 1 per port!)
cpus: "0.5"                 # hard CPU limit
memory: "256M"              # hard memory limit; container is killed above this
pids: 128                   # max processes; stops fork bombs
read_only: "true"           # root filesystem read-only. Writable /tmp is provided as tmpfs
caps: ""                    # extra Linux capabilities, comma-separated. Default: NONE. e.g. "CHOWN,SETUID,SETGID"
```

`replicas` must stay at 1 unless you understand host-mode publishing: each
replica needs its own host port, and one `published` port only maps to one.

## The flag — dynamic challenges

Whale starts your container with the environment variable `FLAG` set to a
value unique to that player. You **must** handle it like this:

1. Read it once at startup.
2. Remove it from the environment (`os.environ.pop("FLAG")`, `unset FLAG`).
3. Keep it in memory or write it to a root-only file (`/flag`, mode 0400) —
   whichever your challenge needs. Never leave it in the environment: any
   process a player runs inside the container can read `/proc/1/environ`.

```python
FLAG = os.environ.pop("FLAG")           # python
```
```bash
echo -n "$FLAG" > /flag && chmod 400 /flag && unset FLAG && exec your-service   # shell entrypoint, as root, then drop privileges
```

Do not set a `flag:` in `challenge.yml` for dynamic challenges; it is ignored.
Players submit the instance's flag in CTFd and it is checked against the
instance that is theirs. A flag from someone else's instance is wrong.

No `published` port either: the platform reaches your container over the
overlay network by its service name, on `port`. Just listen on `0.0.0.0:port`.

## The flag — static challenges

The flag is **not** in the environment and **not** baked into the image. It
is mounted at `/run/secrets/flag` with the permissions in `flag_mode`. Your
challenge reads it from there:

```python
open("/run/secrets/flag").read().strip()
```

```bash
cat /run/secrets/flag
```

Do not `COPY` a flag into the image. Do not put it in an env var. Images sit
in a registry the whole event; secrets do not.

## Rules of the sandbox

1. **No outbound network.** Not DNS, not HTTP, not anything. `pip install`,
   `apt-get`, `curl` all fail at runtime. Do everything at *build* time in the
   Dockerfile. A challenge that needs a callback to the internet cannot be hosted.
2. **Containers can talk to each other** on the challenge network by service
   name (`my-challenge`, `other-challenge`). Use this if your challenge needs
   a database: submit it as a second directory and reference it by name.
3. **Capabilities are dropped to none.** No `ping`, no raw sockets, no
   `mount`, no `chown` unless you list it in `caps`. Ask before adding
   `SYS_ADMIN`, `NET_ADMIN` or `SYS_PTRACE` — we will probably say no.
4. **Root filesystem is read-only** by default. Write to `/tmp` (tmpfs, 64 MB).
   Set `read_only: "false"` only if you truly need it, and explain why in README.
5. **Resource limits are enforced, and they add up.** Your challenge runs as
   one long-lived container shared by every player — nobody spins up their
   own copy — so the host's load is the *sum* of every challenge's declared
   limits. A container that exceeds `memory` is killed and restarted; the
   player loses their state. Size honestly: a Python web service needs
   64–128 MB, not 512. The deploy script warns when the total exceeds the
   host.
6. **Privilege escalation challenges are fine** — setuid binaries work
   inside the container. But the "root" a player gets is root *in the
   container* with no capabilities. That is the design; do not try to break out.
7. **Assume 50 players hit it at once.** Stateless is best. If you need
   per-player state, key it on something the player provides, expire it, and
   bound its size.
8. **Listen on `0.0.0.0`**, not `127.0.0.1`. Log to stdout/stderr.
9. **Do not run as root** if you do not need to. `USER nobody` in the Dockerfile.
10. **Include a solve script.** If we cannot solve it with your script, it
    does not ship.

## What you get back

Static: the challenge is reachable at `10.0.0.4:<published>` over the VPN.
Dynamic: it appears in CTFd under your `category`; players press **Start**
and see their own `10.0.0.3:<port>`. Put that address in the CTFd challenge description. Example for a web
challenge: `http://10.0.0.4:30001/`; for a TCP service: `nc 10.0.0.4 30002`.

## Testing locally

```bash
docker build -t my-challenge .
echo -n 'clubeh{test}' > /tmp/flag
docker run --rm -p 8080:8080 --network none --read-only --tmpfs /tmp \
  --cap-drop ALL -v /tmp/flag:/run/secrets/flag:ro my-challenge
```

`--network none` reproduces the no-internet rule. If it works like that, it
will work in the event.

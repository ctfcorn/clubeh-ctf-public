#!/usr/bin/env python3
"""Emit a docker-compose file for the static challenges, and write their flags.

Runs on the box. Mirrors the sandbox the full range applies through Swarm
(cap_drop ALL, read-only rootfs, tmpfs /tmp, pids/cpu/memory caps) using the
plain-compose equivalents, because this build has no Swarm.

    gen_compose.py <challenges_dir> <secrets_dir>  > challenges.yml
"""
import os
import sys


def parse_yml(path):
    """challenge.yml is a flat key: value file - no need for a YAML parser, and
    this keeps the box free of a PyYAML dependency for one file."""
    out = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.lstrip().startswith("#") or ":" not in line:
                continue
            key, _, val = line.partition(":")
            if key != key.strip():          # indented -> nested, not ours
                continue
            val = val.strip()
            if "#" in val and not (val.startswith('"') or val.startswith("'")):
                val = val.split("#", 1)[0].strip()
            out[key.strip()] = val.strip().strip('"').strip("'")
    return out


def main():
    src, secrets = sys.argv[1], sys.argv[2]
    os.makedirs(secrets, exist_ok=True)

    print("services:")
    any_service = False

    for name in sorted(os.listdir(src)):
        d = os.path.join(src, name)
        f = os.path.join(d, "challenge.yml")
        # _template is the author kit's skeleton, not a challenge - and it
        # claims port 30010, which collides with the real warm-up.
        if name == "_template" or not os.path.isfile(f):
            continue
        c = parse_yml(f)
        if c.get("type") == "dynamic":
            continue
        pub, port = c.get("published"), c.get("port")
        if not pub or not port:
            continue
        proto = c.get("protocol", "tcp")
        flag = c.get("flag", "")
        if not flag:
            sys.stderr.write(f"{name}: no flag, skipped\n")
            continue

        flag_path = os.path.join(secrets, f"{name}.flag")
        with open(flag_path, "w", encoding="utf-8") as fh:
            fh.write(flag)
        # 0444, not the challenge.yml flag_mode: a bind-mounted file keeps its
        # host ownership (root), and every challenge process runs as a non-root
        # user, so 0400 would be unreadable inside the container. The secrets
        # directory itself is 0700 root, which is what keeps this private.
        os.chmod(flag_path, 0o444)

        any_service = True
        print(f"  {name}:")
        print(f"    image: ctflite/{name}:latest")
        print("    restart: always")
        print("    ports:")
        print(f'      - "{pub}:{port}/{proto}"')
        print(f'    read_only: {"false" if c.get("read_only") == "false" else "true"}')
        print("    tmpfs:")
        print("      - /tmp:size=67108864")
        print("    volumes:")
        print(f"      - ../secrets/{name}.flag:/run/secrets/flag:ro")
        print("    cap_drop:")
        print("      - ALL")
        caps = c.get("caps", "")
        if caps:
            print("    cap_add:")
            for cap in (x.strip() for x in caps.split(",")):
                if cap:
                    print(f"      - {cap}")
        # no-new-privileges breaks setuid binaries, which privesc challenges
        # rely on. Opt out per challenge with `allow_setuid: true`.
        if c.get("allow_setuid") != "true":
            print("    security_opt:")
            print("      - no-new-privileges:true")
        print(f'    mem_limit: {c.get("memory", "256M").lower()}')
        print(f'    cpus: {c.get("cpus", "0.5")}')
        print(f'    pids_limit: {c.get("pids", "128")}')
        print("    stop_grace_period: 5s")

    if not any_service:
        sys.stderr.write("no static challenges found\n")
        sys.exit(1)


if __name__ == "__main__":
    main()

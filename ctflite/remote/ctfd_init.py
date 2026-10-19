#!/usr/bin/env python3
"""Run CTFd's first-run setup, then create a challenge per static definition.

Runs on the box against http://127.0.0.1, so there is no TLS or proxy in the
way. Idempotent: a challenge that already exists is updated in place and its
flags and hints are replaced, never appended - an appended duplicate flag would
let a player score the same challenge twice.

    ctfd_init.py <challenges_dir>
"""
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1"

opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
)
CSRF = None


def req(method, path, data=None, form=False):
    url = BASE + path
    headers = {}
    body = None
    if form:
        body = urllib.parse.urlencode(data, doseq=True).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif data is not None:
        # CTFd answers a bare 403 to any state-changing request with no body
        # and no CSRF header, so both are always sent.
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    if CSRF:
        headers["CSRF-Token"] = CSRF
    r = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with opener.open(r, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def api(method, path, data=None):
    code, body = req(method, "/api/v1" + path, data if data is not None else {})
    try:
        return code, json.loads(body)
    except ValueError:
        return code, {}


def nonce_from(html):
    m = re.search(r'name="nonce"[^>]*value="([^"]+)"', html)
    return m.group(1) if m else None


def wait_up():
    for _ in range(60):
        try:
            code, _body = req("GET", "/")
            if code:
                return
        except Exception:
            pass
        time.sleep(5)
    sys.exit("CTFd never answered on " + BASE)


# --------------------------------------------------------------- parsing
def parse_yml(path):
    out = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.lstrip().startswith("#") or ":" not in line:
                continue
            key, _, val = line.partition(":")
            if key != key.strip():
                continue
            val = val.strip()
            if "#" in val and not (val.startswith('"') or val.startswith("'")):
                val = val.split("#", 1)[0].strip()
            out[key.strip()] = val.strip().strip('"').strip("'")
    return out


def description_of(d):
    """Prose of the '## Description (paste into CTFd)' block: everything between
    the heading and the fenced connection example."""
    r = os.path.join(d, "README.md")
    if not os.path.isfile(r):
        return ""
    lines, grab = [], False
    for line in open(r, encoding="utf-8"):
        line = line.rstrip("\n")
        if line.startswith("## Description (paste into CTFd)"):
            grab = True
            continue
        if grab and (line.startswith("```") or line.startswith("## ")):
            break
        if grab:
            lines.append(line.rstrip())
    return "\n".join(lines).strip()


def hints_of(d):
    """Numbered items under '## Hints', with wrapped continuation lines folded
    back onto their item."""
    r = os.path.join(d, "README.md")
    if not os.path.isfile(r):
        return []
    out, buf, grab = [], "", False
    for line in open(r, encoding="utf-8"):
        line = line.rstrip("\n")
        if line.startswith("## Hints"):
            grab = True
            continue
        if not grab:
            continue
        if line.startswith("## "):
            break
        m = re.match(r"^\d+\.\s+(.*)$", line)
        if m:
            if buf:
                out.append(buf)
            buf = m.group(1)
        elif buf and re.match(r"^\s+\S", line):
            buf += " " + line.strip()
    if buf:
        out.append(buf)
    return out


def retarget(text, host):
    """Point every host reference at THIS deployment.

    The challenge READMEs are authored against the full range, where challenges
    live behind a VPN at 10.0.0.4, and some use a literal HOST token. The
    description's connection line is rebuilt from the port, but hints and prose
    are copied verbatim - so without this a player is told to run
    `nc 10.0.0.4 30017`, an address that does not exist on this build.
    """
    if not text:
        return text
    text = text.replace("10.0.0.4", host)
    return re.sub(r"\bHOST\b", host, text)


def connline(d, c, host):
    """Rebuilt from published/protocol, never copied from the README, so it can
    never drift from the port the container is actually listening on."""
    pub, proto = c.get("published"), c.get("protocol", "tcp")
    r = os.path.join(d, "README.md")
    path = ""
    is_http = False
    if os.path.isfile(r):
        m = re.search(r"http://[0-9.]+:[0-9]+([^\s`]*)", open(r, encoding="utf-8").read())
        if m:
            is_http, path = True, m.group(1)
    if is_http:
        return f"http://{host}:{pub}{path}"
    if proto == "udp":
        return f"nc -u {host} {pub}"
    return f"nc {host} {pub}"


# --------------------------------------------------------------- setup
def do_setup():
    code, html = req("GET", "/setup")
    n = nonce_from(html)
    if not n:
        print("  setup page has no nonce - CTFd is probably already configured")
        return False
    form = {
        "ctf_name": os.environ["EVENT_NAME"],
        "ctf_description": os.environ.get("EVENT_DESC", ""),
        "user_mode": os.environ.get("CTF_USER_MODE", "users"),
        "team_size": os.environ.get("CTF_TEAM_SIZE", "4"),
        "challenge_visibility": "private",
        "account_visibility": "private",
        "score_visibility": "private",
        "registration_visibility": "public",
        "verify_emails": "false",
        "name": os.environ["CTFD_ADMIN_USER"],
        "email": os.environ["CTFD_ADMIN_EMAIL"],
        "password": os.environ["CTFD_ADMIN_PW"],
        "ctf_theme": "core-beta",
        "nonce": n,
        "_submit": "Finish",
    }
    code, _ = req("POST", "/setup", form, form=True)
    if code in (200, 302):
        print(f"  CTFd initialised (admin: {form['name']}, mode: {form['user_mode']})")
        return True
    print(f"  setup returned HTTP {code}", file=sys.stderr)
    return False


def login():
    global CSRF
    code, html = req("GET", "/login")
    n = nonce_from(html)
    if not n:
        sys.exit("login page has no nonce")
    req("POST", "/login", {
        "name": os.environ["CTFD_ADMIN_USER"],
        "password": os.environ["CTFD_ADMIN_PW"],
        "nonce": n,
        "_submit": "Submit",
    }, form=True)
    # Read the API nonce from /admin/config, not /challenges: in teams mode an
    # admin who is not on a team gets redirected off /challenges and the nonce
    # comes back empty.
    code, html = req("GET", "/admin/config")
    m = re.search(r"'csrfNonce':\s*\"([^\"]+)\"", html)
    if not m:
        sys.exit("could not read the admin CSRF nonce - is the password right?")
    CSRF = m.group(1)


def clear_children(cid, kind):
    code, body = api("GET", f"/challenges/{cid}/{kind}")
    for item in body.get("data", []) or []:
        api("DELETE", f"/{kind}/{item['id']}")


def register(d, c, host, hint_cost):
    name = c["name"]
    desc = description_of(d) or f"Flag format: {os.environ.get('FLAG_PREFIX','flag')}{{...}}"
    desc = retarget(desc, host)
    desc = f"{desc}\n\n`{connline(d, c, host)}`"

    code, body = api("GET", "/challenges?view=admin")
    existing = [x["id"] for x in body.get("data", []) or [] if x.get("name") == name]
    payload = {
        "name": name,
        "category": c.get("category", "Misc"),
        "description": desc,
        "value": int(c.get("points", 100)),
        "state": "visible",
    }
    if existing:
        cid = existing[0]
        code, body = api("PATCH", f"/challenges/{cid}", payload)
        if not body.get("success"):
            print(f"  {name}: update failed {code} {body}", file=sys.stderr)
            return False
        clear_children(cid, "flags")
        clear_children(cid, "hints")
        print(f"  {name}: updated (id {cid})")
    else:
        code, body = api("POST", "/challenges", dict(payload, type="standard"))
        if not body.get("success"):
            print(f"  {name}: create failed {code} {body}", file=sys.stderr)
            return False
        cid = body["data"]["id"]
        print(f"  {name}: created (id {cid}, {payload['value']} pts, {payload['category']})")

    # CTFd's own admin UI posts `challenge`; the schema documents
    # `challenge_id`. Send both so this works either way.
    code, body = api("POST", "/flags", {
        "challenge": cid, "challenge_id": cid,
        "content": c["flag"], "type": "static", "data": "",
    })
    if not body.get("success"):
        print(f"  {name}: FLAG NOT ATTACHED {code} {body}", file=sys.stderr)
        return False

    n = 0
    for h in hints_of(d):
        code, body = api("POST", "/hints", {
            "challenge": cid, "challenge_id": cid,
            "content": retarget(h, host), "cost": hint_cost, "type": "standard",
        })
        if body.get("success"):
            n += 1
    print(f"    flag attached, {n} hint(s)")
    return cid


def main():
    src = sys.argv[1]
    host = os.environ.get("PUBLIC_HOST", "127.0.0.1")
    hint_cost = int(os.environ.get("HINT_COST", "0"))

    wait_up()
    if os.environ.get("ALREADY_SETUP") == "1":
        print("  restored deployment - skipping the setup wizard")
    else:
        do_setup()
    login()

    okc = 0
    ids = {}
    for name in sorted(os.listdir(src)):
        d = os.path.join(src, name)
        f = os.path.join(d, "challenge.yml")
        if name == "_template" or not os.path.isfile(f):
            continue
        c = parse_yml(f)
        if c.get("type") == "dynamic" or not c.get("flag"):
            continue
        cid = register(d, c, host, hint_cost)
        if cid:
            ids[c["name"]] = cid
            okc += 1

    # Gate: every other challenge requires GATE_CHALLENGE to be solved first, so
    # nobody meets a `nc` challenge before the tutorial that explains nc.
    # anonymize=True shows locked challenges as "???" instead of hiding them, so
    # players can see there is more waiting rather than an empty scoreboard.
    gate = os.environ.get("GATE_CHALLENGE", "").strip()
    if gate:
        gid = ids.get(gate)
        if not gid:
            print(f"  WARNING: GATE_CHALLENGE '{gate}' not found - nothing gated",
                  file=sys.stderr)
        else:
            locked = 0
            for nm, cid in ids.items():
                if cid == gid:
                    api("PATCH", f"/challenges/{cid}", {"requirements": None})
                    continue
                code, body = api("PATCH", f"/challenges/{cid}",
                                 {"requirements": {"prerequisites": [gid],
                                                   "anonymize": True}})
                if body.get("success"):
                    locked += 1
            print(f"  gated {locked} challenge(s) behind '{gate}' (id {gid})")

    code = os.environ.get("CTFD_REGISTRATION_CODE", "")
    if code:
        api("PATCH", "/configs", {"registration_code": code})
        print("  registration code set")

    print(f"  {okc} challenge(s) live in CTFd")


if __name__ == "__main__":
    main()

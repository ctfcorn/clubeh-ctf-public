"""Read-only server for a static web bundle with subdirectories (the SOC console).

Sibling of static_serve.py for bundles that need assets/ and logs/ folders. The
allow-list is every regular file under ROOT, built ONCE at start-up from a walk
that never follows symlinks; a request is served only if its normalised path is
exactly one of those files. So `..`, encoded `%2e%2e`, backslashes, symlinks,
dotfiles and anything created after start-up all get the same plain 404.
GET/HEAD only. `/` serves index.html. No directory listings.

Canonical copy: challenges/_lib/static_tree_serve.py (copied into each src/).
usage: python3 static_tree_serve.py ROOT PORT
"""
import http.server, os, posixpath, sys, urllib.parse

ROOT = os.path.realpath(sys.argv[1])
PORT = int(sys.argv[2])

TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
         ".mjs": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
         ".json": "application/json", ".pdf": "application/pdf",
         ".txt": "text/plain; charset=utf-8", ".log": "text/plain; charset=utf-8",
         ".csv": "text/plain; charset=utf-8", ".md": "text/plain; charset=utf-8",
         ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon"}

def build_allow():
    allow = {}
    for dp, dns, fns in os.walk(ROOT, followlinks=False):
        dns[:] = [d for d in dns if not d.startswith(".") and not os.path.islink(os.path.join(dp, d))]
        for fn in fns:
            p = os.path.join(dp, fn)
            if fn.startswith(".") or os.path.islink(p) or not os.path.isfile(p):
                continue
            rel = os.path.relpath(p, ROOT).replace(os.sep, "/")
            allow["/" + rel] = p
    return allow

ALLOW = build_allow()

class H(http.server.BaseHTTPRequestHandler):
    server_version = "files"
    sys_version = ""

    def send(self, code, body, ctype, head):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def handle_any(self, head):
        raw = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        if "\\" in raw or "\x00" in raw:
            return self.send(404, b"not found\n", "text/plain", head)
        path = posixpath.normpath(raw) if raw != "/" else "/index.html"
        p = ALLOW.get(path)
        if p is None:
            return self.send(404, b"not found\n", "text/plain", head)
        with open(p, "rb") as f:
            data = f.read()
        ctype = TYPES.get(os.path.splitext(p)[1].lower(), "application/octet-stream")
        self.send(200, data, ctype, head)

    def do_GET(self):  self.handle_any(False)
    def do_HEAD(self): self.handle_any(True)

    def log_message(self, fmt, *a):
        print("%s - %s" % (self.client_address[0], fmt % a), flush=True)

http.server.ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()

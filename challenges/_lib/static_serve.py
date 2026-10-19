"""Minimal read-only file server for challenge downloads.

Replaces `python3 -m http.server`. Serves ONLY regular files that sit directly
inside ROOT, by exact name: no subdirectories, no symlinks, no `..`, no query
tricks, GET/HEAD only. The index page lists exactly those files. Anything else
is a plain 404, so the response never tells a prober what exists outside ROOT.

Canonical copy: challenges/_lib/static_serve.py (copied into each src/).
usage: python3 static_serve.py ROOT PORT
"""
import html, http.server, os, sys, urllib.parse

ROOT = os.path.realpath(sys.argv[1])
PORT = int(sys.argv[2])

def allowed():
    out = {}
    for name in sorted(os.listdir(ROOT)):
        p = os.path.join(ROOT, name)
        if not name.startswith(".") and os.path.isfile(p) and not os.path.islink(p):
            out[name] = p
    return out

class H(http.server.BaseHTTPRequestHandler):
    server_version = "files"
    sys_version = ""

    def send(self, code, body, ctype="text/html; charset=utf-8", head=False, extra=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def handle_any(self, head):
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        files = allowed()
        if path == "/":
            items = "".join('<li><a href="%s">%s</a></li>' % (urllib.parse.quote(n), html.escape(n)) for n in files)
            return self.send(200, ("<!doctype html><title>files</title><h1>files</h1><ul>%s</ul>" % items).encode(), head=head)
        name = path[1:]
        if "/" in name or "\\" in name or name not in files:
            return self.send(404, b"not found\n", "text/plain", head)
        with open(files[name], "rb") as f:
            data = f.read()
        ctype = "text/plain; charset=utf-8" if name.endswith((".txt", ".log", ".csv", ".py", ".md")) else "application/octet-stream"
        self.send(200, data, ctype, head, [("Content-Disposition", 'inline; filename="%s"' % name)])

    def do_GET(self):  self.handle_any(False)
    def do_HEAD(self): self.handle_any(True)

    def log_message(self, fmt, *a):
        print("%s - %s" % (self.client_address[0], fmt % a), flush=True)

http.server.ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()

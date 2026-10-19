import http.server

def flag():
    # Mounted by the platform. Permissions come from flag_mode in challenge.yml.
    with open("/run/secrets/flag") as f:
        return f.read().strip()

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"replace me\n")

http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()

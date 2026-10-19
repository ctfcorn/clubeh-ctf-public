import http.server

def flag():
    with open("/run/secrets/flag") as f:
        return f.read().strip()

# The flag lives in an HTML comment. A browser never renders a comment, so the
# page looks empty-handed - but every byte the server sends is in "View Source".
PAGE = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>club.eh :: Staff Portal</title>
</head>
<body>
  <h1>Staff Portal</h1>
  <p>Access restricted to internal staff.</p>
  <p>If you believe you should have access, contact IT.</p>

  <!--
    dev note: temporary bypass code for testing, REMOVE BEFORE LAUNCH
    %s
  -->
</body>
</html>
"""

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = (PAGE % flag()).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *a):
        print("%s - %s" % (self.client_address[0], fmt % a), flush=True)

http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()

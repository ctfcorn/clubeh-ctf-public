import os, socketserver

# ctfd-whale injects the per-instance flag as FLAG. Take it, then remove it:
# after this line `cat /proc/1/environ` shows nothing useful.
FLAG = os.environ.pop("FLAG", "clubeh{no_flag_injected}")
PASSWORD = "open-sesame"

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"Password: ")
        guess = self.rfile.readline(256).strip().decode(errors="ignore")
        if guess == PASSWORD:
            self.wfile.write(("Welcome. " + FLAG + "\n").encode())
        else:
            self.wfile.write(b"No.\n")

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

Server(("0.0.0.0", 9000), Handler).serve_forever()

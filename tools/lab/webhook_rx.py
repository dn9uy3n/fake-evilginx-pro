#!/usr/bin/env python3
# webhook_rx.py — lab receiver: ghi mọi POST JSON vào webhook_rx.log (evidence)
import http.server
import os
import datetime

LOG = os.path.expanduser("~") + "/evilginx2-lab/webhook_rx.log"

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode()
        with open(LOG, "a") as f:
            f.write("[%s] %s\n" % (datetime.datetime.now().strftime("%H:%M:%S"), body))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass

http.server.HTTPServer(("127.0.0.1", 9090), H).serve_forever()

#!/usr/bin/env python3
# testsite.py — lab ORIGIN server: HTTPS login site on 127.0.0.2:443
# Owned-by-us test asset for evilginx2 reverse-proxy demo. Not a real service.
import http.server
import os
import ssl
import urllib.parse
import secrets
import datetime

HOST, PORT = "127.0.0.2", 443
BASE = os.path.expanduser("~") + "/evilginx2-lab"
LOG = BASE + "/testsite.log"
USERS = {"labuser": "labpass123"}
SESSIONS = {}

LOGIN_PAGE = """<html><head><title>Corp Login</title></head><body>
<h1>Corp Login (LAB ORIGIN)</h1>
<form method="POST" action="/login">
<input name="username" placeholder="Username"><br>
<input name="password" type="password" placeholder="Password"><br>
<button type="submit">Sign in</button>
</form></body></html>"""


def log(msg):
    with open(LOG, "a") as f:
        f.write("[%s] %s\n" % (datetime.datetime.now().strftime("%H:%M:%S"), msg))


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body, headers=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, loc, extra=None):
        h = {"Location": loc}
        h.update(extra or {})
        self._send(302, "", h)

    def _cookie(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "LABSESS":
                return v
        return ""

    def do_GET(self):
        log("GET %s cookies=%s ua=%s" % (self.path, self.headers.get("Cookie", "-"),
                                         self.headers.get("User-Agent", "-")))
        if self.path.startswith("/portal"):
            user = SESSIONS.get(self._cookie())
            if not user:
                self._redirect("/login")
                return
            self._send(200, "<html><body><h1>Corp Portal</h1>"
                            "<p>Logged in as <b>%s</b></p></body></html>" % user)
        elif self.path.startswith("/login"):
            self._send(200, LOGIN_PAGE)
        else:
            self._redirect("/login")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(n).decode())
        u = form.get("username", [""])[0]
        p = form.get("password", [""])[0]
        log("POST %s user=%s pass=%s" % (self.path, u, p))
        if self.path.startswith("/login") and USERS.get(u) == p:
            sid = secrets.token_hex(16)
            SESSIONS[sid] = u
            # redirect via /login + email query so #10 outbound query rewrite
            # (origin email= -> victim u=) can be observed in Location
            self._redirect("/login?done=1&email=" + urllib.parse.quote(u),
                           {"Set-Cookie": "LABSESS=%s; Path=/; HttpOnly" % sid})
        else:
            self._send(200, LOGIN_PAGE + "<p>Invalid credentials</p>")

    def log_message(self, *a):
        pass


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(BASE + "/certs/portal.crt", BASE + "/certs/portal.key")
srv = http.server.ThreadingHTTPServer((HOST, PORT), Handler)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
log("test site (lab origin) started on https://%s:%d" % (HOST, PORT))
srv.serve_forever()

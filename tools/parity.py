#!/usr/bin/env python3
"""tools/parity.py — phần chạy TRONG container của phép kiểm chứng khớp (gọi qua tools/parity.sh, không chạy tay).

Lệnh con:
  sample   chọn mẫu từ eval/data/normalized + sinh tập luật dò            (không cần mạng)
  replay   gửi lại NGUYÊN VĂN các request mẫu tới 10.10.10.10               (external_net)
  collect  lấy bản ghi Elasticsearch của các request đã gửi                 (monitor_net)
  compare  so sánh: bản ghi ES ↔ bản ghi chuẩn hoá; luật dò ModSecurity thật ↔ bộ mô phỏng; in Markdown
"""
import argparse, base64, gzip, http.client, json, os, random, re, sys, time, urllib.request
from collections import Counter, defaultdict

sys.path.insert(0, "/svc")            # services/ của dự án (mount chỉ đọc)
TARGET = os.getenv("BENCH_TARGET", "10.10.10.10")
ES_URL = os.getenv("ES_URL", "http://elasticsearch:9200").rstrip("/")
MARK = "nsm-replay"
PROBE_BASE = 9990001


def note(m):
    print(m, file=sys.stderr, flush=True)


def jl_read(p):
    op = gzip.open if p.endswith(".gz") else open
    with op(p, "rt", encoding="utf-8") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


def jl_write(rows):
    for r in rows:
        print(json.dumps(r, ensure_ascii=True))


# ------------------------------------------------------------------ sample
SENDABLE = re.compile(r"^/[\x21-\x7e]*$")       # http.client từ chối khoảng trắng/ký tự điều khiển trong URL


def sendable(r):
    if r["method"] not in ("GET", "POST"):
        return False
    url = r["path"] + ("?" + r["query"] if r["query"] else "")
    return bool(SENDABLE.match(url)) and len(url) < 6000 and len(r.get("body") or "") < 60000


def cmd_sample(a):
    import secrule as S
    import rulegen_ml as M
    rng = random.Random(a.seed)
    rows, skipped = [], Counter()
    for src in a.sources.split(","):
        p = os.path.join("/eval/data/normalized", f"{src}.jsonl.gz")
        if not os.path.exists(p):
            note(f"   (bỏ qua {src}: chưa chuẩn hoá)"); continue
        allr = jl_read(p)
        ok = [r for r in allr if "error" not in r and sendable(r)]
        skipped[src] = len(allr) - len(ok)
        by = defaultdict(list)
        for r in ok:
            by[(r["ds_class"], bool(r.get("body")), r["method"])].append(r)
        k = max(1, a.per_source // max(1, len(by)))
        pick = []
        for key in sorted(by):
            pick += rng.sample(by[key], min(k, len(by[key])))
        rest = [r for r in ok if r not in pick] if len(pick) < a.per_source else []
        pick += rng.sample(rest, min(a.per_source - len(pick), len(rest))) if rest else []
        rows += pick
    for i, r in enumerate(rows):
        r["rid"] = i
    note(f"   mẫu: {len(rows)} request; không gửi được (phương thức lạ/ký tự lạ trong URL): {dict(skipped)}")

    # tập luật dò: luật G2n sinh từ phần train + luật cố định phủ đủ phép biến đổi/toán tử/đích
    train = []
    for src in ("seclists", "openappsec_mal"):
        p = os.path.join("/eval/data/normalized", f"{src}.jsonl.gz")
        if os.path.exists(p):
            train += [r for r in jl_read(p) if r.get("split") == "train" and r["ds_class"] in S.CLASSES
                      and r.get("marg_v")]
    probes = []
    if train:
        rng.shuffle(train)
        # lành tính để kiểm chứng: giá trị THẬT từ phần train của openappsec Legitimate (không lấy phần kiểm tra)
        bvals = ["submit"]
        p_leg = os.path.join("/eval/data/normalized", "openappsec_legit.jsonl.gz")
        if os.path.exists(p_leg):
            with gzip.open(p_leg, "rt", encoding="utf-8") as f:
                for ln in f:
                    r = json.loads(ln)
                    if r.get("split") == "train":
                        bvals += [v for v in r.get("marg_v") or [] if v]
                    if len(bvals) >= 20000:
                        break
        benign = M.Benign(bvals, "", 0)
        prior = M.TokenPrior({c: [max(r["marg_v"], key=len) for r in train if r["ds_class"] == c][:400] for c in S.CLASSES},
                             benign)
        samples = [{"cls": r["ds_class"], "ip": "x", "args": list(zip(r["marg_n"], r["marg_v"]))} for r in train[:600]]
        for spec, _, _ in M.generate_g2(samples, benign, prior, cluster="label", max_rules=4):
            probes.append(dict(spec, target="ARGS", g2n=True))  # đích ARGS để dò được mọi tên tham số
    # luật cố định phủ đủ toán tử (@contains / @rx nhiều token có \b) và mọi phép biến đổi; token phải qua kiểm tra tĩnh
    fixed = [("sqli", "seq", ["union", "select"]), ("sqli", "contains", ["' or"]), ("xss", "contains", ["<script"]),
             ("xss", "seq", ["onerror", "alert("]), ("lfi", "contains", ["../../"]), ("lfi", "contains", ["etc/passwd"]),
             ("rce", "seq", ["/bin/", "cat"]), ("rce", "contains", ["$(echo"]), ("sqli", "contains", ["%27"]),
             ("xss", "contains", ["&lt;"]), ("lfi", "contains", ["/etc/"]), ("rce", "seq", ["echo", "|"])]
    for cls, op, toks in fixed:
        probes.append({"class": cls, "target": "ARGS", "transforms": list(S.PROFILE[cls]), "op": op,
                       "tokens": toks, "max_gap": 40})
        probes.append({"class": cls, "target": "ARGS", "transforms": list(S.BASE), "op": op, "tokens": toks,
                       "max_gap": 40})
    good = []
    for sp in probes:
        ok, why = S.static_check(sp)
        if ok:
            good.append(sp)
        else:
            note(f"   (bỏ luật dò không qua kiểm tra tĩnh: {why} {sp['tokens']!r})")
    for i, sp in enumerate(good):
        sp["pid"] = PROBE_BASE + i
    conf = ["# luật dò của tools/parity.sh — CHỈ ghi nhận, không chặn; tự gỡ khi kết thúc",
            f'SecRule REQUEST_HEADERS:User-Agent "@contains {MARK}/" '
            f'"id:{PROBE_BASE - 1},phase:1,pass,nolog,ctl:auditEngine=On"']
    conf += [S.render(sp, sp["pid"], "shadow") for sp in good]
    with open(a.conf, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(conf) + "\n")
    with open(a.probes, "w", encoding="utf-8") as f:
        json.dump(good, f)
    note(f"   luật dò: {len(good)} (gồm {sum(1 for sp in good if sp.get('g2n'))} luật do G2n sinh)")
    jl_write(rows)


# ------------------------------------------------------------------ replay
def cmd_replay(a):
    rows = jl_read(a.input)
    out, gates = [], Counter()
    for r in rows:
        ua = f"{r.get('ua') or 'Mozilla/5.0'} {MARK}/{a.run}/{r['rid']}"
        headers = {"User-Agent": ua, "Accept": "*/*", "Connection": "close"}
        body = None
        if r["method"] == "POST" or r.get("body"):         # có cả GET mang thân (SR-BH); ModSecurity vẫn đọc thân
            body = (r.get("body") or "").encode("utf-8", "surrogateescape")
            if r.get("ct"):
                headers["Content-Type"] = r["ct"]
        url = r["path"] + ("?" + r["query"] if r["query"] else "")
        st, err = 0, None
        try:
            c = http.client.HTTPConnection(TARGET, 80, timeout=10)
            c.putrequest(r["method"], url, skip_accept_encoding=True)
            for k, v in headers.items():
                c.putheader(k, v.encode("latin-1", "replace").decode("latin-1"))
            if body is not None:
                c.putheader("Content-Length", str(len(body)))
            c.endheaders(body)
            resp = c.getresponse(); data = resp.read(); st = resp.status; c.close()
            gate = "gate1" if st == 403 and b"<center>nginx</center>" in data else ("gate2" if st == 403 else "pass")
        except Exception as e:                   # noqa: BLE001
            gate, err = "error", f"{type(e).__name__}: {e}"[:120]
        gates[gate] += 1
        out.append({"rid": r["rid"], "status": st, "gate": gate, "err": err, "t": time.time()})
        time.sleep(a.gap)
    note(f"   đã gửi {len(out)} request: {dict(gates)}")
    jl_write(out)


# ------------------------------------------------------------------ collect
def es(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    rq = urllib.request.Request(ES_URL + path, data=data, method=method, headers={"Content-Type": "application/json"})
    if os.getenv("ES_USER"):
        cred = f"{os.getenv('ES_USER')}:{os.getenv('ES_PASSWORD', '')}".encode()
        rq.add_header("Authorization", "Basic " + base64.b64encode(cred).decode())
    with urllib.request.urlopen(rq, timeout=60) as r:
        return json.loads(r.read())


def cmd_collect(a):
    sent = jl_read(a.input)
    want = {s["rid"] for s in sent if s["gate"] in ("pass", "gate2")}
    rx = re.compile(re.escape(f"{MARK}/{a.run}/") + r"(\d+)")
    found, t0, last, last_n = {}, time.time(), time.time(), -1
    fields = ["ua", "label", "tier", "confidence", "target", "arg_n", "arg_v", "marg_n", "marg_v", "marg_body", "status",
              "waf_blocked", "has_body"]
    while True:
        try:
            q = {"size": 10000, "_source": fields,
                 "query": {"bool": {"filter": [{"term": {"source.keyword": "web"}},
                                               {"match_phrase": {"ua": f"{MARK}/{a.run}"}}]}}}
            hits = es("POST", "/web-events-*/_search?ignore_unavailable=true", q)["hits"]["hits"]
        except Exception as e:                   # noqa: BLE001
            note(f"   (ES chưa trả lời: {e})"); hits = []
        for h in hits:
            m = rx.search(h["_source"].get("ua") or "")
            if m:
                found[int(m.group(1))] = h["_source"]
        n = len(want & set(found))
        if n != last_n:
            last_n, last = n, time.time()
        if n >= len(want) or time.time() - last > 40 or time.time() - t0 > 240:
            break
        time.sleep(3)
    note(f"   Elasticsearch: tìm thấy {n}/{len(want)} bản ghi")
    jl_write([dict(v, rid=k) for k, v in sorted(found.items())])


# ------------------------------------------------------------------ compare
def cmd_compare(a):
    import secrule as S
    base = "/out"
    sample = {r["rid"]: r for r in jl_read(f"{base}/sample.jsonl")}
    sent = {r["rid"]: r for r in jl_read(f"{base}/sent.jsonl")}
    esd = {r["rid"]: r for r in jl_read(f"{base}/es.jsonl")}
    probes = json.load(open(f"{base}/probes.json", encoding="utf-8"))
    pid2 = {p["pid"]: p for p in probes}
    # nhật ký kiểm toán: rid -> tập id luật dò đã khớp (ModSecurity thật)
    rx_rid = re.compile(re.escape(f"{MARK}/{a.run}/") + r"(\d+)")
    rx_id = re.compile(r'\[id "(\d+)"\]')
    real = {}
    for ln in open(f"{base}/audit.jsonl", encoding="utf-8", errors="replace"):
        m = rx_rid.search(ln)
        if not m:
            continue
        try:                                     # mã luật nằm trong chuỗi message đã thoát JSON -> phải giải mã trước
            msgs = (json.loads(ln).get("audit_data") or {}).get("messages") or []
        except ValueError:
            msgs = [ln]
        ids = {int(x) for msg in msgs for x in rx_id.findall(str(msg)) if int(x) in pid2}
        real.setdefault(int(m.group(1)), set()).update(ids)

    L = [f"# Kiểm chứng khớp giữa dữ liệu chuẩn hoá và hệ thống thật — lượt {a.run}", ""]
    reached = [rid for rid, s in sent.items() if s["gate"] in ("pass", "gate2")]
    L.append(f"Mẫu: {len(sample)} request ({dict(Counter(r['source'] for r in sample.values()))}). "
             f"Gửi: {dict(Counter(s['gate'] for s in sent.values()))}.")
    L.append("")

    # 1) bản ghi ES ↔ chuẩn hoá
    fields = ("arg_n", "arg_v", "marg_n", "marg_v", "marg_body", "label", "tier")
    miss = [rid for rid in reached if rid not in esd]
    diff = Counter(); ex = defaultdict(list)
    for rid in reached:
        if rid not in esd:
            continue
        e, o = esd[rid], sample[rid]
        for f in fields:
            if e.get(f) != o.get(f):
                diff[f] += 1
                if len(ex[f]) < 4:
                    ex[f].append((o["source"], o["method"], (o["path"] + "?" + o["query"])[:90], o.get(f), e.get(f)))
    n_cmp = len(reached) - len(miss)
    L += ["## 1. Bản ghi Elasticsearch so với bản ghi chuẩn hoá", "",
          f"So được {n_cmp} request (thiếu trong ES: {len(miss)}).", "",
          "| Trường | Khác nhau | Tỷ lệ |", "|---|---|---|"]
    for f in fields:
        L.append(f"| `{f}` | {diff[f]} | {100 * diff[f] / max(n_cmp, 1):.2f} % |".replace(".", ","))
    L.append("")
    for f in fields:
        for src, m, url, ov, ev in ex[f]:
            L.append(f"- `{f}` — {src} {m} `{url}`: chuẩn hoá `{str(ov)[:80]}` / thật `{str(ev)[:80]}`")
    L.append("")

    # 2) luật dò: ModSecurity thật ↔ mô phỏng
    logged = [rid for rid in reached if rid in real]
    tp = fp = fn = tn = 0; mism = []; n_bad = 0
    per_probe = Counter()
    for rid in logged:
        o = sample[rid]
        args = list(zip(o.get("marg_n") or [], o.get("marg_v") or []))
        pred = {p["pid"] for p in probes if S.matches(p, args)}
        act = real[rid]
        for pid in pid2:
            a_, p_ = pid in act, pid in pred
            if a_ and p_: tp += 1
            elif p_ and not a_: fp += 1; per_probe[pid] += 1
            elif a_ and not p_: fn += 1; per_probe[pid] += 1
            else: tn += 1
        if act != pred:
            n_bad += 1
        if act != pred and len(mism) < 12:
            mism.append((o["source"], (o["path"] + "?" + o["query"])[:100], (o.get("body") or "")[:60],
                         sorted(pred - act), sorted(act - pred)))
    tot = tp + fp + fn + tn
    L += ["## 2. Luật dò: ModSecurity thật so với bộ mô phỏng", "",
          f"{len(probes)} luật dò × {len(logged)} request có trong nhật ký kiểm toán "
          f"(thiếu nhật ký: {len(reached) - len(logged)}).", "",
          "| | Mô phỏng: khớp | Mô phỏng: không khớp |", "|---|---|---|",
          f"| **Thật: khớp** | {tp} | {fn} |", f"| **Thật: không khớp** | {fp} | {tn} |", "",
          f"Tỷ lệ cặp (luật, request) lệch nhau: **{100 * (fp + fn) / max(tot, 1):.3f} %**; "
          f"request có ít nhất một luật lệch: {n_bad}/{len(logged)}.", ""]
    if per_probe:
        L.append("Luật dò hay lệch nhất:")
        L.append("")
        for pid, k in per_probe.most_common(8):
            p = pid2[pid]
            L.append(f"- {pid}: {p['class']} {p['op']} {p['tokens']!r} biến đổi {','.join(p['transforms'])} — lệch {k} lần")
        L.append("")
    if mism:
        L.append("Ví dụ request lệch (mô phỏng thừa / mô phỏng thiếu):")
        L.append("")
        for src, url, body, extra, lack in mism:
            L.append(f"- {src} `{url}` thân `{body}`: thừa {extra}, thiếu {lack}")
        L.append("")
    print("\n".join(L))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="manual")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("sample"); p.add_argument("--sources", default="seclists,openappsec_mal,httpparams,srbh2020,openappsec_legit")
    p.add_argument("--per-source", type=int, default=400); p.add_argument("--seed", type=int, default=7)
    p.add_argument("--conf", required=True); p.add_argument("--probes", required=True)
    p = sub.add_parser("replay"); p.add_argument("--input", required=True); p.add_argument("--gap", type=float, default=0.02)
    p = sub.add_parser("collect"); p.add_argument("--input", required=True)
    sub.add_parser("compare")
    a = ap.parse_args()
    {"sample": cmd_sample, "replay": cmd_replay, "collect": cmd_collect, "compare": cmd_compare}[a.cmd](a)


if __name__ == "__main__":
    main()

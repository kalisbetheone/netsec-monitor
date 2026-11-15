#!/usr/bin/env python3
"""tools/t2test.py — tính BA SỐ ĐO của bộ thử "CRS và regex tầng 1 đều bỏ lọt" cho tầng 2 (tiêu chí ghi trong
eval/PROTOCOL.md ngày 15/11/2026, trước khi đo). Chỉ ĐỌC kết quả đã có; không gửi request, không đụng hệ thống.

  python -X utf8 -B tools/t2test.py <thư mục kết quả kịch bản 44> [--out <tệp .md>]

Đầu vào:
  scenarios/tang-2/bo-thu.jsonl      bộ thử đã cố định: {id, value, cls, part: gieo|giu_lai, loc: [thư mục lượt lọc, chỉ số i]}
  scenarios/tang-2/gieo-{a,b,c}.jsonl, giu-lai.jsonl, doi-chung.jsonl   tệp payload của từng tác nhân (thứ tự gửi)
  eval/results/<lượt lọc>/<kịch bản lọc>/{runs.jsonl, obs.json}         lần gửi ĐẦU của mỗi payload (rulegen dừng)
  <thư mục kết quả kịch bản 44>/44-chi-tang-2-thay/{runs.jsonl, obs.json}
Số đo 1: tỷ lệ payload của cả bộ được classifier gắn nhãn tấn công ở lần gửi đầu (lượt lọc).
Số đo 2: tỷ lệ payload phần giữ lại bị Cổng 2 trả 403 ở pha kiểm chứng; và request đối chứng bị luật tự sinh chặn.
Số đo 3: thời gian từ payload đầu của một lớp tới lần đầu một request phần gieo của lớp đó bị 403; số request đã lọt.
Lớp có dưới 8 payload chỉ tính vào số đo 1.
"""
import argparse, json, math, os, sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TD = os.path.join(ROOT, "scenarios", "tang-2")
SCN = "44-chi-tang-2-thay"
MIN_CLASS = 8


def jl(p):
    with open(p, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()


def wilson(k, n, z=1.96):
    if n == 0: return (0.0, 0.0)
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def pct(k, n):
    return f"{k}/{n} ({100.0 * k / n:.1f} %)" if n else "0/0"


def align(rdir, scn, actor, ipn=0):
    """Ghép từng request của một tác nhân (runs.jsonl) với sự kiện web của nó trong Elasticsearch (obs.json), theo thứ tự
    thời gian của cùng IP. Kiểm chặt: cùng số lượng và cùng dãy mã phản hồi; lệch thì dừng (không đoán)."""
    d = os.path.join(rdir, scn)
    runs = [r for r in jl(os.path.join(d, "runs.jsonl")) if r.get("actor") == actor]
    runs.sort(key=lambda r: r["ip"])
    r = runs[ipn]
    sent = [x for x in r["sent"] if x["gate"] != "error"]
    obs = json.load(open(os.path.join(d, "obs.json"), encoding="utf-8"))
    wj = os.path.join(d, "web.json")          # đọc đủ bằng `tools/t2test.sh fetch` (obs.json bị giới hạn 10 000 bản ghi mọi nguồn)
    web = json.load(open(wj, encoding="utf-8")) if os.path.exists(wj) else obs["web"]
    tag = f"/{scn}/{actor}"
    ev = [e for e in web if e.get("src_ip") == r["ip"] and e.get("source", "web") == "web" and str(e.get("ua", "")).endswith(tag)]
    ev.sort(key=lambda e: e["@timestamp"])
    if len(ev) != len(sent) or [e.get("status") for e in ev] != [x["status"] for x in sent]:
        raise SystemExit(f"!! không ghép được request với sự kiện: {scn} tác nhân {actor} IP {r['ip']}: "
                         f"{len(sent)} request, {len(ev)} sự kiện")
    return r, [dict(x, label=e.get("label"), tier=e.get("tier"), matched=e.get("matched")) for x, e in zip(sent, ev)], obs


def fetch(d):
    """Chạy TRONG container (mạng giám sát): đọc MỌI sự kiện web (source = web) của các IP tác nhân trong khoảng thời gian
    của kịch bản, phân trang bằng search_after, ghi <d>/web.json. Chỉ đọc Elasticsearch."""
    import base64, urllib.request
    runs = jl(os.path.join(d, "runs.jsonl"))
    ips = sorted({r["ip"] for r in runs})
    t0 = min(r["t_start"] for r in runs) - 5; t1 = max(r.get("t_end", r["t_start"]) for r in runs) + 180
    iso = lambda t: datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    out, after = [], None
    while True:
        body = {"size": 5000, "_source": ["@timestamp", "src_ip", "source", "label", "tier", "status", "ua", "matched", "weighted", "t2_label"],
                "query": {"bool": {"filter": [{"terms": {"src_ip.keyword": ips}}, {"term": {"source.keyword": "web"}},
                                              {"range": {"@timestamp": {"gte": iso(t0), "lte": iso(t1)}}}]}},
                "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}]}
        if after: body["search_after"] = after
        rq = urllib.request.Request(os.getenv("ES_URL", "http://elasticsearch:9200") + "/web-events-*/_search?ignore_unavailable=true",
                                    data=json.dumps(body).encode(), method="POST", headers={"Content-Type": "application/json"})
        cred = f"{os.getenv('ES_USER', 'elastic')}:{os.getenv('ES_PASSWORD', '')}".encode()
        rq.add_header("Authorization", "Basic " + base64.b64encode(cred).decode())
        with urllib.request.urlopen(rq, timeout=120) as r:
            hits = json.loads(r.read())["hits"]["hits"]
        if not hits: break
        out += [h["_source"] for h in hits]; after = hits[-1]["sort"]
    with open(os.path.join(d, "web.json"), "w", encoding="utf-8") as f: json.dump(out, f, ensure_ascii=False)
    print(f"web.json: {len(out)} sự kiện web của {len(ips)} IP")


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "fetch":
        return fetch(sys.argv[2])
    ap = argparse.ArgumentParser()
    ap.add_argument("rdir"); ap.add_argument("--out")
    a = ap.parse_args()
    bo = jl(os.path.join(TD, "bo-thu.jsonl"))
    byid = {p["id"]: p for p in bo}
    cls_n = Counter(p["cls"] for p in bo)
    big = sorted(c for c, n in cls_n.items() if n >= MIN_CLASS)
    L = []
    w = L.append
    w("# Bộ thử tầng 2: payload mà CRS và regex tầng 1 đều bỏ lọt — ba số đo\n")
    w("Sinh bởi `tools/t2test.py`. Mọi request là lưu lượng thử gửi vào hệ thống của dự án. Tiêu chí và ngưỡng: `eval/PROTOCOL.md`.\n")
    w(f"Bộ thử: {len(bo)} payload — " + ", ".join(f"{c} {cls_n[c]}" for c in sorted(cls_n)) +
      f". Phần gieo {sum(p['part'] == 'gieo' for p in bo)}, phần giữ lại {sum(p['part'] == 'giu_lai' for p in bo)}. "
      f"Lớp đủ {MIN_CLASS} payload (tính cả ba số đo): {', '.join(big) or 'không có'}.\n")

    # ---------- số đo 1: lần gửi đầu (lượt lọc, rulegen dừng) ----------
    cache = {}
    lab = {}
    for p in bo:
        rd, scn, i = p["loc"]
        if (rd, scn) not in cache:
            cache[(rd, scn)] = {x["i"]: x for x in align(os.path.join(ROOT, "eval", "results", rd), scn, 0)[1]}
        x = cache[(rd, scn)][i]
        if x["gate"] != "pass":
            raise SystemExit(f"!! payload {p['id']} không đi qua Cổng 2 ở lượt lọc")
        lab[p["id"]] = x
    flagged = {i: (x["label"] not in (None, "benign")) for i, x in lab.items()}
    k1, n1 = sum(flagged.values()), len(bo)
    lo, hi = wilson(k1, n1)
    w("## Số đo 1 — tỷ lệ gắn nhãn (lần gửi đầu, không có luật tự sinh)\n")
    w("| Lớp | Được gắn nhãn tấn công | Tầng gắn nhãn | Nhãn đúng lớp |")
    w("|---|---|---|---|")
    for c in sorted(cls_n):
        ids = [p["id"] for p in bo if p["cls"] == c]
        fl = [i for i in ids if flagged[i]]
        tiers = Counter(str(lab[i]["tier"]) for i in fl)
        same = sum(1 for i in fl if lab[i]["label"] == c)
        w(f"| {c} | {pct(len(fl), len(ids))} | {', '.join(f'tầng {t}: {n}' for t, n in sorted(tiers.items())) or '—'} | {same}/{len(fl)} |")
    w(f"| **Cả bộ** | **{pct(k1, n1)}**; Wilson 95 %: {100 * lo:.1f}–{100 * hi:.1f} % | | |")
    ok1 = n1 > 0 and k1 / n1 >= 0.60
    w(f"\nNgưỡng ≥ 60 %: **{'ĐẠT' if ok1 else 'KHÔNG ĐẠT'}**.\n")
    w("Payload KHÔNG được gắn nhãn:\n")
    for p in bo:
        if not flagged[p["id"]]:
            w(f"- `{p['cls']}` #{p['id']}: `{p['value'][:110]}`")
    w("")

    # ---------- kịch bản 44 ----------
    seeds = []
    for k, name in enumerate(("a", "b", "c")):
        order = jl(os.path.join(TD, f"gieo-{name}.jsonl"))
        r, xs, obs = align(a.rdir, SCN, k)
        for x in xs:
            p = order[x["i"] % len(order)]
            seeds.append(dict(x, pid=p["id"], cls=p["cls"], ip=r["ip"], rnd=x["i"] // len(order)))
    rules = obs.get("rules") or []
    t_first_rule = min([float(r.get("active_since") or r.get("since")) for r in rules if r.get("active_since") or r.get("since")], default=None)
    t_start = min(x["t"] for x in seeds)
    w("## Luật tự sinh trong kịch bản 44\n")
    if rules:
        w("| Mã | Lớp | Đích | Nội dung | Bằng chứng | Số mẫu / số IP | Có hiệu lực sau (s) | Trạng thái |")
        w("|---|---|---|---|---|---|---|---|")
        for r in sorted(rules, key=lambda r: r.get("since") or 0):
            t = r.get("active_since") or r.get("since")
            w(f"| {r.get('id')} | {r.get('class')} | {r.get('target')} | `{str(r.get('token'))[:90]}` | {r.get('evidence')} | "
              f"{r.get('cluster_size')} / {r.get('sources')} | {float(t) - t_start:.0f} | {r.get('state')} |")
    else:
        w("Không có luật tự sinh nào được ban hành.")
    w("")
    # đối chiếu: nhãn ở vòng gieo đầu của IP thứ nhất
    first = [x for x in seeds if x["rnd"] == 0 and x["ip"] == seeds[0]["ip"]]
    kf = sum(1 for x in first if x["label"] not in (None, "benign"))
    w(f"Đối chiếu số đo 1 trong kịch bản 44 (vòng gieo đầu của IP thứ nhất, chỉ phần gieo): {pct(kf, len(first))} được gắn nhãn.\n")

    # ---------- số đo 2: phần giữ lại + đối chứng ----------
    hold = jl(os.path.join(TD, "giu-lai.jsonl"))
    r, xs, _ = align(a.rdir, SCN, 4)
    hv = [dict(x, pid=hold[x["i"] % len(hold)]["id"], cls=hold[x["i"] % len(hold)]["cls"]) for x in xs]
    w("## Số đo 2 — phần giữ lại bị luật tự sinh chặn (pha kiểm chứng, IP mới)\n")
    w("| Lớp | Phần giữ lại bị Cổng 2 chặn (403) | Tính vào ngưỡng |")
    w("|---|---|---|")
    kb = nb = 0
    for c in sorted({x["cls"] for x in hv}):
        ys = [x for x in hv if x["cls"] == c]
        b = sum(1 for x in ys if x["gate"] == "gate2")
        w(f"| {c} | {pct(b, len(ys))} | {'có' if c in big else f'không (lớp dưới {MIN_CLASS} payload)'} |")
        if c in big: kb += b; nb += len(ys)
    ball = sum(1 for x in hv if x["gate"] == "gate2")
    w(f"| **Các lớp tính vào ngưỡng** | **{pct(kb, nb)}** | |")
    w(f"| Mọi lớp (tham khảo) | {pct(ball, len(hv))} | |")
    ctl = jl(os.path.join(TD, "doi-chung.jsonl"))
    cx = []
    for ipn in (0, 1):
        try: r, xs, _ = align(a.rdir, SCN, 3, ipn)
        except IndexError: break
        cx += [dict(x, pid=ctl[x["i"] % len(ctl)]["id"], ip=r["ip"]) for x in xs]
    before = defaultdict(list); after = defaultdict(list)
    for x in cx:
        (before if (t_first_rule is None or x["t"] < t_first_rule) else after)[x["pid"]].append(x["gate"])
    by_rule = sorted(pid for pid, g in after.items() if "gate2" in g and before.get(pid) and "gate2" not in before[pid])
    by_crs = sorted(pid for pid, g in before.items() if "gate2" in g)
    unk = sorted(pid for pid, g in after.items() if "gate2" in g and not before.get(pid))
    n_after = sum(len(g) for g in after.values())
    n_after_blk = sum(g.count("gate2") for pid, g in after.items() if pid in by_rule)
    w(f"\nĐối chứng (văn bản hợp lệ, cùng tham số `q`): {len(cx)} request, {len(ctl)} văn bản khác nhau; "
      f"{sum(len(g) for g in before.values())} request trước luật đầu tiên, {n_after} request sau.")
    w(f"- Văn bản bị Cổng 2 chặn từ TRƯỚC khi có luật (do CRS / luật tầng 1, không do luật tự sinh): {len(by_crs)}"
      + (": " + "; ".join(f"`{ctl[i]['value']}`" for i in by_crs) if by_crs else "") + ".")
    w(f"- Văn bản đi qua trước khi có luật nhưng bị chặn SAU khi có luật (do luật tự sinh): **{len(by_rule)}**"
      + (": " + "; ".join(f"`{ctl[i]['value']}`" for i in by_rule) + f" ({n_after_blk} request)" if by_rule else "") + ".")
    if unk:
        w(f"- Văn bản chỉ được gửi sau khi có luật và bị chặn (không phân định được): {len(unk)}: " + "; ".join(f"`{ctl[i]['value']}`" for i in unk) + ".")
    ok2 = nb > 0 and kb / nb >= 0.50 and not by_rule and not unk
    w(f"\nNgưỡng ≥ 50 % và không request đối chứng nào bị luật tự sinh chặn: **{'ĐẠT' if ok2 else 'KHÔNG ĐẠT'}**.\n")

    # ---------- số đo 3 ----------
    w("## Số đo 3 — thời gian tới khi luật có hiệu lực, và phần lọt trước đó (phần gieo)\n")
    w("| Lớp | Payload gieo | Request đầu → lần đầu bị 403 (s) | Request của lớp đã tới ứng dụng trước mốc đó | Request của lớp bị 403 sau mốc |")
    w("|---|---|---|---|---|")
    Ts = []
    for c in sorted({x["cls"] for x in seeds}):
        ys = sorted((x for x in seeds if x["cls"] == c), key=lambda x: x["t"])
        t0 = ys[0]["t"]
        blk = [x for x in ys if x["gate"] == "gate2"]
        npay = len({x["pid"] for x in ys})
        if blk:
            tb = blk[0]["t"]; T = tb - t0
            leak = sum(1 for x in ys if x["gate"] == "pass" and x["t"] < tb)
            late = sum(1 for x in ys if x["gate"] == "pass" and x["t"] >= tb)
            w(f"| {c} | {npay} | {T:.0f} | {leak} | {len(blk)} bị chặn, {late} vẫn lọt |")
            if c in big: Ts.append(T)
        else:
            w(f"| {c} | {npay} | không có luật | {sum(1 for x in ys if x['gate'] == 'pass')} (tất cả) | 0 |")
            if c in big: Ts.append(None)
    val = sorted(t for t in Ts if t is not None)
    if Ts and all(t is not None for t in Ts):
        med = val[len(val) // 2] if len(val) % 2 else (val[len(val) // 2 - 1] + val[len(val) // 2]) / 2
        ok3 = med <= 120
        w(f"\nTrung vị theo lớp (các lớp đủ {MIN_CLASS} payload): {med:.0f} s. Ngưỡng ≤ 120 s: **{'ĐẠT' if ok3 else 'KHÔNG ĐẠT'}**.\n")
    else:
        ok3 = False
        w(f"\nCó lớp đủ {MIN_CLASS} payload mà không có luật nào chặn: **KHÔNG ĐẠT** (theo quy ước ghi trước).\n")

    # ---------- quyết định ----------
    w("## Quyết định theo bảng đã ghi trước\n")
    if by_rule or unk: dec = "về `corroborate` cho tới khi bàn xong (luật tự sinh chặn request đối chứng)"
    elif not ok1: dec = "về `corroborate` (số đo 1 dưới 60 %)"
    elif ok2 and ok3: dec = "giữ `weighted` (cả ba số đo đạt)"
    else: dec = "giữ `weighted`, ghi giới hạn (số đo 1 đạt; số đo 2 hoặc 3 không đạt)"
    w(f"- Số đo 1: {'đạt' if ok1 else 'không đạt'}; số đo 2: {'đạt' if ok2 else 'không đạt'}; số đo 3: {'đạt' if ok3 else 'không đạt'}.")
    w(f"- Quyết định: **{dec}**.")
    txt = "\n".join(L) + "\n"
    out = a.out or os.path.join(a.rdir, "t2test.md")
    with open(out, "w", encoding="utf-8", newline="\n") as f: f.write(txt)
    sys.stdout.write(txt); print(">> đã ghi:", out)


if __name__ == "__main__":
    main()

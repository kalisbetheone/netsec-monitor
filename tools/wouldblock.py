#!/usr/bin/env python3
"""tools/wouldblock.py — ĐẾM QUYẾT ĐỊNH CHẶN / "SẼ CHẶN" của responder trong một khoảng thời gian, theo từng IP nguồn, và
đối chiếu với danh sách phân vai (IP nào là khách hợp lệ, IP nào là nguồn thử tấn công). Dùng cho đợt chạy thử (dryrun)
và "ngày nén". CHỈ ĐỌC Elasticsearch, không đổi gì trên hệ thống.

Chạy trong container (image nsm-classifier, mạng nsm_monitor_net) — xem lớp bọc tools/wouldblock.sh:
  wouldblock.py --t0 <epoch> [--t1 <epoch>] [--nguon nguon.json] [--out <thư mục>]

nguon.json: {"hop_le": [ip...], "phat_lai": [ip...], "tan_cong": [ip...], "thuong_tru": [ip...]}
  hop_le = khách hợp lệ của chính ứng dụng (thuong_tru cũng là hop_le) — mã thoát tính trên nhóm này;
  phat_lai = IP phát lại lưu lượng thật của website khác (ghi nhận riêng: liệt kê từng quyết định kèm số request trả 404).
Kết quả: bảng Markdown ra stdout; <thư mục>/wouldblock.json nếu có --out.
Mã thoát: 0 = không quyết định nào vào IP hợp lệ; 1 = có; 2 = lỗi (không đọc được Elasticsearch, tham số sai).
"""
import argparse, base64, json, os, sys, urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

ES_URL = os.getenv("ES_URL", "http://elasticsearch:9200").rstrip("/")
DECISIONS = ("would_block", "block")
# giờ in ra theo múi giờ của máy chủ (container không có dữ liệu múi giờ): wouldblock.sh truyền NSM_UTC_OFFSET, vd +0700
_o = os.getenv("NSM_UTC_OFFSET", "+0000")
try:
    TZ = timezone((1 if _o[0] != "-" else -1) * timedelta(hours=int(_o[1:3]), minutes=int(_o[3:5])))
except (ValueError, IndexError):
    TZ = timezone.utc


def es(path, body):
    rq = urllib.request.Request(ES_URL + path, data=json.dumps(body).encode(), method="POST",
                                headers={"Content-Type": "application/json"})
    cred = f"{os.getenv('ES_USER', 'elastic')}:{os.getenv('ES_PASSWORD') or os.getenv('ELASTIC_PASSWORD', '')}".encode()
    rq.add_header("Authorization", "Basic " + base64.b64encode(cred).decode())
    with urllib.request.urlopen(rq, timeout=60) as r:
        return json.loads(r.read())


def hhmmss(s):
    try:
        t = datetime.fromisoformat(str(s).replace("Z", "+00:00")).astimezone(TZ)
        return t.strftime("%H:%M:%S")
    except ValueError:
        return str(s)


def trange(t0, t1):
    r = {"gte": int(t0 * 1000), "format": "epoch_millis"}
    if t1:
        r["lte"] = int(t1 * 1000)
    return {"range": {"@timestamp": r}}


def decisions(t0, t1):
    """Mọi quyết định block / would_block trong khoảng thời gian (đọc theo trang, không giới hạn 10 000)."""
    out, after = [], None
    while True:
        body = {"size": 2000, "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
                "_source": ["@timestamp", "decision", "src_ip", "reason", "cls", "ttl_s", "offenses", "scope", "fp_ua",
                            "alert_source"],
                "query": {"bool": {"filter": [trange(t0, t1), {"terms": {"decision.keyword": list(DECISIONS)}}]}}}
        if after:
            body["search_after"] = after
        hits = es("/audit-decisions-*/_search?ignore_unavailable=true", body)["hits"]["hits"]
        out += [h["_source"] for h in hits]
        if len(hits) < 2000:
            return out
        after = hits[-1]["sort"]


def traffic(ips, t0, t1):
    """Lưu lượng của từng IP: số request tới được Apache (web-events), trong đó số bị Cổng 2 trả 403; số request bị Cổng 1
    từ chối theo mã (gate-events: 403 = đang bị chặn, 429 = giới hạn tốc độ; mỗi bản ghi mang trường count)."""
    st = {ip: {"web": 0, "g2_403": 0, "s404": 0, "g1_403": 0, "g1_429": 0} for ip in ips}
    if not ips:
        return st
    flt = [trange(t0, t1), {"terms": {"src_ip.keyword": sorted(ips)}}]
    try:
        r = es("/web-events-*/_search?ignore_unavailable=true", {
            "size": 0, "query": {"bool": {"filter": flt + [{"term": {"source.keyword": "web"}}]}},
            "aggs": {"ip": {"terms": {"field": "src_ip.keyword", "size": len(ips) + 10},
                            "aggs": {"s403": {"filter": {"term": {"status": 403}}},
                                     "s404": {"filter": {"term": {"status": 404}}}}}}})
        for b in r.get("aggregations", {}).get("ip", {}).get("buckets", []):
            if b["key"] in st:
                st[b["key"]].update(web=b["doc_count"], g2_403=b["s403"]["doc_count"], s404=b["s404"]["doc_count"])
    except Exception as e:                      # noqa: BLE001
        print(f"(không đọc được web-events: {e})", file=sys.stderr)
    try:
        r = es("/gate-events-*/_search?ignore_unavailable=true", {
            "size": 0, "query": {"bool": {"filter": flt}},
            "aggs": {"ip": {"terms": {"field": "src_ip.keyword", "size": len(ips) + 10},
                            "aggs": {"st": {"terms": {"field": "status", "size": 10},
                                            "aggs": {"n": {"sum": {"field": "count", "missing": 1}}}}}}}})
        for b in r.get("aggregations", {}).get("ip", {}).get("buckets", []):
            for s in b["st"]["buckets"]:
                k = {403: "g1_403", 429: "g1_429"}.get(int(s["key"]))
                if k and b["key"] in st:
                    st[b["key"]][k] = int(s["n"]["value"])
    except Exception as e:                      # noqa: BLE001
        print(f"(không đọc được gate-events: {e})", file=sys.stderr)
    return st


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--t0", type=float, required=True); ap.add_argument("--t1", type=float, default=0)
    ap.add_argument("--nguon"); ap.add_argument("--out")
    a = ap.parse_args()
    src = {"hop_le": [], "phat_lai": [], "tan_cong": [], "thuong_tru": []}
    if a.nguon:
        with open(a.nguon, encoding="utf-8") as f:
            src.update(json.load(f))
    atk = set(src["tan_cong"])
    rep = set(src["phat_lai"]) - atk
    ok = (set(src["hop_le"]) | set(src["thuong_tru"])) - atk - rep
    role = lambda ip: "tan_cong" if ip in atk else "phat_lai" if ip in rep else "hop_le" if ip in ok else "khong_ro"
    try:
        dec = decisions(a.t0, a.t1)
    except Exception as e:                      # noqa: BLE001
        print(f"!! không đọc được audit-decisions: {e}", file=sys.stderr); return 2
    by = defaultdict(list)
    for d in dec:
        by[str(d.get("src_ip"))].append(d)
    rows = []
    for ip, ds in sorted(by.items(), key=lambda kv: (role(kv[0]), kv[0])):
        rows.append({"ip": ip, "vai": role(ip), "so_quyet_dinh": len(ds),
                     "quyet_dinh": dict(Counter(d.get("decision") for d in ds)),
                     "ly_do": sorted({str(d.get("reason")) for d in ds}),
                     "lop": sorted({str(d.get("cls")) for d in ds if d.get("cls")}),
                     "ttl_s": [d.get("ttl_s") for d in ds], "offenses": [d.get("offenses")for d in ds],
                     "luc": [hhmmss(d.get("@timestamp")) for d in ds],
                     "dau_van_tay": sorted({str(d.get("fp_ua"))[:60] for d in ds if d.get("fp_ua")})})
    n_role = Counter(r["vai"] for r in rows)
    res = sorted(set(src["thuong_tru"]))
    rep_hit = [r["ip"] for r in rows if r["vai"] == "phat_lai"]
    tr_all = traffic(sorted(set(res) | set(rep_hit)), a.t0, a.t1)
    tr = {ip: tr_all[ip] for ip in res}
    rep_rows = [{"ip": r["ip"], "luc": r["luc"], "quyet_dinh": r["quyet_dinh"], "ly_do": r["ly_do"], "lop": r["lop"],
                 "ttl_s": r["ttl_s"], "so_request": tr_all[r["ip"]]["web"], "so_404": tr_all[r["ip"]]["s404"],
                 "cong_2_403": tr_all[r["ip"]]["g2_403"]} for r in rows if r["vai"] == "phat_lai"]
    result = {"t0": a.t0, "t1": a.t1 or None, "tong_quyet_dinh": len(dec), "so_ip": len(rows),
              "ip_theo_vai": dict(n_role), "ip_hop_le_bi_chan": [r["ip"] for r in rows if r["vai"] == "hop_le"],
              "ip_khong_ro_co_quyet_dinh": [r["ip"] for r in rows if r["vai"] == "khong_ro"],
              "phat_lai_co_quyet_dinh": rep_rows,
              "so_ip_khai_bao": {"hop_le": len(ok), "phat_lai": len(rep), "tan_cong": len(atk), "thuong_tru": len(res)},
              "ip": rows, "thuong_tru": tr}
    if a.out:
        os.makedirs(a.out, exist_ok=True)
        with open(os.path.join(a.out, "wouldblock.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(result, f, ensure_ascii=False, indent=1)

    P = print
    P("### Quyết định chặn / \"sẽ chặn\" của responder")
    P()
    span = datetime.fromtimestamp(a.t0, tz=TZ).strftime("%d/%m %H:%M:%S") + " → " + (
        datetime.fromtimestamp(a.t1, tz=TZ).strftime("%H:%M:%S") if a.t1 else "lúc đọc")
    P(f"Khoảng thời gian: {span}. Tổng {len(dec)} quyết định trên {len(rows)} IP. "
      f"Khai báo: {len(ok)} IP hợp lệ (trong đó {len(res)} thường trú), {len(rep)} IP phát lại lưu lượng thật, "
      f"{len(atk)} IP nguồn thử tấn công.")
    P()
    P("| Vai | Số IP có quyết định | Số quyết định |")
    P("|---|---|---|")
    for v, ten in (("hop_le", "Hợp lệ (khách của chính ứng dụng)"), ("phat_lai", "Phát lại lưu lượng thật (ghi nhận riêng)"),
                   ("tan_cong", "Nguồn thử tấn công"), ("khong_ro", "Không rõ (ngoài danh sách)")):
        P(f"| {ten} | {n_role.get(v, 0)} | {sum(r['so_quyet_dinh'] for r in rows if r['vai'] == v)} |")
    P()
    if rows:
        P("| IP | Vai | Quyết định | Lúc | Lý do | Lớp | ttl_s | Lần vi phạm |")
        P("|---|---|---|---|---|---|---|---|")
        for r in rows[:200]:
            P(f"| {r['ip']} | {r['vai']} | {', '.join(f'{k}: {v}' for k, v in r['quyet_dinh'].items())} | "
              f"{', '.join(r['luc'])} | {'; '.join(r['ly_do'])} | {', '.join(r['lop']) or '—'} | "
              f"{', '.join(str(x) for x in r['ttl_s'])} | {', '.join(str(x) for x in r['offenses'])} |")
        if len(rows) > 200:
            P(f"\n(còn {len(rows) - 200} IP nữa, xem wouldblock.json)")
        P()
    if rep_rows:
        P("### Quyết định vào IP phát lại lưu lượng thật (không tính vào kết luận)")
        P()
        P("Lưu lượng phát lại là URL của website khác gửi vào ứng dụng này nên phần lớn trả 404; khách thật của ứng dụng "
          "không tạo ra mẫu đó. Mỗi quyết định được liệt kê để xem xét.")
        P()
        P("| IP | Lúc | Quyết định | Lý do | Lớp | Request tới Apache | Trong đó trả 404 | Cổng 2 trả 403 |")
        P("|---|---|---|---|---|---|---|---|")
        for x in rep_rows:
            P(f"| {x['ip']} | {', '.join(x['luc'])} | {', '.join(f'{k}: {v}' for k, v in x['quyet_dinh'].items())} | "
              f"{'; '.join(x['ly_do'])} | {', '.join(x['lop']) or '—'} | {x['so_request']} | {x['so_404']} | {x['cong_2_403']} |")
        P()
    if res:
        P("### Khách thường trú (chạy suốt đợt thử)")
        P()
        P("| IP | Request tới Apache | Cổng 2 trả 403 | Cổng 1 trả 403 (đang bị chặn) | Cổng 1 trả 429 (giới hạn tốc độ) |")
        P("|---|---|---|---|---|")
        for ip in res:
            t = tr[ip]
            P(f"| {ip} | {t['web']} | {t['g2_403']} | {t['g1_403']} | {t['g1_429']} |")
        P()
    bad = result["ip_hop_le_bi_chan"]
    unk = [r["ip"] for r in rows if r["vai"] == "khong_ro"]
    if unk and (a.nguon):
        P(f"**Cần xem tay:** {len(unk)} IP có quyết định nhưng KHÔNG có trong danh sách phân vai: {', '.join(unk[:30])}.")
        P()
    P(f"**Kết luận:** {'KHÔNG có' if not bad else 'CÓ ' + str(len(bad))} IP hợp lệ nhận quyết định chặn / \"sẽ chặn\""
      + (": " + ", ".join(bad[:30]) if bad else "") + "."
      + (f" Ngoài ra {len(rep_rows)} IP phát lại lưu lượng thật có quyết định (liệt kê ở trên)." if rep_rows else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

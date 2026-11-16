#!/usr/bin/env python3
"""tools/alertlat.py — tính độ trễ từng khâu của đường cảnh báo từ kết quả của tools/alertlat.sh. Chỉ đọc tệp.

    python -X utf8 -B tools/alertlat.py eval/results/alertlat-<thời điểm>

Với mỗi lần thử (User-Agent `alertlat/<lượt>/<pha>/<số>`):
  t0        thời điểm Apache xử lý request (ts_ms trong nhật ký truy cập)
  truy_cap  dấu thời gian Kafka của dòng nhật ký truy cập   − t0   = Apache ghi tệp + Filebeat đọc + gửi
  kiem_toan dấu thời gian Kafka của dòng nhật ký kiểm toán  − t0   (ModSecurity ghi khi request xong; POST phải chờ dòng này)
  canh_bao  dấu thời gian Kafka của cảnh báo                − t0   = tổng tới lúc classifier phát cảnh báo
  classifier = canh_bao − (mốc muộn nhất trong các dòng mà classifier cần) = thời gian nằm trong classifier
"""
import json, os, statistics, sys


def lines(p):
    if not os.path.exists(p):
        return
    with open(p, encoding="utf-8", errors="replace") as f:
        for ln in f:
            if ln.startswith("CreateTime:") and "\t" in ln:
                ts, val = ln.rstrip("\n").split("\t", 1)
                yield int(ts.split(":", 1)[1]), val


def main():
    d = sys.argv[1]
    probes = [ln.split() for ln in open(os.path.join(d, "probes.txt"), encoding="utf-8") if ln.strip()]
    run = os.path.basename(os.path.normpath(d)).split("alertlat-", 1)[1]
    acc, aud, alr = {}, {}, {}
    for ts, val in lines(os.path.join(d, "web.logs.txt")):
        if "alertlat/" + run in val:
            try:
                e = json.loads(val)
            except ValueError:
                continue
            acc.setdefault(e.get("ua"), (ts, e))
    for ts, val in lines(os.path.join(d, "web.audit.txt")):
        i = val.find("alertlat/" + run)
        if i >= 0:
            ua = val[i:].split('"', 1)[0]
            aud.setdefault(ua, ts)
    for ts, val in lines(os.path.join(d, "alerts.txt")):
        if "alertlat/" + run in val:
            try:
                e = json.loads(val)
            except ValueError:
                continue
            alr.setdefault(e.get("ua"), (ts, e))
    rows = []
    for phase, n, method, ip, code in probes:
        ua = f"alertlat/{run}/{phase}/{n}"
        a = acc.get(ua)
        if not a:
            rows.append({"phase": phase, "n": n, "method": method, "code": code, "missing": "nhật ký truy cập"})
            continue
        t0 = a[1]["ts_ms"]
        r = {"phase": phase, "n": n, "method": method, "code": code, "truy_cap": (a[0] - t0) / 1000}
        if ua in aud:
            r["kiem_toan"] = (aud[ua] - t0) / 1000
        if ua in alr:
            r["canh_bao"] = (alr[ua][0] - t0) / 1000
            need = max(a[0], aud.get(ua, 0) if method == "POST" else 0)
            r["classifier"] = (alr[ua][0] - need) / 1000
            r["nhan"] = alr[ua][1].get("class"); r["tang"] = alr[ua][1].get("tier")
        rows.append(r)
    with open(os.path.join(d, "rows.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=1)
    f3 = lambda x: "   —  " if x is None else f"{x:6.2f}"
    print(f"lượt {run}: {len(rows)} lần thử; thiếu nhật ký truy cập: {sum('missing' in r for r in rows)}; có cảnh báo: {sum('canh_bao' in r for r in rows)}")
    print(f"{'pha':10} {'#':>2} {'mã':>4} {'truy cập':>9} {'kiểm toán':>10} {'cảnh báo':>9} {'trong classifier':>17}   (giây sau khi Apache xử lý request)")
    for r in rows:
        if "missing" in r:
            print(f"{r['phase']:10} {r['n']:>2} {r['code']:>4}   thiếu {r['missing']}"); continue
        print(f"{r['phase']:10} {r['n']:>2} {r['code']:>4} {f3(r.get('truy_cap')):>9} {f3(r.get('kiem_toan')):>10} {f3(r.get('canh_bao')):>9} {f3(r.get('classifier')):>17}")
    print("\ntóm tắt theo pha: trung vị [nhỏ nhất – lớn nhất], giây")
    for phase in dict.fromkeys(r["phase"] for r in rows):
        xs = [r for r in rows if r["phase"] == phase and "missing" not in r]
        def s(k):
            v = [r[k] for r in xs if k in r]
            return "—" if not v else f"{statistics.median(v):.2f} [{min(v):.2f} – {max(v):.2f}] (n={len(v)})"
        print(f"  {phase:10} truy cập {s('truy_cap')} | kiểm toán {s('kiem_toan')} | cảnh báo {s('canh_bao')} | trong classifier {s('classifier')}")


if __name__ == "__main__":
    main()

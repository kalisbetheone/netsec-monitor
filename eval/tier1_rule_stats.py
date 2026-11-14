#!/usr/bin/env python3
"""eval/tier1_rule_stats.py — đo TỪNG LUẬT regex tầng 1 của classifier trên dữ liệu đã chuẩn hoá (eval/data/normalized).

Với mỗi luật (chỉ các lần khớp có độ tin cậy >= 0,9 — đúng những gì dẫn tới chặn):
  fp = số request LÀNH TÍNH THẬT (openappsec Legitimate, mọi phần) mà luật khớp
  tp = số request TẤN CÔNG (SecLists, openappsec Malicious, HttpParams, SR-BH) mà luật khớp
Một request được tính cho MỌI luật khớp nó (không chỉ luật đầu tiên), nên tổng có thể lớn hơn số request.

Dùng để hiệu chỉnh độ tin cậy (D5): luật không khớp nhầm lần nào trên toàn bộ lưu lượng lành tính và có đủ lần khớp
đúng thì được coi là "rất chắc" (services/classifier.py: STRONG_RULES -> cảnh báo khoá ngay).
LƯU Ý: các luật đã từng được chỉnh sau khi xem báo nhầm trên chính tập lành tính này (PROTOCOL.md 13/11), nên fp ở đây
là số lạc quan; nó chỉ được dùng để CHỌN luật rất chắc, không dùng làm số báo nhầm của hệ thống.

Chạy từ thư mục nsm (không cần Docker):   python -X utf8 -B eval/tier1_rule_stats.py [--limit N]
Kết quả: eval/tier1_rule_stats.json
"""
import argparse, gzip, json, os, sys, time, types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "services"))
ck = types.ModuleType("confluent_kafka"); ck.Consumer = object; ck.Producer = object
sys.modules.setdefault("confluent_kafka", ck)
es_mod = types.ModuleType("elasticsearch"); es_mod.helpers = types.SimpleNamespace(); es_mod.Elasticsearch = object
sys.modules.setdefault("elasticsearch", es_mod)
os.environ.setdefault("MODEL_PATH", "/khong-nap-model")       # chỉ cần tầng 1
import classifier as C

NORM = os.path.join(ROOT, "eval", "data", "normalized")
OUT = os.path.join(ROOT, "eval", "tier1_rule_stats.json")


def rules_hit(r):
    path = C.decode_p(r["path"]).lower()
    qargs, bargs = C.split_params(r.get("query") or ""), C.body_params(r.get("body"))
    hdr = {"User-Agent": r.get("ua") or "", "Referer": None, "cookies": []}
    units = C.scan_units(path, qargs, bargs, hdr)
    out = []
    for i, (cls, p, scope) in enumerate(C.RULES_T1):
        for field, text in units:
            cap = C._in_scope(scope, field)
            if cap is not None and cap >= 0.9 and p.search(text):
                out.append(i); break
    return out


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    n = len(C.RULES_T1)
    fp, tp = [0] * n, [0] * n
    seen = {"benign": 0, "attack": 0}
    t0 = time.time()
    for src in ("openappsec_legit", "seclists", "openappsec_mal", "httpparams", "srbh2020"):
        p = os.path.join(NORM, f"{src}.jsonl.gz")
        if not os.path.exists(p):
            print("bỏ qua", src); continue
        k = 0
        with gzip.open(p, "rt", encoding="utf-8") as f:
            for ln in f:
                r = json.loads(ln)
                if "error" in r: continue
                benign = r.get("ds_class") == "benign"
                if src == "srbh2020" and benign: continue          # phần "bình thường" của SR-BH có nhãn bẩn (~10 %)
                if src == "openappsec_legit" and not benign: continue
                k += 1
                if a.limit and k > a.limit: break
                seen["benign" if benign else "attack"] += 1
                for i in rules_hit(r):
                    (fp if benign else tp)[i] += 1
        print(f"{src}: {k} dòng, {time.time() - t0:.0f} s", flush=True)
    rows = [{"i": i, "class": cls, "scope": scope, "pattern": p.pattern, "fp": fp[i], "tp": tp[i]}
            for i, (cls, p, scope) in enumerate(C.RULES_T1)]
    json.dump({"benign_requests": seen["benign"], "attack_requests": seen["attack"], "rules": rows},
              open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("đã ghi", OUT)
    for r in sorted(rows, key=lambda x: (-x["fp"], -x["tp"])):
        print(f"{r['class']:8} {r['scope']:8} fp={r['fp']:6} tp={r['tp']:6}  {r['pattern'][:70]}")


if __name__ == "__main__":
    main()

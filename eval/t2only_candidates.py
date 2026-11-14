#!/usr/bin/env python3
"""eval/t2only_candidates.py — tìm payload tấn công mà regex TẦNG 1 KHÔNG bắt nhưng model TẦNG 2 bắt (bước 1 của bộ thử
"chỉ tầng 2 thấy"). Bước 2 (tools/t2only.sh) gửi các ứng viên qua Cổng 2 thật và giữ lại những cái CRS cũng không chặn.

Nguồn: phần tấn công của HttpParams, SecLists, openappsec Malicious trong eval/data/normalized (dữ liệu công khai).
Chỉ lấy request có payload ở query hoặc thân form (tầng 2 không đọc đường dẫn). Kết quả: eval/t2only_candidates.jsonl
Chạy từ thư mục nsm:  MODEL_PATH=models/tier2.joblib TIER2_DECISION=argmax TIER2_THRESHOLD=0.67 TIER2_SYNTAX_GATE=0 \
                      TIER2_MODE=enforce python -X utf8 -B eval/t2only_candidates.py
"""
import gzip, json, os, random, sys, types, warnings
warnings.filterwarnings("ignore")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ck = types.ModuleType("confluent_kafka"); ck.Consumer = object; ck.Producer = object; sys.modules["confluent_kafka"] = ck
es = types.ModuleType("elasticsearch"); es.helpers = types.SimpleNamespace(); es.Elasticsearch = object; sys.modules["elasticsearch"] = es
sys.path.insert(0, os.path.join(ROOT, "services"))
import logging; logging.disable(logging.INFO)
import classifier as C
assert C.MODEL is not None, "chưa nạp được model tầng 2 (MODEL_PATH)"
D = os.path.join(ROOT, "eval", "data", "normalized")
out, seen = [], set()
for ds in ("httpparams", "seclists", "openappsec_mal"):
    with gzip.open(os.path.join(D, f"{ds}.jsonl.gz"), "rt", encoding="utf-8") as fh:
        for line in fh:
            d = json.loads(line)
            if d.get("ds_class") not in ("sqli", "xss", "lfi", "rce") or "error" in d: continue
            if d.get("method") not in ("GET", "POST"): continue
            q, b = d.get("query") or "", d.get("body") or ""
            if not (q or b) or len(q) + len(b) > 1500: continue
            if b and "urlencoded" not in (d.get("ct") or ""): continue
            ev = {"uri": d.get("path") or "/", "query": ("?" + q) if q else "", "body": b, "_waf_blocked": False}
            r = C.classify(C.decode_p(d.get("path") or "/").lower(), C.split_params(q), C.body_params(b), "Mozilla/5.0", ev,
                           {"User-Agent": "Mozilla/5.0"})
            if r.get("tier") != 2: continue                      # tầng 1 đã bắt, hoặc tầng 2 không bắt
            key = (q, b)
            if key in seen: continue
            seen.add(key)
            out.append({"src": ds, "cls": d["ds_class"], "t2_label": r["label"], "t2_conf": r.get("t2_conf"),
                        "method": d["method"], "query": q, "body": b, "ct": d.get("ct") or ""})
random.Random(7).shuffle(out)
p = os.path.join(ROOT, "eval", "t2only_candidates.jsonl")
with open(p, "w", encoding="utf-8", newline="\n") as f:
    for o in out: f.write(json.dumps(o, ensure_ascii=True) + "\n")
from collections import Counter
print(len(out), "ứng viên:", dict(Counter((o["src"], o["cls"]) for o in out)))

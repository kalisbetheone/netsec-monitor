"""eval/tier2_live_eval.py — đưa các tập CHƯA THẤY qua classify() HIỆN TẠI của hệ thống với một cấu hình tầng 2.

Cấu hình đặt bằng biến môi trường như trong docker-compose.yml: MODEL_PATH, TIER2_MODE, TIER2_DECISION, TIER2_THRESHOLD,
TIER2_SYNTAX_GATE. Không cần Docker. Dùng:
    MODEL_PATH=models/tier2.joblib TIER2_MODE=weighted TIER2_DECISION=argmax TIER2_THRESHOLD=0.67 TIER2_SYNTAX_GATE=0 \
        python -X utf8 -B eval/tier2_live_eval.py . eval/results/tier2-live-<nhãn>.json
Kết quả theo khoá "<tập>|<lớp thật>|<args / path_only>": n, flag (bị gắn nhãn tấn công), t2 (do tầng 2), hit (đúng lớp).
(Trước 15/11/2026 script này chỉ nằm trong thư mục tạm của một phiên làm việc.)"""
import gzip, json, os, sys, time, types, warnings
from collections import Counter, defaultdict
warnings.filterwarnings("ignore")
ROOT, OUT = sys.argv[1], sys.argv[2]
ck = types.ModuleType("confluent_kafka"); ck.Consumer = object; ck.Producer = object; sys.modules["confluent_kafka"] = ck
es = types.ModuleType("elasticsearch"); es.helpers = types.SimpleNamespace(); es.Elasticsearch = object; sys.modules["elasticsearch"] = es
sys.path.insert(0, os.path.join(ROOT, "services"))
os.environ.setdefault("INTERNAL_CIDRS", "10.10.30.0/24")
import logging; logging.disable(logging.INFO)
import classifier as C
D = os.path.join(ROOT, "eval", "data", "normalized")
st = defaultdict(Counter); lat = []; t0 = time.time()
def run(ds, keep):
    with gzip.open(os.path.join(D, f"{ds}.jsonl.gz"), "rt", encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            d = json.loads(line)
            if not keep(i, d) or d.get("ds_class") == "other": continue
            q, b = d.get("query") or "", "" if d.get("over_limit") else (d.get("body") or "")
            ev = {"uri": d.get("path") or "/", "query": ("?" + q) if q else "", "body": b, "_waf_blocked": False}
            path = C.decode_p(d.get("path") or "/").lower()
            s = time.perf_counter()
            r = C.classify(path, C.split_params(q), C.body_params(b), d.get("ua") or "", ev, {"User-Agent": d.get("ua") or ""})
            lat.append(time.perf_counter() - s)
            cls = d["ds_class"]; loc = "args" if (q or b.strip()) else "path_only"
            k = f"{ds}|{cls}|{loc}"
            st[k]["n"] += 1
            st[k]["flag"] += r["label"] not in ("benign", "uninspected")
            st[k]["t2"] += r.get("tier") == 2
            st[k]["hit"] += r["label"] == cls
run("openappsec_legit", lambda i, d: d.get("split") == "test_sites" and i % 5 == 0)
run("srbh2020", lambda i, d: True)
run("httpparams", lambda i, d: True)
run("seclists", lambda i, d: d.get("split") == "valid")
run("openappsec_mal", lambda i, d: d.get("split") == "valid")
lat.sort()
json.dump({"stats": st, "sec": round(time.time() - t0), "lat_ms_p50": round(1000 * lat[len(lat) // 2], 3),
           "lat_ms_p99": round(1000 * lat[int(len(lat) * .99)], 3),
           "env": {k: os.environ.get(k) for k in ("MODEL_PATH", "TIER2_MODE", "TIER2_DECISION", "TIER2_THRESHOLD", "TIER2_SYNTAX_GATE", "TIER2_STRUCTURED_BODY")}},
          open(OUT, "w", encoding="utf-8"), indent=1)
print("xong", OUT, round(time.time() - t0), "s")

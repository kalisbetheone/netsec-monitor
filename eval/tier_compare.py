"""So sánh độ phát hiện / báo nhầm của classifier HIỆN TẠI với nhãn đã lưu trong dữ liệu chuẩn hoá
(nhãn đó do classifier bản trước sinh: tầng 1 + tầng 2 ở chế độ enforce).

    python -X utf8 eval/tier_compare.py [--legit-every 20]

Mỗi bản ghi chuẩn hoá được đưa lại qua classify() của bản hiện tại (mặc định TIER2_MODE=observe).
Đầu ra: bảng theo dataset × lớp — tỷ lệ phát hiện (lớp tấn công) hoặc tỷ lệ báo nhầm (benign), trước và sau.
Không cần Docker: Kafka/Elasticsearch được giả lập như trong tests/test_logic.py.
"""
import argparse, gzip, json, os, sys, time, types, warnings
from collections import Counter, defaultdict

warnings.filterwarnings("ignore")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ck = types.ModuleType("confluent_kafka"); ck.Consumer = object; ck.Producer = object
sys.modules.setdefault("confluent_kafka", ck)
es = types.ModuleType("elasticsearch"); es.helpers = types.SimpleNamespace(); es.Elasticsearch = object
sys.modules.setdefault("elasticsearch", es)
sys.path.insert(0, os.path.join(ROOT, "services"))
os.environ.setdefault("MODEL_PATH", os.path.join(ROOT, "models", "tier2.joblib"))
os.environ.setdefault("INTERNAL_CIDRS", "10.10.30.0/24,10.10.10.10/32,172.16.0.0/12")
import logging; logging.disable(logging.INFO)
import classifier as C

ap = argparse.ArgumentParser()
ap.add_argument("--legit-every", type=int, default=20, help="lấy 1/N bản ghi openappsec_legit (1 triệu bản ghi)")
ap.add_argument("--out", default=None)
a = ap.parse_args()

DATA = os.path.join(ROOT, "eval", "data", "normalized")
SETS = ["seclists", "openappsec_mal", "httpparams", "srbh2020", "openappsec_legit"]
# Lưu ý khi đọc kết quả: nhãn "000 Normal" của SR-BH 2020 lẫn nhiều request tấn công rõ ràng (/etc/passwd,
# <script>, sleep(15) trong đường dẫn) — tỷ lệ "báo nhầm" trên srbh2020/benign phần lớn là nhiễu nhãn.
stat = defaultdict(lambda: Counter())
t0 = time.time()
for ds in SETS:
    f = os.path.join(DATA, f"{ds}.jsonl.gz")
    if not os.path.exists(f): continue
    with gzip.open(f, "rt", encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            if ds == "openappsec_legit" and i % a.legit_every: continue
            d = json.loads(line)
            cls = d.get("ds_class")
            if cls == "other": continue
            q, b = d.get("query") or "", d.get("body") or ""
            ev = {"uri": d.get("path") or "/", "query": ("?" + q) if q else "", "body": b}
            path = C.decode_p(d.get("path") or "/").lower()
            r = C.classify(path, C.split_params(q), C.body_params(b), d.get("ua") or "", ev,
                           {"User-Agent": d.get("ua") or ""})
            old = str(d.get("label") or "benign")
            k = (ds, cls)
            st = stat[k]
            st["n"] += 1
            st["old_flag"] += old not in ("benign", "info")
            st["new_flag"] += r["label"] not in ("benign",)
            st["new_t2"] += bool(r.get("t2_label"))
            st["new_uninspected"] += r["label"] == "uninspected"
            if cls != "benign":
                st["old_hit"] += old == cls
                st["new_hit"] += r["label"] == cls
print(f"xong trong {time.time() - t0:.0f} s")

lines = ["| Dataset | Lớp | n | Trước: gắn nhãn tấn công | Sau: gắn nhãn tấn công | Sau: tầng 2 sẽ báo (chỉ ghi nhận) |",
         "|---|---|---|---|---|---|"]
pct = lambda x, n: f"{100 * x / n:.1f} %" if n else "-"
for (ds, cls), st in sorted(stat.items()):
    lines.append(f"| {ds} | {cls} | {st['n']} | {pct(st['old_flag'], st['n'])} | {pct(st['new_flag'], st['n'])} "
                 f"| {pct(st['new_t2'], st['n'])} |")
tot = Counter()
for (ds, cls), st in stat.items():
    g = "benign" if cls == "benign" else "attack"
    for k2, v in st.items(): tot[(g, k2)] += v
lines.append("")
lines.append(f"Tổng tấn công (sqli/xss/lfi/rce): n={tot[('attack', 'n')]}, gắn nhãn tấn công trước "
             f"{pct(tot[('attack', 'old_flag')], tot[('attack', 'n')])} → sau {pct(tot[('attack', 'new_flag')], tot[('attack', 'n')])}; "
             f"đúng lớp trước {pct(tot[('attack', 'old_hit')], tot[('attack', 'n')])} → sau {pct(tot[('attack', 'new_hit')], tot[('attack', 'n')])}")
lines.append(f"Tổng lành tính: n={tot[('benign', 'n')]}, báo nhầm trước {pct(tot[('benign', 'old_flag')], tot[('benign', 'n')])} "
             f"→ sau {pct(tot[('benign', 'new_flag')], tot[('benign', 'n')])} (trong đó 'uninspected': "
             f"{pct(tot[('benign', 'new_uninspected')], tot[('benign', 'n')])})")
out = "\n".join(lines)
print(out)
if a.out:
    open(a.out, "w", encoding="utf-8").write(out + "\n")

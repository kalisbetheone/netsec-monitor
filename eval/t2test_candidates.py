#!/usr/bin/env python3
"""eval/t2test_candidates.py — ứng viên cho bộ thử "CRS và regex tầng 1 đều bỏ lọt" (bước 1), CHỌN MÀ KHÔNG NHÌN TẦNG 2.

Khác eval/t2only_candidates.py (15/11 sáng): tệp đó chỉ giữ payload mà model tầng 2 ĐÃ gắn nhãn, nên đo "tầng 2 gắn nhãn
được bao nhiêu" trên nó là vòng lặp (gần 100 % theo cách dựng). Ở đây model tầng 2 KHÔNG được nạp: chỉ loại payload mà
regex tầng 1 bắt. Bước 2 (kịch bản scenarios/tang-2/loc-cong-2.toml) gửi ứng viên qua Cổng 2 thật và giữ payload không bị chặn.

Nguồn: phần tấn công của HttpParams, SecLists, openappsec Malicious trong eval/data/normalized (dữ liệu công khai),
chỉ phần model tầng 2 CHƯA THẤY khi huấn luyện (HttpParams độc lập; SecLists / openappsec phần valid).
Chỉ lấy request có ĐÚNG MỘT tham số (query hoặc thân form); giá trị tham số đó là payload, sẽ được đặt vào  GET /index.php?q=<payload>.
Kiểm tầng 1 trên đúng dạng request đó. Lấy ngẫu nhiên (hạt giống cố định) tối đa PER_CLASS payload mỗi lớp.
Chạy từ thư mục nsm:  python -X utf8 -B eval/t2test_candidates.py     -> scenarios/tang-2/ung-vien.jsonl
Dùng cho việc đo hệ thống phòng thủ của dự án trong mạng thử nội bộ.
"""
import gzip, json, os, random, sys, types, warnings
from urllib.parse import parse_qsl, quote
warnings.filterwarnings("ignore")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ["MODEL_PATH"] = os.path.join(ROOT, "khong-co-model")       # KHÔNG nạp tầng 2: việc chọn không được nhìn nhãn của nó
os.environ["TIER2_MODE"] = "observe"
ck = types.ModuleType("confluent_kafka"); ck.Consumer = object; ck.Producer = object; sys.modules["confluent_kafka"] = ck
es = types.ModuleType("elasticsearch"); es.helpers = types.SimpleNamespace(); es.Elasticsearch = object; sys.modules["elasticsearch"] = es
sys.path.insert(0, os.path.join(ROOT, "services"))
import logging; logging.disable(logging.INFO)
import classifier as C
assert C.MODEL is None, "model tầng 2 không được nạp ở bước chọn ứng viên"
PER_CLASS = int(os.getenv("T2TEST_PER_CLASS", "75"))
SEED = 20261115
D = os.path.join(ROOT, "eval", "data", "normalized")
UA = "Mozilla/5.0"


def tier1_catches(value):
    q = "q=" + quote(value, safe="")
    ev = {"uri": "/index.php", "query": "?" + q, "body": "", "_waf_blocked": False}
    r = C.classify("/index.php", C.split_params(q), C.body_params(""), UA, ev, {"User-Agent": UA})
    return r.get("tier") == 1 or (r.get("label") not in (None, "benign"))


pool, seen, stat = {}, set(), {"doc": 0, "mot_tham_so": 0, "tang1_bat": 0}
for ds in ("httpparams", "seclists", "openappsec_mal"):
    with gzip.open(os.path.join(D, f"{ds}.jsonl.gz"), "rt", encoding="utf-8") as fh:
        for line in fh:
            d = json.loads(line)
            cls = d.get("ds_class")
            if cls not in ("sqli", "xss", "lfi", "rce") or "error" in d: continue
            if ds != "httpparams" and d.get("split") != "valid": continue
            if d.get("method") not in ("GET", "POST"): continue
            q, b = d.get("query") or "", d.get("body") or ""
            if b and "urlencoded" not in (d.get("ct") or ""): continue
            stat["doc"] += 1
            try: prm = parse_qsl(q, keep_blank_values=True) + parse_qsl(b, keep_blank_values=True)
            except ValueError: continue
            if len(prm) != 1: continue
            v = prm[0][1]
            if not (4 <= len(v) <= 400) or any(ord(c) < 32 and c not in "\t\n\r" for c in v) or "�" in v: continue
            if v in seen: continue
            seen.add(v); stat["mot_tham_so"] += 1
            if tier1_catches(v): stat["tang1_bat"] += 1; continue
            pool.setdefault(cls, []).append({"value": v, "cls": cls, "src": ds})
rng = random.Random(SEED)
out = []
for cls in sorted(pool):
    xs = sorted(pool[cls], key=lambda o: o["value"]); rng.shuffle(xs)
    out += xs[:PER_CLASS]
rng.shuffle(out)
for i, o in enumerate(out): o["id"] = i
os.makedirs(os.path.join(ROOT, "scenarios", "tang-2"), exist_ok=True)
p = os.path.join(ROOT, "scenarios", "tang-2", "ung-vien.jsonl")
with open(p, "w", encoding="utf-8", newline="\n") as f:
    for o in out: f.write(json.dumps(o, ensure_ascii=True) + "\n")
from collections import Counter
print("bản ghi tấn công đã đọc:", stat["doc"], "| một tham số, không trùng:", stat["mot_tham_so"], "| tầng 1 bắt:", stat["tang1_bat"])
print("tầng 1 bỏ lọt, theo lớp:", {k: len(v) for k, v in sorted(pool.items())})
print(len(out), "ứng viên ->", p, dict(Counter(o["cls"] for o in out)))

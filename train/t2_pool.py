#!/usr/bin/env python3
"""train/t2_pool.py — bước 2 của việc cải thiện tầng 2: lập DANH SÁCH PAYLOAD HUẤN LUYỆN cần gửi qua Cổng 2 thật.

    python -X utf8 -B train/t2_pool.py            (chạy từ thư mục nsm; vài phút)

Tầng 2 chỉ có giá trị riêng ở phần mà Cổng 2 (CRS + luật tầng 1 đồng bộ) bỏ lọt. Để huấn luyện và chọn model theo đúng phần
đó, mỗi payload của tập train/valid cần một cờ "lọt Cổng 2". Tệp này:
  1. đọc payload của train/valid ĐÚNG như train/build_tier2_dataset.py (seclists, openappsec_mal; giá trị dài nhất mà
     ModSecurity nhìn thấy), khử trùng theo giá trị;
  2. kiểm regex tầng 1 trên request  GET /index.php?q=<payload>  (đúng dạng request mà bước lọc sẽ gửi), KHÔNG nạp model
     tầng 2;
  3. ghi train/data_src/pool.jsonl.gz (mọi payload, cờ t1) và chia phần tầng 1 bỏ lọt thành N tệp
     scenarios/tang-2/loc/phan-<k>.jsonl cho N tác nhân gửi song song (tools/scenario.sh, kịch bản loc-song-song).
Sau bước lọc, train/t2_pool_result.py đọc mã phản hồi và ghi cờ g2pass.
Dữ liệu công khai; lưu lượng thử chỉ gửi vào hệ thống của dự án trong mạng Docker nội bộ.
"""
import gzip, json, os, sys, types, warnings
from collections import Counter
from urllib.parse import quote
warnings.filterwarnings("ignore")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ["MODEL_PATH"] = os.path.join(ROOT, "khong-co-model")       # KHÔNG nạp tầng 2
os.environ["TIER2_MODE"] = "observe"
ck = types.ModuleType("confluent_kafka"); ck.Consumer = object; ck.Producer = object; sys.modules["confluent_kafka"] = ck
es = types.ModuleType("elasticsearch"); es.helpers = types.SimpleNamespace(); es.Elasticsearch = object; sys.modules["elasticsearch"] = es
sys.path.insert(0, os.path.join(ROOT, "services"))
import logging; logging.disable(logging.INFO)
import classifier as C
assert C.MODEL is None, "model tầng 2 không được nạp ở bước lập danh sách"
NORM = os.path.join(ROOT, "eval", "data", "normalized")
SRC_OUT = os.path.join(ROOT, "train", "data_src")
LOC = os.path.join(ROOT, "scenarios", "tang-2", "loc")
N_PARTS = int(os.getenv("T2_POOL_PARTS", "8"))
CLASSES = ("sqli", "xss", "lfi", "rce")
UA = "Mozilla/5.0"


def tier1_catches(value):
    q = "q=" + quote(value, safe="")
    ev = {"uri": "/index.php", "query": "?" + q, "body": "", "_waf_blocked": False}
    r = C.classify("/index.php", C.split_params(q), C.body_params(""), UA, ev, {"User-Agent": UA})
    return r.get("tier") == 1 or (r.get("label") not in (None, "benign"))


def longest(r):
    v = r.get("marg_v") or []
    return max(v, key=len) if v else ""


def sendable(v):
    """Gửi được nguyên vẹn trong một tham số GET: không rỗng, không quá dài, không ký tự điều khiển."""
    return 1 <= len(v) <= 1500 and not any(ord(c) < 32 and c not in "\t\n\r" for c in v) and "�" not in v


def main():
    """Không tham số: payload train/valid. Tham số `test`: payload của tập kiểm tra độc lập SR-BH 2020 (tấn công thật từ
    Internet) — để lập bộ kiểm tra "lọt Cổng 2" MỚI; ghi pool_test.jsonl.gz và scenarios/tang-2/loc-test/. Không dùng để huấn luyện."""
    global LOC
    test = len(sys.argv) > 1 and sys.argv[1] == "test"
    sources = ("srbh2020",) if test else ("seclists", "openappsec_mal")
    pool_name = "pool_test.jsonl.gz" if test else "pool.jsonl.gz"
    if test:
        LOC = os.path.join(ROOT, "scenarios", "tang-2", "loc-test")
    seen, pool, stat = {}, [], Counter()
    for src in sources:
        with gzip.open(os.path.join(NORM, f"{src}.jsonl.gz"), "rt", encoding="utf-8") as f:
            for ln in f:
                r = json.loads(ln)
                if test:
                    r["split"] = "test"
                if r.get("ds_class") not in CLASSES or r.get("split") not in ("train", "valid", "test"):
                    continue
                v = longest(r)
                if not v:
                    continue
                stat["dong"] += 1
                key = (r["split"], v)
                if key in seen:
                    continue
                seen[key] = 1
                o = {"value": v, "cls": r["ds_class"], "split": r["split"], "src": src, "family": r.get("family")}
                if not sendable(v):
                    o["skip"] = "khong_gui_duoc"; stat["khong_gui_duoc"] += 1
                else:
                    o["t1"] = bool(tier1_catches(v))
                pool.append(o)
    os.makedirs(SRC_OUT, exist_ok=True); os.makedirs(LOC, exist_ok=True)
    with gzip.open(os.path.join(SRC_OUT, pool_name), "wt", encoding="utf-8") as f:
        for i, o in enumerate(pool):
            o["id"] = i
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    send = [o for o in pool if o.get("t1") is False]
    for old in os.listdir(LOC):
        if old.startswith("phan-"):
            os.remove(os.path.join(LOC, old))
    parts = [send[k::N_PARTS] for k in range(N_PARTS)]
    for k, part in enumerate(parts):
        with open(os.path.join(LOC, f"phan-{k}.jsonl"), "w", encoding="utf-8", newline="\n") as f:
            for o in part:
                f.write(json.dumps({"value": o["value"], "id": o["id"]}, ensure_ascii=True) + "\n")
    toml = ['# SINH TỰ ĐỘNG bởi train/t2_pool.py — bước lọc song song: gửi payload huấn luyện mà regex tầng 1 bỏ lọt qua Cổng 2 thật.',
            '# Chỉ đọc mã phản hồi (runs.jsonl). rulegen dừng (mặc định). Lưu lượng thử nội bộ, gửi vào hệ thống của dự án.',
            f'# Chạy:  SC_DIR=scenarios/tang-2/{os.path.basename(LOC)} SC_OUT_NAME={"t2pooltest" if test else "t2pool"} bash tools/scenario.sh loc-song-song',
            f'title = "Tầng 2, bước 2 — lọc {len(send)} payload {"kiểm tra (SR-BH)" if test else "huấn luyện"} qua Cổng 2, {N_PARTS} tác nhân gửi song song"',
            'case = "công cụ (dữ liệu huấn luyện tầng 2)"',
            'notes = "IP được miễn trừ để gửi hết request, không nghỉ giữa các request."',
            'max_s = 1800', 'exempt = ["self"]', '']
    for k, part in enumerate(parts):
        toml += ['[[actor]]', f'name = "phần {k}"', 'role = "probe"', 'ips = 1', 'family = "t2test"',
                 f'source = "file:/scenarios/phan-{k}.jsonl"', 'path = "/index.php"', 'param = "q"', 'method = "GET"',
                 f'count = {len(part)}', 'interval_s = 0', 'max_s = 1500', 'stop_on_block = false', '']
    with open(os.path.join(LOC, "loc-song-song.toml"), "w", encoding="utf-8", newline=chr(10)) as f:
        f.write(chr(10).join(toml))
    by = Counter((o["split"], o["cls"]) for o in pool)
    t1 = Counter((o["split"], o["cls"]) for o in pool if o.get("t1"))
    ms = Counter((o["split"], o["cls"]) for o in send)
    print("dòng tấn công đã đọc:", stat["dong"], "| payload khác nhau:", len(pool), "| không gửi được:", stat["khong_gui_duoc"])
    for s in (("test",) if test else ("train", "valid")):
        for c in CLASSES:
            print(f"  {s:5} {c:4}: {by[(s, c)]:6} payload | tầng 1 bắt {t1[(s, c)]:6} | tầng 1 bỏ lọt, sẽ gửi qua Cổng 2: {ms[(s, c)]:6}")
    print(f"tổng sẽ gửi: {len(send)} payload, chia {N_PARTS} phần: {[len(p) for p in parts]} -> {LOC}")


if __name__ == "__main__":
    main()

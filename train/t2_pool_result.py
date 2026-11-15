#!/usr/bin/env python3
"""train/t2_pool_result.py — đọc kết quả bước lọc song song và gắn cờ "lọt Cổng 2" cho payload huấn luyện.

    python -X utf8 -B train/t2_pool_result.py eval/results/t2pool-<thời điểm>            payload train/valid
    python -X utf8 -B train/t2_pool_result.py eval/results/t2pooltest-<thời điểm> test   payload kiểm tra (SR-BH) -> pool_test_g2

Vào : train/data_src/pool.jsonl.gz (train/t2_pool.py), scenarios/tang-2/loc/phan-<k>.jsonl, <kết quả>/loc-song-song/runs.jsonl
Ra  : train/data_src/pool_g2.jsonl.gz — như pool.jsonl.gz, thêm g2 = "pass" (mã 200: Cổng 2 để lọt VÀ giá trị có cấu trúc tấn
      công rõ, xem train/t2_constructs.py) | "pass_weak" (lọt nhưng không rõ cấu trúc: payload hỏng hoặc giá trị thường)
      | "block" (403 tại Cổng 2) | "t1" (regex tầng 1 đã bắt, không gửi) | "unknown" (lỗi mạng, mã khác, không gửi được).
Chỉ đọc tệp; không đụng tới hệ thống.
"""
import gzip, json, os, sys
from collections import Counter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from t2_constructs import constructs
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "train", "data_src")
LOC = os.path.join(ROOT, "scenarios", "tang-2", "loc")


def jl(p, gz=False):
    op = gzip.open if gz else open
    with op(p, "rt", encoding="utf-8") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


def main():
    global LOC
    test = len(sys.argv) > 2 and sys.argv[2] == "test"
    name = "pool_test" if test else "pool"
    if test:
        LOC = os.path.join(ROOT, "scenarios", "tang-2", "loc-test")
    rdir = os.path.join(ROOT, sys.argv[1], "loc-song-song")
    pool = jl(os.path.join(SRC, f"{name}.jsonl.gz"), gz=True)
    res, gates = {}, Counter()
    for r in jl(os.path.join(rdir, "runs.jsonl")):
        part = jl(os.path.join(LOC, f"phan-{int(r['actor'])}.jsonl"))          # request thứ i của tác nhân k gửi part[i % len(part)]
        for x in r["sent"]:
            pid = part[int(x["i"]) % len(part)]["id"]
            st = str(x.get("status"))
            g = "pass" if st == "200" else "block" if (st == "403" and x.get("gate") == "gate2") else "unknown"
            gates[(x.get("gate"), st)] += 1
            res[pid] = g
    out = Counter()
    with gzip.open(os.path.join(SRC, f"{name}_g2.jsonl.gz"), "wt", encoding="utf-8") as f:
        for o in pool:
            o["g2"] = "t1" if o.get("t1") else res.get(o["id"], "unknown")
            if o["g2"] == "pass":                       # lọt Cổng 2: chỉ payload có cấu trúc tấn công rõ mới là "pass" (xem t2_constructs.py)
                o["construct"] = constructs(o["value"])
                if not o["construct"]:
                    o["g2"] = "pass_weak"
            out[(o["split"], o["cls"], o["g2"])] += 1
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    print("mã phản hồi (cổng, mã):", dict(gates))
    for s in (("test",) if test else ("train", "valid")):
        for c in ("sqli", "xss", "lfi", "rce"):
            n = {g: out[(s, c, g)] for g in ("pass", "pass_weak", "block", "t1", "unknown")}
            tot = sum(n.values())
            print(f"  {s:5} {c:4}: {tot:6} payload | lọt Cổng 2, có cấu trúc tấn công {n['pass']:5} ({100 * n['pass'] / max(tot, 1):4.1f} %) "
                  f"| lọt, không rõ cấu trúc {n['pass_weak']:5} | Cổng 2 chặn {n['block']:6} | tầng 1 bắt {n['t1']:6} | không rõ {n['unknown']:5}")
    print("->", os.path.join(SRC, f"{name}_g2.jsonl.gz"))


if __name__ == "__main__":
    main()

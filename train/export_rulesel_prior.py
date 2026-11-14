#!/usr/bin/env python3
"""train/export_rulesel_prior.py — xuất "kho nền" ĐÓNG BĂNG mà bộ chọn luật G2r cần khi chạy trong rulegen.

    python -I -X utf8 -B train/export_rulesel_prior.py          (chạy từ thư mục nsm; vài phút)

Vì sao: các đặc trưng của G2r (llr, số lần đã gặp trong tấn công, xác suất lành tính, cổng NB) được tính từ
TokenPrior + Benign lúc dựng dữ liệu (train/build_rulesel_dataset.py). Khi chạy thật phải tính bằng ĐÚNG kho đó
thì điểm của model mới cùng thang với lúc huấn luyện. Script này tái tạo chính xác:
    - payload tấn công phần train (SecLists + openappsec Malicious, giá trị dài nhất của marg_v, <= 400 ký tự);
    - 30 000 giá trị lành tính của website train (cùng hạt giống và cùng thứ tự gọi rng như bản dựng dữ liệu);
    - vốn từ tiếng Anh nền.
Đầu ra: models/rulesel_prior.json.gz  (rulegen nạp cùng models/rulesel_g2r.joblib)
"""
import gzip, json, os, random, sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "train"))
import build_rulesel_dataset as B          # noqa: E402  (dùng lại đúng hằng số và hàm đọc)


def main():
    rng = random.Random(B.SEED)                     # lần dùng rng đầu tiên = bvals({"train"}) như trong B.main()
    pools = defaultdict(list)
    for src in ("seclists", "openappsec_mal"):
        for r in B.rows(src):
            if r["ds_class"] in B.CLASSES and r["split"] == "train":
                v = B.longest(r)
                if v and len(v) <= 400:
                    pools[(r["ds_class"], r["sub"])].append(v)
    attacks = {c: [] for c in B.CLASSES}
    for (c, g), vs in pools.items():
        attacks[c] += vs
    it = (v for r in B.rows("openappsec_legit") if r["split"] == "train" for v in (r.get("marg_v") or []) if v)
    benign = list(dict.fromkeys(B.reservoir(it, B.B_SAFE, rng)))
    vocab = [w for w in open(B.VOCAB, encoding="utf-8").read().split() if w]
    out = os.path.join(ROOT, "models", "rulesel_prior.json.gz")
    with gzip.open(out, "wt", encoding="utf-8", compresslevel=9) as f:
        json.dump({"version": 1, "seed": B.SEED, "attacks": attacks, "benign": benign, "vocab": vocab}, f,
                  ensure_ascii=True)
    print(f"đã ghi {out}: tấn công { {c: len(v) for c, v in attacks.items()} }, lành tính {len(benign)}, "
          f"vốn từ {len(vocab)}, {os.path.getsize(out) / 2**20:.1f} MB")


if __name__ == "__main__":
    main()

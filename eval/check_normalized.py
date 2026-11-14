#!/usr/bin/env python3
"""eval/check_normalized.py — kiểm tra dữ liệu đã chuẩn hoá (eval/data/normalized) và in báo cáo Markdown.

    python -I -X utf8 -B eval/check_normalized.py > eval/results/normalized_check.md

Đọc từng dòng (RAM nhỏ). Hai phần: (1) kiểm tra tính nhất quán — mọi bản ghi phải có đủ trường như bản
ghi Elasticsearch, các danh sách tên/giá trị phải dài bằng nhau, nhãn và tập phải thuộc tập giá trị hợp lệ;
(2) thống kê — nhãn của hệ thống so với nhãn của dataset, độ phủ của góc nhìn ModSecurity.
"""
import gzip, json, os, re
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NORM = os.path.join(ROOT, "eval", "data", "normalized")
SOURCES = ("seclists", "openappsec_mal", "openappsec_legit", "httpparams", "srbh2020")
CLASSES = ("sqli", "xss", "lfi", "rce", "benign", "other")
SPLITS = {"train", "valid", "test_sites", "test_ext1", "test_ext2"}
LABELS = {"sqli", "xss", "lfi", "rce", "recon", "scanner", "benign"}
NEED = ("method", "path", "query", "body", "ct", "ua", "source", "sub", "ds_raw", "ds_class", "dup", "label",
        "confidence", "tier", "arg_n", "arg_v", "marg_n", "marg_v", "marg_body", "has_body", "family", "split",
        "body_len", "cut")


def pct(a, b):
    return "—" if not b else f"{100 * a / b:.1f} %".replace(".", ",")


def num(n):
    return f"{n:,}".replace(",", ".")


def main():
    L = ["# Kiểm tra dữ liệu đã chuẩn hoá", ""]
    summ = json.load(open(os.path.join(NORM, "summary.json"), encoding="utf-8"))
    L += ["## 1. Tổng quan", "",
          "| Nguồn | Bản ghi gốc | Khác nhau | Lỗi | Không có tham số | Thân không tách được | Thân vượt giới hạn ModSecurity (413) | Thân/URL bị cắt khi lưu | Thời gian |",
          "|---|---|---|---|---|---|---|---|---|"]
    for s in SOURCES:
        v = summ.get(s, {})
        L.append(f"| {s} | {num(v.get('raw', 0))} | {num(v.get('unique', 0))} | {v.get('errors', 0)} | {num(v.get('no_args', 0))} | "
                 f"{num(v.get('marg_body_false', 0))} | {num(v.get('over_limit', 0))} | {num(v.get('cut', 0))} | {v.get('seconds', 0):.0f} s |")
    L.append("")

    problems = Counter(); prob_ex = defaultdict(list)
    conf = {s: Counter() for s in SOURCES}           # (ds_class, label) -> số bản ghi khác nhau
    confw = {s: Counter() for s in SOURCES}          # có trọng số dup (số request thật)
    tiers = {s: Counter() for s in SOURCES}
    json_body = Counter(); seen = Counter(); seen_args = Counter()
    fp_ex = defaultdict(list)
    for s in SOURCES:
        p = os.path.join(NORM, f"{s}.jsonl.gz")
        if not os.path.exists(p):
            problems[f"{s}: thiếu tệp"] += 1
            continue
        with gzip.open(p, "rt", encoding="utf-8") as f:
            for ln in f:
                r = json.loads(ln)
                miss = [k for k in NEED if k not in r]
                if miss:
                    problems["thiếu trường"] += 1
                    if len(prob_ex["thiếu trường"]) < 3: prob_ex["thiếu trường"].append((s, miss))
                if len(r.get("marg_n") or []) != len(r.get("marg_v") or []) or len(r.get("arg_n") or []) != len(r.get("arg_v") or []):
                    problems["tên/giá trị lệch độ dài"] += 1
                if r.get("ds_class") not in CLASSES: problems["ds_class lạ"] += 1
                if r.get("split") not in SPLITS: problems["split lạ"] += 1
                if r.get("label") not in LABELS: problems["nhãn hệ thống lạ"] += 1
                if not r.get("family"): problems["thiếu họ payload"] += 1
                if any(len(v) > 2048 for v in r.get("marg_v") or []): problems["marg_v quá 2048"] += 1
                if (r.get("label") == "benign") != (r.get("tier") is None): problems["nhãn và tầng không khớp"] += 1
                if r.get("marg_body") and r.get("ct", "").lower().startswith("application/json") and r.get("has_body"):
                    json_body[s] += 1
                conf[s][(r["ds_class"], r["label"])] += 1
                confw[s][(r["ds_class"], r["label"])] += r.get("dup", 1)
                tiers[s][(r["ds_class"] != "benign", r.get("tier"))] += 1
                if r.get("seen_in_train") is not None:
                    seen_args[s] += 1; seen[s] += bool(r["seen_in_train"])
                if r["ds_class"] == "benign" and r["label"] != "benign" and len(fp_ex[s]) < 8:
                    fp_ex[s].append((r["label"], r.get("tier"), r["method"], (r["path"] + ("?" + r["query"] if r["query"] else ""))[:110],
                                     (r.get("evidence") or "")[:50]))

    L += ["## 2. Kiểm tra tính nhất quán", ""]
    if problems:
        for k, v in problems.most_common():
            L.append(f"- **{k}:** {num(v)}" + (f" — ví dụ {prob_ex[k][:2]}" if prob_ex.get(k) else ""))
    else:
        L.append("Không có lỗi: mọi bản ghi có đủ trường, danh sách tên/giá trị dài bằng nhau, nhãn và tập hợp lệ.")
    L.append("")

    L += ["## 3. Nhãn của hệ thống so với nhãn của dataset", "",
          "Đếm trên request **khác nhau**. \"Phát hiện\" = classifier gắn bất kỳ nhãn nào khác `benign`.", ""]
    for s in SOURCES:
        c = conf[s]
        if not c:
            continue
        L += [f"### {s}", "", "| Nhãn dataset | Số | Hệ thống phát hiện | Đúng lớp | Nhãn hệ thống hay gặp |", "|---|---|---|---|---|"]
        for ds in CLASSES:
            tot = sum(v for (d, _), v in c.items() if d == ds)
            if not tot:
                continue
            det = sum(v for (d, l), v in c.items() if d == ds and l != "benign")
            same = c[(ds, ds)] if ds in ("sqli", "xss", "lfi", "rce") else None
            top = ", ".join(f"{l}: {num(v)}" for (d, l), v in sorted(c.items(), key=lambda x: -x[1]) if d == ds)[:120]
            L.append(f"| {ds} | {num(tot)} | {pct(det, tot)} | {pct(same, tot) if same is not None else '—'} | {top} |")
        L.append("")
    L += ["## 4. Báo nhầm của classifier trên lưu lượng lành tính", ""]
    for s in ("openappsec_legit", "httpparams", "srbh2020"):
        c, cw = conf[s], confw[s]
        tot = sum(v for (d, _), v in c.items() if d == "benign"); fp = sum(v for (d, l), v in c.items() if d == "benign" and l != "benign")
        totw = sum(v for (d, _), v in cw.items() if d == "benign"); fpw = sum(v for (d, l), v in cw.items() if d == "benign" and l != "benign")
        if tot:
            L.append(f"- **{s}:** {num(fp)}/{num(tot)} request khác nhau ({pct(fp, tot)}); tính cả lặp lại {num(fpw)}/{num(totw)} ({pct(fpw, totw)})")
            for lab, tier, m, url, ev in fp_ex[s][:5]:
                L.append(f"  - {lab} (tầng {tier}) {m} `{url}` — bằng chứng `{ev}`")
    L += ["", "## 5. Độ phủ của góc nhìn ModSecurity", ""]
    for s in SOURCES:
        if json_body[s]:
            L.append(f"- {s}: {num(json_body[s])} request có thân JSON được tách thành ARGS")
    L += ["", "## 6. Trùng họ payload với phần train (chỉ request có tham số)", ""]
    for s in ("openappsec_legit", "httpparams", "srbh2020"):
        if seen_args[s]:
            L.append(f"- {s}: {num(seen[s])}/{num(seen_args[s])} ({pct(seen[s], seen_args[s])})")
    print("\n".join(L))


if __name__ == "__main__":
    main()

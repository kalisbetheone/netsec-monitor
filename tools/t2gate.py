#!/usr/bin/env python3
"""tools/t2gate.py — so hai lượt đo của tools/t2gate.sh (cổng cú pháp của tầng 2 tắt / bật). Chỉ đọc tệp kết quả.

    python -X utf8 -B tools/t2gate.py eval/results/t2gate-0.txt eval/results/t2gate-1.txt

In: nhãn trên bộ thử 52 payload và hai danh sách văn bản hợp lệ (kịch bản do-nhan), pha detect của bench, kết quả 5 kịch bản.
Tiêu chí quyết định được ghi trong eval/PROTOCOL.md TRƯỚC khi đo; tệp này chỉ tính và in.
"""
import json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import t2test as T
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def conf(p):
    return dict(ln.strip().split("=", 1) for ln in open(p, encoding="utf-8") if "=" in ln)


def labels(nhan_dir):
    out = {}
    # kịch bản do-nhan: 3 tác nhân; do-nhan-3 (16/11): thêm danh sách đối chứng thứ ba ở vị trí 1
    scn = next((s for s in ("do-nhan-4", "do-nhan-3") if os.path.isdir(os.path.join(ROOT, nhan_dir, s))), "do-nhan")
    actors = ([(0, "bo_thu", "bo-thu.jsonl"), (1, "doi_chung_4a_thuong", "doi-chung-4a.jsonl"), (2, "doi_chung_4b_ky_thuat", "doi-chung-4b.jsonl"),
               (3, "doi_chung_3", "doi-chung-3.jsonl"), (4, "doi_chung_moi", "doi-chung-2.jsonl"), (5, "doi_chung_cu", "doi-chung.jsonl")]
              if scn == "do-nhan-4" else
              [(0, "bo_thu", "bo-thu.jsonl"), (1, "doi_chung_3", "doi-chung-3.jsonl"), (2, "doi_chung_moi", "doi-chung-2.jsonl"), (3, "doi_chung_cu", "doi-chung.jsonl")]
              if scn == "do-nhan-3" else [(0, "bo_thu", "bo-thu.jsonl"), (1, "doi_chung_moi", "doi-chung-2.jsonl"), (2, "doi_chung_cu", "doi-chung.jsonl")])
    bo = T.jl(os.path.join(ROOT, "scenarios", "tang-2", "bo-thu.jsonl"))
    for actor, name, src in actors:
        pool = [o["value"] for o in T.jl(os.path.join(ROOT, "scenarios", "tang-2", src))]     # request thứ i gửi pool[i % len(pool)]
        _, rows, _ = T.align(os.path.join(ROOT, nhan_dir), scn, actor)
        hit = [r for r in rows if r.get("label") not in (None, "benign")]
        out[name] = {"n": len(rows), "labelled": len(hit), "gate2_blocked": sum(1 for r in rows if str(r["status"]) == "403"),
                     "values": sorted({pool[int(r["i"]) % len(pool)][:40] for r in hit})}
        if name == "bo_thu":                           # theo lớp, để đọc riêng lớp RCE
            c = {}
            for r in rows:
                k = bo[int(r["i"]) % len(bo)]["cls"]; c.setdefault(k, [0, 0]); c[k][1] += 1
                c[k][0] += r.get("label") not in (None, "benign")
            out[name]["theo_lop"] = {k: f"{a}/{n}" for k, (a, n) in sorted(c.items())}
    return out


def bench(bdir):
    """Số của pha detect: đọc report.md của bench (các dòng có 'x / y')."""
    p = os.path.join(ROOT, bdir, "report.md")
    txt = open(p, encoding="utf-8").read() if os.path.exists(p) else ""
    return [ln.strip() for ln in txt.splitlines() if ln.startswith(("- **Phát hiện tấn công", "- **Báo nhầm", "Tầng ra quyết định"))]


def scenarios(kdir):
    p = os.path.join(ROOT, kdir, "results.jsonl")
    out = {}
    if os.path.exists(p):
        for r in T.jl(p):
            out[r.get("id")] = r.get("verdict")
    return out


def main():
    for p in sys.argv[1:]:
        c = conf(p)
        print(f"\n===== cổng cú pháp = {c['gate']}  ({c.get('classifier_sau')}) =====")
        lab = labels(c["nhan"])
        for k, v in lab.items():
            print(f"  {k:14} bị gắn nhãn tấn công {v['labelled']:2}/{v['n']} | Cổng 2 chặn {v['gate2_blocked']}" + (f" | theo lớp {v['theo_lop']}" if "theo_lop" in v else ""))
            if k != "bo_thu":
                print("      ", v["values"])
        print("  bench (pha detect):")
        for ln in bench(c["bench"]):
            print("     ", ln[:170])
        print("  kịch bản:", scenarios(c["kichban"]))


if __name__ == "__main__":
    main()

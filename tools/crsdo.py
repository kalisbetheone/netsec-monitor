#!/usr/bin/env python3
"""tools/crsdo.py — đọc kết quả của tools/crsdo.sh (một hay nhiều lượt) và in bảng so. Chỉ đọc tệp kết quả.
   python -X utf8 -B tools/crsdo.py eval/results/crs-truoc.txt eval/results/crs-sau.txt
"""
import json, math, os, re, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def kv(p):
    return dict(l.rstrip("\r\n").split("=", 1) for l in open(p, encoding="utf-8") if "=" in l)


def wilson(k, n, z=1.96):
    if not n: return "—"
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return f"{100 * (c - h):.1f}–{100 * (c + h):.1f} %"


def replay(rdir, sid):
    p = os.path.join(ROOT, rdir, f"crsfp-{sid}.json")
    if not os.path.isfile(p): return None
    d = json.load(open(p, encoding="utf-8")); return d["gate2_blocked"], d["sent"]


def scen(sdir):
    out = {}
    p = os.path.join(ROOT, sdir, "results.jsonl")
    if os.path.isfile(p):
        for l in open(p, encoding="utf-8"):
            r = json.loads(l); a = (r.get("metrics") or {}).get("attack") or {}; b = (r.get("metrics") or {}).get("benign") or {}
            out[r["id"][:2]] = {"verdict": r.get("verdict"), "att_g2": (a.get("gates") or {}).get("gate2"), "att_n": a.get("sent"),
                                "ben_g2": (b.get("gates") or {}).get("gate2"), "ben_n": b.get("sent")}
    rp = os.path.join(ROOT, sdir, "report.md"); txt = open(rp, encoding="utf-8").read() if os.path.isfile(rp) else ""
    m = re.search(r"\| Tấn công \(bị chặn là đúng\) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \|", txt)
    out["gtw"] = m.groups() if m else None
    m = re.search(r"\| (?:Hợp lệ|Lành tính|Báo nhầm)[^|]*\| (\d+) \| (\d+) \| (\d+) \| (\d+) \|", txt)
    out["gtw_fp"] = m.groups() if m else None
    m = re.search(r"bị chặn (\d+), lọt (\d+) \(tỷ lệ chặn ([\d.]+) %\); chặn nhầm \(FALSED\) (\d+) tệp", txt)
    out["wb"] = m.groups() if m else None
    return out


def bench(bdir):
    p = os.path.join(ROOT, bdir, "report.md"); txt = open(p, encoding="utf-8").read() if os.path.isfile(p) else ""
    return [l.strip()[:230] for l in txt.splitlines() if l.startswith(("- **Phát hiện tấn công", "- **Báo nhầm")) or "Cổng 2 chặn" in l and "lành tính" in l.lower()][:4]


for p in sys.argv[1:]:
    c = kv(p); print(f"\n===== lượt '{c.get('tag')}' =====")
    for sid in ("quan-sat", "kiem-tra"):
        r = replay(c.get("phatlai", ""), sid)
        if r: print(f"  phát lại {sid:9}: Cổng 2 chặn {r[0]}/{r[1]} = {100 * r[0] / r[1]:.2f} %  (KTC 95 % {wilson(*r)})")
    for l in bench(c.get("bench", "")): print("  bench:", l)
    s = scen(c.get("tancong", ""))
    for k in ("01", "36", "47"):
        if k in s: print(f"  kịch bản {k}: {s[k]['verdict']} | tấn công bị Cổng 2 chặn {s[k]['att_g2']}/{s[k]['att_n']} | hợp lệ bị Cổng 2 chặn {s[k]['ben_g2']}/{s[k]['ben_n']}")
    print("  GoTestWAF (gửi, bị chặn, đi qua, không xác định):", s.get("gtw"), "| bộ thử báo nhầm:", s.get("gtw_fp"))
    print("  waf-bypass (bị chặn, lọt, tỷ lệ %, FALSED):", s.get("wb"))

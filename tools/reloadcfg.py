#!/usr/bin/env python3
"""tools/reloadcfg.py — đọc kết quả của tools/reloadcfg.sh và in bảng so các cấu hình nạp lại danh sách chặn của nginx.
   python -X utf8 -B tools/reloadcfg.py eval/results/reload-N5.txt eval/results/reload-N2.txt ...
Chạy trên host, từ thư mục nsm. Chỉ đọc tệp kết quả."""
import json, os, re, statistics, sys


def kv(path):
    d = {}
    for line in open(path, encoding="utf-8"):
        if "=" in line:
            k, v = line.rstrip("\r\n").split("=", 1); d[k] = v
    return d


def num(s):
    s = s.strip().replace(",", ".")
    try: return float(s)
    except ValueError: return None


def mttr(bdir):
    """-> (số lần, số bị khoá, [T thực thi], [T tổng], [T quyết định]) từ bảng 'Chi tiết từng lần' của report.md"""
    p = os.path.join(bdir, "report.md")
    if not bdir or not os.path.isfile(p): return None
    n = b = 0; enf, tot, dec = [], [], []
    for line in open(p, encoding="utf-8"):
        c = [x.strip() for x in line.strip().strip("|").split("|")]
        if len(c) >= 7 and c[0] in ("sqli", "rce", "flood", "recon") and re.fullmatch(r"\d+", c[1]) and c[2].startswith("10."):
            n += 1; b += c[3] == "có"
            for lst, v in ((tot, num(c[4])), (dec, num(c[5])), (enf, num(c[6]))):
                if v is not None: lst.append(v)
    return n, b, enf, tot, dec


def st(v):
    if not v: return "—"
    return f"{statistics.median(v):.2f} ({min(v):.1f}–{max(v):.1f})"


def kb(sdir, name):
    """-> dict: kết luận, người dùng hợp lệ không-200, thời gian tới khi từng bot bị Cổng 1 chặn"""
    o = {"verdict": "?"}
    rp = os.path.join(sdir, "results.jsonl")
    if not sdir or not os.path.isfile(rp): return o
    for line in open(rp, encoding="utf-8"):
        r = json.loads(line)
        if r.get("id") == name: o["verdict"] = r.get("verdict", "?")
    d = os.path.join(sdir, name)
    non200 = sent = 0; first, blk = {}, {}; ok_bot = 0
    for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if not re.fullmatch(r"a_\d+_\d+\.json", f): continue
        a = json.load(open(os.path.join(d, f), encoding="utf-8"))
        for s in a.get("sent", []):
            if a.get("role") == "benign":
                sent += 1; non200 += s.get("status") != 200
            else:
                src = s.get("src") or a.get("ip")
                first.setdefault(src, s["t"])
                if s.get("gate") == "gate1" and s.get("status") == 403: blk.setdefault(src, s["t"])
                ok_bot += s.get("gate") == "pass"
    tb = sorted(blk[k] - first[k] for k in blk)
    o.update(benign_sent=sent, benign_non200=non200, bots=len(first), bots_blocked=len(blk), bot_pass=ok_bot,
             t_block=(f"{statistics.median(tb):.1f} / {tb[int(len(tb) * 0.9)]:.1f} / {tb[-1]:.1f}" if tb else "—"))
    return o


def samples(path):
    pid, mem = [], []
    if not os.path.isfile(path): return "—", "—"
    for line in open(path, encoding="utf-8", errors="replace"):
        p = line.rstrip("\r\n").split("\t")
        if len(p) < 2 or "|" not in p[1]: continue
        a = p[1].split("|")
        try:
            pid.append(int(a[0])); m = a[1].split("/")[0].strip()
            mem.append(float(re.sub(r"[^\d.]", "", m)) * (1024 if "GiB" in m else 1))
        except ValueError: pass
    return (max(pid) if pid else "—"), (f"{max(mem):.0f}" if mem else "—")


rows = []
for p in sys.argv[1:]:
    c = kv(p); base = os.path.dirname(p)
    seq = mttr(c.get("lanluot", "")); s1 = mttr(c.get("sole1", "")); s2 = mttr(c.get("sole2", ""))
    sole = None
    if s1 and s2: sole = (s1[0] + s2[0], s1[1] + s2[1], s1[2] + s2[2], s1[3] + s2[3], s1[4] + s2[4])
    k39 = kb(c.get("kb39", ""), "39-flood-phan-tan-300-ip"); k45 = kb(c.get("kb45", ""), "45-nhoi-tai-khoan-cong-dat-cho")
    pk, mm = samples(os.path.join(base, f"reload-{c.get('tag')}-nginx.tsv"))
    rows.append((c, seq, sole, s1, s2, k39, k45, pk, mm))

print("| Cấu hình | Lần lượt: khoá | T thực thi | So le: khoá | T thực thi (gộp) | lượt 1 | lượt 2 | T quyết định so le |")
print("|---|---|---|---|---|---|---|---|")
for c, seq, sole, s1, s2, *_ in rows:
    print(f"| {c.get('tag')} ({c.get('interval')} s, chờ đúng {c.get('exact')}) | "
          + (f"{seq[1]}/{seq[0]} | {st(seq[2])}" if seq else "— | —") + " | "
          + (f"{sole[1]}/{sole[0]} | {st(sole[2])} | {st(s1[2])} | {st(s2[2])} | {st(sole[4])}" if sole else "— | — | — | — | —") + " |")
print()
print("| Cấu hình | KB 39 | bot bị khoá | tới khi bị chặn: trung vị / p90 / lớn nhất (s) | request của bot qua cả hai cổng | người dùng không-200 | số lần nạp lại | đỉnh tiến trình | đỉnh bộ nhớ (MiB) | dòng lỗi nginx | KB 45 | KB 45 người dùng không-200 |")
print("|---|---|---|---|---|---|---|---|---|---|---|---|")
for c, seq, sole, s1, s2, k39, k45, pk, mm in rows:
    if not c.get("kb39"): continue
    print(f"| {c.get('tag')} | {k39['verdict']} | {k39.get('bots_blocked')}/{k39.get('bots')} | {k39.get('t_block')} | {k39.get('bot_pass')} | "
          f"{k39.get('benign_non200')}/{k39.get('benign_sent')} | {c.get('reloads39')} | {pk} | {mm} | {c.get('nginx_bad39')} | "
          f"{k45['verdict']} | {k45.get('benign_non200')}/{k45.get('benign_sent')} |")

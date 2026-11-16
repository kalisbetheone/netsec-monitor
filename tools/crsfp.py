#!/usr/bin/env python3
"""tools/crsfp.py — LUẬT CRS NÀO CHẶN NHẦM? Đọc một lượt phát lại lưu lượng hợp lệ (kịch bản kind = "replay") và nhật ký kiểm toán
của ModSecurity, in: bao nhiêu request hợp lệ bị Cổng 2 chặn, và từng luật CRS góp vào bao nhiêu lần chặn. Chỉ đọc.

    bash tools/crsfp.sh <thư mục kết quả> <mã kịch bản> [--tong]

--tong: chỉ in tổng (dùng cho mẫu KIỂM TRA, để không xem chi tiết theo luật trước khi chốt tinh chỉnh).
Nhật ký kiểm toán đọc từ stdin (mỗi dòng một JSON); request của lượt chạy nhận ra qua dấu trong User-Agent
("nsm-sc/<lượt>/<kịch bản>/"). Kết quả chi tiết ghi vào <thư mục kết quả>/crsfp-<kịch bản>.json.
"""
import json, os, re, sys
from collections import Counter, defaultdict

META = {"949110", "949111", "980170", "959100", "980130", "980140"}          # chấm điểm / tổng kết, không phải luật phát hiện
RX_ID = re.compile(r'\[id "(\d+)"\]'); RX_MSG = re.compile(r'\[msg "([^"]*)"\]')
RX_VAR = re.compile(r'\bat ([A-Z_]+(?::[^\s]+?)?)\. \[file'); RX_DATA = re.compile(r'\[data "((?:[^"\\]|\\.)*)"\]')


def main():
    rdir, sid = sys.argv[1], sys.argv[2]; tong = "--tong" in sys.argv
    run = "-".join(os.path.basename(os.path.normpath(rdir)).split("-")[-2:])
    mark = f"nsm-sc/{run}/{sid}/"
    sent = st403 = 0; status = Counter()
    d = os.path.join(rdir, sid)
    for f in sorted(os.listdir(d)):
        if re.fullmatch(r"a_\d+_\d+\.json", f):
            a = json.load(open(os.path.join(d, f), encoding="utf-8"))
            for s in a.get("sent", []):
                sent += 1; status[(s.get("status"), s.get("gate"))] += 1; st403 += s.get("gate") == "gate2"
    seen = blocked = 0
    per = defaultdict(lambda: {"n": 0, "sole": 0, "msg": "", "vars": Counter(), "paths": Counter(), "ct": Counter(), "ex": []})
    combos = Counter()
    for raw in sys.stdin.buffer:                     # thân nhị phân (gzip...) có byte không phải UTF-8: thay bằng ký tự thế
        line = raw.decode("utf-8", "replace")
        if mark not in line: continue
        try: ev = json.loads(line)
        except ValueError: continue
        req = ev.get("request") or {}; h = req.get("headers") or {}
        if mark not in str(h.get("User-Agent", "")): continue
        seen += 1
        ad = ev.get("audit_data") or {}
        if not (ad.get("action") or {}).get("intercepted"): continue
        blocked += 1
        ids = []
        for m in ad.get("messages") or []:
            i = RX_ID.search(m)
            if not i or i.group(1) in META: continue
            rid = i.group(1); ids.append(rid); p = per[rid]
            mm = RX_MSG.search(m); p["msg"] = mm.group(1) if mm else p["msg"]
            v = RX_VAR.search(m)
            if v: p["vars"][re.sub(r"\d+", "N", v.group(1))[:60]] += 1
            dm = RX_DATA.search(m)
            if dm and len(p["ex"]) < 6: p["ex"].append(dm.group(1)[:220])
        path = (req.get("request_line") or "").split(" ")[1:2]; path = (path[0] if path else "").split("?")[0]
        ct = str(h.get("Content-Type", "-")).split(";")[0]
        for rid in set(ids):
            per[rid]["n"] += 1; per[rid]["sole"] += len(set(ids)) == 1
            per[rid]["paths"][re.sub(r"[0-9a-f]{8,}|\d+", "N", path)[:70]] += 1; per[rid]["ct"][ct] += 1
        combos["+".join(sorted(set(ids)))] += 1
    print(f"lượt {run}, kịch bản {sid}: gửi {sent} request hợp lệ; Cổng 2 chặn {st403} ({100 * st403 / max(sent, 1):.2f} %)")
    print("  mã trả về:", dict(sorted(status.items(), key=lambda kv: -kv[1])[:6]))
    print(f"  nhật ký kiểm toán: {seen} mục của lượt này, {blocked} mục bị chặn" + ("" if blocked == st403 else "  (LỆCH với số 403 phía người gửi)"))
    out = {"run": run, "scenario": sid, "sent": sent, "gate2_blocked": st403, "audit_seen": seen, "audit_blocked": blocked,
           "rules": {k: {"n": v["n"], "sole": v["sole"], "msg": v["msg"], "vars": dict(v["vars"].most_common(8)),
                         "paths": dict(v["paths"].most_common(6)), "ct": dict(v["ct"]), "ex": v["ex"]} for k, v in per.items()},
           "combos": dict(combos.most_common(40))}
    if tong:                # mẫu kiểm tra: chỉ ghi và in con số tổng, không ghi chi tiết theo luật
        out = {k: out[k] for k in ("run", "scenario", "sent", "gate2_blocked", "audit_seen", "audit_blocked")}
    json.dump(out, open(os.path.join(rdir, f"crsfp-{sid}.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    if tong: return
    print("\n| Luật | Request bị chặn có luật này | …là luật duy nhất | Nội dung | Biến khớp nhiều nhất |")
    print("|---|---|---|---|---|")
    for rid, v in sorted(per.items(), key=lambda kv: -kv[1]["n"]):
        print(f"| {rid} | {v['n']} | {v['sole']} | {v['msg'][:70]} | {', '.join(f'{a}×{b}' for a, b in v['vars'].most_common(3))[:110]} |")
    print("\nTổ hợp luật trên mỗi request bị chặn:")
    for c, n in combos.most_common(15): print(f"  {n:4d}  {c}")


if __name__ == "__main__":
    main()

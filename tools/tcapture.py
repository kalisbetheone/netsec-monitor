#!/usr/bin/env python3
"""tools/tcapture.py — đo ModSecurity THẬT biến đổi một giá trị thế nào (dùng bởi tools/tcapture.sh).

  conf   in tệp luật ghi lại giá trị sau từng chuỗi phép biến đổi (capture + logdata)
  send   gửi các giá trị cần đo (stdin: JSON danh sách {"value", "transforms"}) tới /nsm-tcap
  diff   so giá trị ModSecurity ghi lại với secrule.apply; in kết quả KHỚP/LỆCH (không in nội dung giá trị)
"""
import http.client, json, re, sys, urllib.parse

sys.path.insert(0, "/svc")
import secrule as S                                 # noqa: E402

BASE = 9992000


def chains(items):
    out = []
    for it in items:
        t = tuple(it["transforms"])
        if t not in out:
            out.append(t)
    return out


def cmd_conf(items):
    lines = [f'SecRule REQUEST_URI "@beginsWith /nsm-tcap" "id:{BASE},phase:1,pass,nolog,ctl:auditEngine=On"']
    for i, t in enumerate(chains(items)):
        tt = ",".join("t:" + x for x in t)
        lines.append(f'SecRule ARGS:v "@rx ^(.*)$" "id:{BASE + 1 + i},phase:2,pass,log,capture,t:none,{tt},'
                     f"msg:'tcap {i}',logdata:'%{{TX.1}}'\"")
    print("\n".join(lines))


def cmd_send(items):
    for k, it in enumerate(items):
        q = urllib.parse.urlencode({"v": it["value"], "k": str(k)})
        c = http.client.HTTPConnection("10.10.10.10", 80, timeout=10)
        c.request("GET", "/nsm-tcap?" + q, headers={"User-Agent": "nsm-tcap"})
        c.getresponse().read(); c.close()


def cmd_diff(items, audit):
    ch = chains(items)
    got = {}
    for ln in open(audit, encoding="utf-8", errors="replace"):
        try:
            d = json.loads(ln)
        except ValueError:
            continue
        line = (d.get("request") or {}).get("request_line") or ""
        m = re.search(r"[?&]k=(\d+)", line)
        if not m:
            continue
        for msg in (d.get("audit_data") or {}).get("messages") or []:
            g = re.search(r'\[data "(.*)"\] \[severity', msg, re.S) or re.search(r'\[data "(.*?)"\]', msg, re.S)
            i = re.search(r"\[msg \"tcap (\d+)\"\]", msg)
            if g and i:
                # nhật ký ModSecurity viết byte ngoài ASCII và một số ký tự (vd dấu nháy kép) dạng \xhh -> giải mã lại
                val = re.sub(r"\\x([0-9a-fA-F]{2})", lambda x: chr(int(x.group(1), 16)), g.group(1))
                got[(int(m.group(1)), int(i.group(1)))] = val
    ok = bad = miss = 0
    for k, it in enumerate(items):
        ci = ch.index(tuple(it["transforms"]))
        real = got.get((k, ci))
        if real is None:
            miss += 1; continue
        sim = S.apply(it["transforms"], S.modsec_urldecode(urllib.parse.quote(it["value"], safe="")))
        # ModSecurity cắt logdata ở 512 ký tự và thoát một số ký tự trong nhật ký
        if sim[:500] == real[:500] or sim.replace("\\", "\\\\")[:500] == real[:500]:
            ok += 1
        else:
            bad += 1
            j = next((x for x in range(min(len(sim), len(real))) if sim[x] != real[x]), min(len(sim), len(real)))
            print(f"   LỆCH #{k} ({','.join(it['transforms'])}): độ dài mô phỏng {len(sim)} / thật {len(real)}, "
                  f"khác từ vị trí {j}; ký tự quanh đó: mô phỏng {sim[max(0, j - 3):j + 4]!r} thật {real[max(0, j - 3):j + 4]!r}")
    print(f"   khớp {ok}, lệch {bad}, không có trong nhật ký {miss}")


if __name__ == "__main__":
    items = json.load(open(sys.argv[2], encoding="utf-8"))
    if sys.argv[1] == "conf":
        cmd_conf(items)
    elif sys.argv[1] == "send":
        cmd_send(items)
    else:
        cmd_diff(items, sys.argv[3])

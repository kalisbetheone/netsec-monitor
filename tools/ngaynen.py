#!/usr/bin/env python3
"""tools/ngaynen.py — "NGÀY NÉN 12 LẦN": một ngày vận hành 24 giờ được nén thành 24 khung, mỗi khung khoảng 5 phút thật,
chạy ở chế độ chạy thử (dryrun) để xem hệ thống có "sẽ chặn" nhầm khách hợp lệ hay không. Thay cho đợt chạy thử 24 giờ.
Mọi "tấn công" ở đây là lưu lượng thử của bộ kiểm thử, gửi vào chính hệ thống của dự án trong mạng Docker nội bộ.

Chạy trên HOST, từ thư mục nsm (không cần Docker, không cần stack):
  python -X utf8 -B tools/ngaynen.py sinh                    sinh scenarios/ngay-nen/gio-00.toml … gio-23.toml + nguon.json
  python -X utf8 -B tools/ngaynen.py nguon --hours "00 01" --out <tệp>   nguon.json cho một lượt chỉ chạy vài khung giờ
  python -X utf8 -B tools/ngaynen.py tongket <thư mục kết quả>         cộng mọi */runs.jsonl theo vai, in bảng Markdown
  python -X utf8 -B tools/ngaynen.py tieuchi <thư mục kết quả>         chấm các tiêu chí của ngày nén (sau wouldblock, tongket)

Mỗi khối tác nhân được SAO CHÉP từ một kịch bản có sẵn (02, 13, 25, 40, 41, 42), chỉ đổi số lượng, nhịp, IP và phần mẫu.
Không có ngẫu nhiên trong bước sinh: chạy lại `sinh` cho ra các tệp giống hệt. IP cấp tự động phụ thuộc thứ tự tệp trong
lượt chạy (slot của tools/scenario.sh), nên nguon.json phải được tính cho đúng danh sách khung giờ sẽ chạy.
"""
import argparse, glob, importlib.util, json, os, sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(os.path.dirname(HERE), "scenarios", "ngay-nen")

# ---- dải IP của ngày nén (luật R6 của spec phân việc 15/11)
RESIDENTS = [f"10.10.4.{i}" for i in (1, 2, 3)] + [f"10.10.4.{i}" for i in (11, 12, 13)]   # khách thường trú (ngaynen.sh)
# Dịch vụ client-booking của docker-compose.yml (10.10.10.21) chạy suốt và KHÔNG được miễn trừ -> cũng là khách hợp lệ
# thường trú (soát chéo P2, 15/11). Dịch vụ client (10.10.10.20) nằm trong EXEMPT_CIDRS nên không bao giờ có quyết định.
RESIDENTS += ["10.10.10.21"]
SHARED_IP = "10.10.15.240"                                    # IP dùng chung nhiều trình duyệt (giờ 12, 18)
SEED_IPS = ["10.10.15.241", "10.10.15.242"]                   # nguồn thử tấn công, gieo ở giờ 01, 09, 20
VERIFY_IPS = [f"10.10.4.{i}" for i in range(21, 27)]          # "IP mới, biến thể chưa thấy" ở giờ 20
# IP của tác nhân PHÁT LẠI lưu lượng thật: cố định, để vai "phát lại" không bao giờ lẫn với khách hợp lệ (IP cấp tự động
# của giờ h bị giờ h+6 dùng lại). Mỗi giờ lấy tối đa 3 IP liên tiếp trong vòng 12 IP -> hai giờ liền nhau không dùng chung
# IP (tránh ARP cũ của nginx), một IP được dùng lại sau 4 khung giờ.
REPLAY_POOL = [f"10.10.4.{i}" for i in (4, 5, 6, 7, 8, 9, 14, 15, 16, 17, 18, 19)]

NIGHT = (0, 1, 2, 3, 4, 5)
PEAK = {9: (150, 0), 10: (150, 150), 11: (150, 300), 19: (100, 450), 20: (100, 600)}     # giờ -> (số khách, bot_offset)
OFFICE = (12, 18)
SEED_HOURS = (1, 9, 20)

# Ba trình duyệt của kịch bản 13 + một trình duyệt thứ tư; đã bỏ User-Agent của công cụ quét và họ tấn công.
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
]


# ---------------------------------------------------------------- các khối tác nhân (chép từ kịch bản có sẵn)
def a_thuong(ips, count, interval):          # 02-a1-nguoi-dung, khối "người dùng" — chỉ văn bản thường
    return {"name": "khách thường", "role": "benign", "ips": ips, "families": ["benign"], "placement": "query",
            "count": count, "interval_s": interval, "stop_on_block": False}


def a_kho(ips, count, interval):             # 02-a1-nguoi-dung, khối "người dùng" — nửa thường, nửa "khó"
    return {"name": "khách gõ văn bản khó", "role": "benign", "ips": ips, "families": ["benign", "benign_hard"],
            "placement": "query", "count": count, "interval_s": interval, "stop_on_block": False}


def a_nhay(ips, count, interval):            # 25-d4-luat-qua-rong, khối "người dùng gõ dấu nháy"
    return {"name": "khách gõ dấu nháy", "role": "benign", "ips": ips, "family": "benign_quote",
            "path": "/vulnerabilities/sqli/", "param": "id", "method": "GET", "count": count, "interval_s": interval,
            "stop_on_block": False}


def a_cao_diem(bots, offset, count, interval):   # 40-cao-diem-hop-le, khối "khách hợp lệ"
    return {"name": "khách cao điểm", "role": "benign", "kind": "botnet", "bots": bots, "bot_offset": offset,
            "families": ["benign", "benign", "benign", "benign_quote"], "count": count, "interval_s": interval,
            "stop_on_block": False}


def a_phat_lai(h, n, count, interval, start):    # 42-phat-lai-mau-khong-trung, khối "phát lại (mẫu mới)"; KHÔNG miễn trừ
    ips = [REPLAY_POOL[(3 * h + j) % len(REPLAY_POOL)] for j in range(n)]
    return {"name": "phát lại lưu lượng thật", "role": "benign", "kind": "replay", "ip": ips, "count": count,
            "every": 37, "start": start, "interval_s": interval}


def a_dung_chung(count, interval):               # 13-d1-nat, bỏ họ tấn công và công cụ quét, thêm trình duyệt thứ tư
    return {"name": "IP dùng chung, 4 trình duyệt", "role": "benign", "ip": SHARED_IP,
            "families": ["benign", "benign", "benign", "benign"], "user_agents": BROWSERS, "count": count,
            "interval_s": interval, "stop_on_block": False}


def a_gieo():                                    # 41-luat-ap-dung-ngay-go-lai, khối "gieo tấn công"
    return {"name": "gieo tấn công", "ip": SEED_IPS, "family": "rce_seed", "path": "/vulnerabilities/exec/",
            "param": "ip", "method": "POST", "count": 8, "interval_s": 0.5}


def a_bien_the():                                # 41-luat-ap-dung-ngay-go-lai, khối "IP mới, biến thể chưa thấy"
    return {"name": "IP mới, biến thể chưa thấy", "role": "verify", "ip": VERIFY_IPS, "start_s": 30,
            "family": "rce_variant", "shuffle": True, "path": "/vulnerabilities/exec/", "param": "ip", "method": "POST",
            "count": 2, "interval_s": 1, "stop_on_block": False}


def loai(h):
    return "đêm" if h in NIGHT else "cao điểm" if h in PEAK else "văn phòng" if h in OFFICE else "thường"


def hour(h):
    """-> dict kịch bản của khung giờ h (0–23)."""
    start = 45000 + h * 12000            # mỗi khung một đoạn khác của tập openappsec Legitimate, sau phần 32 và 42 đã dùng
    kind = loai(h)
    if kind == "đêm":
        actors = [a_thuong(5, 20, 10), a_phat_lai(h, 1, 100, 2, start)]
    elif kind == "cao điểm":
        bots, off = PEAK[h]
        actors = [a_cao_diem(bots, off, 30, 6), a_kho(6, 20, 8), a_phat_lai(h, 3, 100, 2, start)]
    else:
        actors = [a_thuong(12, 30, 6), a_kho(4, 20, 8), a_nhay(4, 20, 8), a_phat_lai(h, 2, 100, 2, start)]
        if kind == "văn phòng":
            actors.append(a_dung_chung(80, 2.5))
    notes = f"Khung giờ {h:02d} của ngày nén (loại: {kind}). Lưu lượng hợp lệ theo hồ sơ của loại khung giờ."
    s = {"title": f"Ngày nén — giờ {h:02d} ({kind})", "case": "chạy thử (dryrun), ngày nén 12 lần", "max_s": 250,
         "settle_s": 10}
    if h in SEED_HOURS:
        actors.append(a_gieo())
        notes += " Có nguồn thử tấn công (khối 'gieo tấn công' của kịch bản 41) từ hai IP cố định."
        if h == 1:                        # rulegen chỉ sinh luật từ tấn công LỌT Cổng 2 -> 70 giây đầu Cổng 2 chỉ ghi nhận
            s["rulegen"] = True; s["modsec_detection_only_s"] = 70
            notes += " 70 giây đầu Cổng 2 chỉ ghi nhận, để bộ sinh luật có đầu vào (như kịch bản 41)."
        if h == 20:
            actors.append(a_bien_the())
            notes += " Từ giây 30: sáu IP mới gửi biến thể chưa thấy (khối thứ hai của kịch bản 41)."
    s["notes"] = notes
    for a in actors:                      # mọi tác nhân phải gửi xong trong 240 giây
        assert a["count"] * a["interval_s"] + a.get("start_s", 0) <= 240, (h, a["name"])
    n_cont = sum(len(a["ip"]) if isinstance(a.get("ip"), list) else int(a.get("ips", 1)) for a in actors)
    assert n_cont <= 25, (h, n_cont)      # SC_PARALLEL mặc định 25: quá số này tác nhân phải xếp hàng, vỡ khung 240 giây
    s["actor"] = actors
    s["expect"] = {"benign_blocked": False, "benign_gate2_max_share": 0.05, "benign_429_max_share": 0.01}
    return s


# ---------------------------------------------------------------- ghi TOML (chỉ các kiểu đang dùng)
def tv(v):
    if isinstance(v, bool): return "true" if v else "false"
    if isinstance(v, (int, float)): return repr(v)
    if isinstance(v, str): return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list): return "[" + ", ".join(tv(x) for x in v) + "]"
    raise TypeError(type(v))


def to_toml(s):
    out = ["# SINH TỰ ĐỘNG bởi tools/ngaynen.py — không sửa tay; sửa trong ngaynen.py rồi chạy lại `ngaynen.py sinh`."]
    out += [f"{k} = {tv(v)}" for k, v in s.items() if k not in ("actor", "expect")]
    for a in s["actor"]:
        out += ["", "[[actor]]"] + [f"{k} = {tv(v)}" for k, v in a.items()]
    out += ["", "[expect]"] + [f"{k} = {tv(v)}" for k, v in s["expect"].items()]
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- phân vai IP
def _scenario_py():
    sp = importlib.util.spec_from_file_location("nsm_scenario", os.path.join(HERE, "scenario.py"))
    m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
    return m


def sources(hours):
    """nguon.json cho một lượt chạy các khung giờ `hours` THEO ĐÚNG THỨ TỰ scenario.sh sẽ chạy (tên tệp tăng dần):
    slot = vị trí trong lượt chạy. Dùng chính alloc_ips / bot_ips của tools/scenario.py."""
    sc = _scenario_py()
    ok, atk, rep, per = set(RESIDENTS), set(), set(), {}
    for slot, h in enumerate(sorted(hours)):
        s = sc.alloc_ips(json.loads(json.dumps(hour(h))), slot)
        row = {"hop_le": [], "phat_lai": [], "tan_cong": []}
        for a in s["actor"]:
            ips = list(a["_ips"])
            if a.get("kind") == "botnet":
                ips += sc.bot_ips(int(a["bots"]), int(a.get("bot_offset", 0)))
            row["phat_lai" if a.get("kind") == "replay" else "hop_le" if a.get("role") == "benign" else "tan_cong"] += ips
        per[f"{h:02d}"] = row
        ok |= set(row["hop_le"]); atk |= set(row["tan_cong"]); rep |= set(row["phat_lai"])
    both = (ok & atk) | (ok & rep) | (atk & rep)
    assert not both, f"IP thuộc hai vai: {sorted(both)[:5]}"
    return {"ghi_chu": "Phân vai IP của ngày nén: hop_le = khách hợp lệ của chính ứng dụng (kể cả thường trú và IP bí danh "
                       "của khung cao điểm) — tiêu chí 1 tính trên nhóm này; phat_lai = IP phát lại lưu lượng thật của "
                       "website KHÁC vào DVWA (phần lớn trả 404, không phải mẫu của khách thật; ghi nhận riêng); tan_cong "
                       "= nguồn thử tấn công của bộ kiểm thử. Sinh bởi tools/ngaynen.py.",
            "khung_gio": [f"{h:02d}" for h in sorted(hours)],
            "hop_le": sorted(ok), "phat_lai": sorted(rep), "tan_cong": sorted(atk), "thuong_tru": list(RESIDENTS),
            "theo_gio": per}


def cmd_sinh(a):
    os.makedirs(a.dir, exist_ok=True)
    for old in glob.glob(os.path.join(a.dir, "gio-*.toml")):
        os.remove(old)
    for h in range(24):
        with open(os.path.join(a.dir, f"gio-{h:02d}.toml"), "w", encoding="utf-8", newline="\n") as f:
            f.write(to_toml(hour(h)))
    src = sources(range(24))
    with open(os.path.join(a.dir, "nguon.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(src, f, ensure_ascii=False, indent=1); f.write("\n")
    print(f"đã sinh 24 khung giờ + nguon.json vào {a.dir}: {len(src['hop_le'])} IP hợp lệ, {len(src['phat_lai'])} IP phát "
          f"lại, {len(src['tan_cong'])} IP nguồn thử tấn công, {len(src['thuong_tru'])} thường trú")


def cmd_nguon(a):
    hours = [int(x) for x in a.hours.split()]
    src = sources(hours)
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(src, f, ensure_ascii=False, indent=1); f.write("\n")
    print(f"nguon.json cho khung giờ {' '.join(src['khung_gio'])}: {len(src['hop_le'])} IP hợp lệ, "
          f"{len(src['phat_lai'])} IP phát lại, {len(src['tan_cong'])} IP nguồn thử tấn công -> {a.out}")


# ---------------------------------------------------------------- tổng kết
def pct(a, b):
    return f"{100 * a / b:.2f} %" if b else "—"


def cmd_tongket(a):
    """Cộng mọi */runs.jsonl của một lượt ngày nén. Phân nhóm: vai hợp lệ (lưu lượng SINH RA / PHÁT LẠI), nguồn thử tấn
    công. Tiêu chí 3 không tính 70 giây đầu của giờ 01 (lúc đó Cổng 2 cố ý chỉ ghi nhận)."""
    files = sorted(glob.glob(os.path.join(a.dir, "gio-*", "runs.jsonl")))
    if not files:
        print(f"!! không thấy gio-*/runs.jsonl trong {a.dir}", file=sys.stderr); return 2
    Z = lambda: {"sent": 0, "pass": 0, "gate2": 0, "gate1": 0, "limit": 0, "error": 0, "reject": 0}
    by_name, by_group, by_hour, seeds = defaultdict(Z), defaultdict(Z), defaultdict(Z), []
    crit = {"sinh_ra": Z(), "phat_lai": Z()}
    for fp in files:
        hh = os.path.basename(os.path.dirname(fp))[4:6]
        runs = []
        with open(fp, encoding="utf-8") as f:
            for ln in f:
                if ln.strip().startswith("{"):
                    runs.append(json.loads(ln))
        if not runs:
            continue
        t_hour = min(r["t_start"] for r in runs)
        for r in runs:
            ok = r.get("role") == "benign"
            grp = ("phat_lai" if r.get("kind") == "replay" else "sinh_ra") if ok else "tan_cong"
            for x in r.get("sent", []):
                g = x.get("gate", "error")
                for d in (by_name[(grp, r.get("name", ""))], by_group[grp]) + ((by_hour[hh],) if ok else ()):
                    d["sent"] += 1; d[g] = d.get(g, 0) + 1
                if ok and not (hh == "01" and x.get("t", 0) < t_hour + 70):
                    c = crit[grp]; c["sent"] += 1; c[g] = c.get(g, 0) + 1
            if not ok:
                seeds.append((hh, r.get("name", ""), r.get("ip"), len(r.get("sent", [])),
                              dict(sorted((k, sum(1 for x in r["sent"] if x.get("gate") == k))
                                          for k in {x.get("gate") for x in r.get("sent", [])}))))
    P = print
    P("### Lưu lượng của ngày nén theo vai")
    P()
    P(f"Số khung giờ có dữ liệu: {len(files)}.")
    P()
    hd = "| Request | Thành công | Cổng 2 chặn (403) | Cổng 1 chặn (403) | Giới hạn tốc độ (429) | Lỗi / bị từ chối |"
    row = lambda d: (f"| {d['sent']} | {d['pass']} ({pct(d['pass'], d['sent'])}) | {d['gate2']} ({pct(d['gate2'], d['sent'])}) | "
                     f"{d['gate1']} | {d['limit']} ({pct(d['limit'], d['sent'])}) | {d['error'] + d['reject']} |")
    ten = {"sinh_ra": "Hợp lệ — lưu lượng sinh ra", "phat_lai": "Hợp lệ — phát lại lưu lượng thật", "tan_cong": "Nguồn thử tấn công"}
    P("| Nhóm " + hd); P("|---|---|---|---|---|---|---|")
    for g in ("sinh_ra", "phat_lai", "tan_cong"):
        if by_group[g]["sent"]:
            P(f"| {ten[g]} " + row(by_group[g]))
    P()
    P("| Nhóm | Tác nhân " + hd); P("|---|---|---|---|---|---|---|---|")
    for (g, n), d in sorted(by_name.items()):
        P(f"| {ten[g]} | {n} " + row(d))
    P()
    P("### Vai hợp lệ theo khung giờ")
    P()
    P("| Giờ " + hd); P("|---|---|---|---|---|---|---|")
    for hh in sorted(by_hour):
        P(f"| {hh} " + row(by_hour[hh]))
    P()
    if seeds:
        P("### Nguồn thử tấn công")
        P()
        P("| Giờ | Tác nhân | IP | Request | Kết quả theo cổng |"); P("|---|---|---|---|---|")
        for hh, n, ip, k, g in sorted(seeds):
            P(f"| {hh} | {n} | {ip} | {k} | {', '.join(f'{a_}: {b_}' for a_, b_ in g.items())} |")
        P()
    P("### Tiêu chí 3 (vai hợp lệ, cả ngày; không tính 70 giây đầu của giờ 01)")
    P()
    g, r = crit["sinh_ra"], crit["phat_lai"]
    allv = {k: g[k] + r[k] for k in g}
    checks = [
        ("429 ≤ 1 % (mọi request hợp lệ)", allv["limit"], allv["sent"], lambda x: x <= 0.01),
        ("Cổng 2 chặn ≤ 1 % (lưu lượng sinh ra)", g["gate2"], g["sent"], lambda x: x <= 0.01),
        ("Cổng 2 chặn ≤ 5 % (phát lại)", r["gate2"], r["sent"], lambda x: x <= 0.05),
        ("Thành công ≥ 99 % (lưu lượng sinh ra)", g["pass"], g["sent"], lambda x: x >= 0.99),
    ]
    P("| Điều kiện | Số đo | Kết quả |"); P("|---|---|---|")
    all_ok = True
    for name, num, den, f in checks:
        ok = (not den) or f(num / den); all_ok &= ok          # không có request loại này (lượt thử vài khung giờ): bỏ qua
        P(f"| {name} | {num}/{den} ({pct(num, den)}) | {'không có dữ liệu' if not den else 'ĐẠT' if ok else 'KHÔNG ĐẠT'} |")
    P()
    P(f"**Tiêu chí 3: {'ĐẠT' if all_ok else 'KHÔNG ĐẠT'}.**")
    if a.json:
        with open(a.json, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"nhom": by_group, "tieu_chi_3": {"sinh_ra": g, "phat_lai": r, "dat": all_ok},
                       "theo_gio": by_hour}, f, ensure_ascii=False, indent=1)
    return 0


def cmd_tieuchi(a):
    """Chấm các tiêu chí của ngày nén từ wouldblock.json, tongket.json, nguon.json, rules.txt trong thư mục kết quả."""
    rd = lambda n: json.load(open(os.path.join(a.dir, n), encoding="utf-8"))
    try:
        wb, tk, ng = rd("wouldblock.json"), rd("tongket.json"), rd("nguon.json")
    except (OSError, ValueError) as e:
        print(f"(không chấm được tiêu chí: {e})"); return 0
    hours = [int(h) for h in ng.get("khung_gio", [])]
    want = [75, 300, 7200][:sum(1 for h in hours if h in SEED_HOURS)]
    bad = wb.get("ip_hop_le_bi_chan", [])
    rows = {r["ip"]: r for r in wb.get("ip", [])}
    seed_ok, seed_txt = bool(want), []
    for ip in SEED_IPS:
        ttl = [t for t in (rows.get(ip) or {}).get("ttl_s", []) if t is not None]
        seed_ok &= [int(t) for t in ttl] == want
        seed_txt.append(f"{ip}: {ttl or 'không có quyết định'}")
    try:
        rules = [ln.strip() for ln in open(os.path.join(a.dir, "rules.txt"), encoding="utf-8") if ln.strip()]
    except OSError:
        rules = []
    P = print
    P("| # | Tiêu chí | Số đo | Kết quả |"); P("|---|---|---|---|")
    P(f"| 1 | 0 quyết định \"sẽ chặn\" vào IP hợp lệ | {len(bad)} IP hợp lệ có quyết định"
      + (f" ({', '.join(bad[:10])})" if bad else "") + f" | {'ĐẠT' if not bad else 'KHÔNG ĐẠT'} |")
    unk = [r for r in wb.get("ip", []) if r.get("vai") == "khong_ro"]
    P("| 1c | Quyết định vào IP KHÔNG có trong danh sách phân vai (phải xem tay; > 0 = công cụ phân vai còn sót) | "
      + (f"{len(unk)} IP: " + "; ".join(f"{r['ip']} ({'; '.join(r.get('ly_do', []))})" for r in unk[:10]) if unk else "0 IP")
      + f" | {'CẦN XEM TAY' if unk else 'ĐẠT'} |")
    rp = wb.get("phat_lai_co_quyet_dinh", [])
    P("| 1b | Quyết định \"sẽ chặn\" vào IP phát lại lưu lượng thật (ghi nhận riêng, không tính vào tiêu chí 1) | "
      + ("; ".join(f"{x['ip']} lúc {', '.join(x['luc'])}: {'; '.join(x['ly_do'])}, {x['so_404']}/{x['so_request']} request trả 404"
                   for x in rp) or "không có") + " | ghi nhận |")
    P(f"| 2 | Hai IP gieo có \"sẽ chặn\" ở mỗi giờ gieo, ttl_s tăng dần (kỳ vọng {want or 'không có giờ gieo'}) | "
      + "; ".join(seed_txt) + f" | {'ĐẠT' if seed_ok else ('không áp dụng' if not want else 'KHÔNG ĐẠT')} |")
    c = tk.get("tieu_chi_3", {})
    g, r = c.get("sinh_ra", {}), c.get("phat_lai", {})
    P(f"| 3 | Vai hợp lệ: 429 ≤ 1 %; Cổng 2 chặn ≤ 1 % (sinh ra), ≤ 5 % (phát lại); thành công ≥ 99 % (sinh ra) | "
      f"sinh ra {g.get('sent', 0)} request: {g.get('gate2', 0)} bị Cổng 2 chặn, {g.get('limit', 0)} lần 429, "
      f"{g.get('pass', 0)} thành công; phát lại {r.get('sent', 0)} request: {r.get('gate2', 0)} bị Cổng 2 chặn, "
      f"{r.get('limit', 0)} lần 429 | {'ĐẠT' if c.get('dat') else 'KHÔNG ĐẠT'} |")
    P(f"| 4 | Vòng đời luật tự sinh (chỉ ghi nhận) | {' / '.join(rules[:4]) or 'không đọc được'} | ghi nhận |")
    P("| 5 | Sau đợt thử hệ thống về trạng thái gốc | kiểm sau khi script kết thúc (tham số in ở cuối, và kiểm tay) | kiểm tay |")
    P()
    P("Tiêu chí 1 tính trên khách hợp lệ của chính ứng dụng. Lưu lượng phát lại là URL của website khác gửi vào DVWA, phần "
      "lớn trả 404 — khách thật của ứng dụng không tạo ra mẫu đó — nên quyết định vào các IP này được liệt kê riêng ở dòng 1b.")
    P("Tiêu chí 3 không tính 70 giây đầu của giờ 01 (lúc đó Cổng 2 cố ý chỉ ghi nhận). "
      "Ngưỡng của tiêu chí 2 theo `TTL_STEPS_S=75,300,7200`.")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("sinh"); p.add_argument("--dir", default=OUT_DIR); p.set_defaults(fn=cmd_sinh)
    p = sub.add_parser("nguon"); p.add_argument("--hours", required=True); p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_nguon)
    p = sub.add_parser("tongket"); p.add_argument("dir"); p.add_argument("--json"); p.set_defaults(fn=cmd_tongket)
    p = sub.add_parser("tieuchi"); p.add_argument("dir"); p.set_defaults(fn=cmd_tieuchi)
    a = ap.parse_args()
    return a.fn(a) or 0


if __name__ == "__main__":
    sys.exit(main())

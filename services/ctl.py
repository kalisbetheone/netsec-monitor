"""ctl: công cụ quản trị, chạy qua tools/nsmctl.sh (container dùng một lần, tài khoản Kafka 'ctl').

  blocks                  liệt kê IP đang bị chặn (đọc tệp trạng thái của responder, chỉ đọc)
  exempt                  liệt kê dải miễn trừ (cấu hình + thêm lúc chạy)
  unblock <ip>            gỡ chặn một IP ngay, không đụng tới các IP khác
  exempt-add <cidr>       thêm dải miễn trừ lúc đang chạy (IP đang bị chặn trong dải được gỡ luôn)
  exempt-del <cidr>       bỏ một dải đã thêm bằng exempt-add
  mode                    xem chế độ của responder: enforce (chặn thật) hay dryrun (chạy thử: chỉ ghi "sẽ chặn")
  mode dryrun|enforce     đổi chế độ ngay, không khởi động lại; lệnh chặn thật đang có giữ nguyên tới khi hết hạn
  rules                   liệt kê luật tự sinh đang sống (mã, lớp, trạng thái, đích, nội dung, số lần khớp thật)
  rule-revoke <mã>        gỡ MỘT luật tự sinh ngay (Cổng 2 áp dụng trong vài giây); luật đó không bị sinh lại trong 24 giờ
  rule-revoke-all         gỡ mọi luật tự sinh đang sống

Lệnh thay đổi được gửi vào topic nsm.control (chỉ tài khoản 'ctl' được ghi; responder đọc các lệnh chặn/miễn trừ/chế
độ, rulegen đọc các lệnh rule-*), rồi chờ bên thi hành xác nhận qua nhật ký kiểm toán (audit-decisions).
Không lệnh nào xoá trạng thái.
"""
import ipaddress, json, logging, sys, time, uuid
from common import es_client, iso, load_json, producer

logging.getLogger("elastic_transport").setLevel(logging.WARNING)     # công cụ dòng lệnh: chỉ in kết quả

STATE_PATH = "/state/responder.json"      # volume của responder, gắn CHỈ ĐỌC vào container này
RULES_PATH = "/rstate/rules.json"         # volume của rulegen, gắn CHỈ ĐỌC
WAIT_S = 25

def die(msg, code=2):
    print(msg, file=sys.stderr); sys.exit(code)

def left(sec):
    sec = int(max(0, sec))
    return f"{sec // 3600}h{sec % 3600 // 60:02d}m" if sec >= 3600 else f"{sec // 60}m{sec % 60:02d}s"

def cmd_blocks():
    st = load_json(STATE_PATH, None)
    if st is None: die("!! chưa đọc được trạng thái của responder (responder đã chạy chưa?)", 1)
    now = time.time()
    rows = sorted(((ip, r) for ip, r in (st.get("blocks") or {}).items() if r.get("active") and r.get("expires", 0) > now),
                  key=lambda x: x[1]["expires"])
    if not rows:
        print("Không có IP nào đang bị chặn."); return
    print(f"{'IP':<40} {'còn lại':>9}  {'lần vi phạm':>11}  hết hạn (UTC)")
    for ip, r in rows:
        print(f"{ip:<40} {left(r['expires'] - now):>9}  {r.get('offenses', 1):>11}  {iso(r['expires'])}")
    print(f"Tổng: {len(rows)} IP.")

def cmd_exempt():
    st = load_json(STATE_PATH, None)
    if st is None: die("!! chưa đọc được trạng thái của responder (responder đã chạy chưa?)", 1)
    print("Miễn trừ theo cấu hình (EXEMPT_CIDRS, sửa trong docker-compose.yml):")
    for c in st.get("exempt_env") or ["(chưa có — responder chưa lưu trạng thái lần nào)"]: print("  " + c)
    print("Miễn trừ thêm lúc chạy (nsmctl exempt-add):")
    for c in st.get("exempt_extra") or ["(không có)"]: print("  " + c)

def cmd_mode():
    st = load_json(STATE_PATH, None)
    if st is None: die("!! chưa đọc được trạng thái của responder (responder đã chạy chưa?)", 1)
    m = st.get("mode")
    now = time.time()
    would = [k for k, r in (st.get("would") or {}).items() if r.get("active") and r.get("expires", 0) > now]
    print(f"Chế độ đặt lúc chạy: {m or '(chưa đặt — theo biến RESPONDER_MODE trong docker-compose.yml)'}")
    if would:
        print(f'Đang "sẽ chặn" (chạy thử) {len(would)} nguồn:')
        for k in sorted(would): print("  " + k)

def cmd_rules():
    st = load_json(RULES_PATH, None)
    if st is None: die("!! chưa đọc được trạng thái của rulegen (rulegen đã chạy chưa?)", 1)
    now = time.time()
    live = sorted((r for r in (st.get("rules") or {}).values() if r.get("state") in ("shadow", "active")), key=lambda r: r["id"])
    if not live:
        print("Không có luật tự sinh nào đang sống."); return
    print(f"{'mã':<9} {'lớp':<5} {'trạng thái':<10} {'còn lại':>8} {'khớp thật':>9}  đích / nội dung")
    for r in live:
        ttl = left(r["expires"] - now) if r.get("expires") else "—"
        print(f"{r['id']:<9} {r.get('class', ''):<5} {r['state']:<10} {ttl:>8} {r.get('hits_real', 0):>9}  "
              f"{r.get('target', '')}  {str(r.get('token'))[:90]}")
    print(f"Tổng: {len(live)} luật. Gỡ một luật: nsmctl rule-revoke <mã>")

def send(cmd, **args):
    cid = uuid.uuid4().hex
    err = {}
    p = producer()
    p.produce("nsm.control", key=b"control", value=json.dumps({"cmd": cmd, "id": cid, "ts": time.time(), **args}).encode(),
              callback=lambda e, m: err.update(e=str(e)) if e else None)
    p.flush(15)
    if err: die(f"!! không gửi được lệnh vào Kafka: {err['e']}", 1)
    es = es_client()
    deadline = time.time() + WAIT_S
    while time.time() < deadline:
        time.sleep(1.5)
        try:
            hits = es.search(index="audit-decisions-*", ignore_unavailable=True, size=1,
                             query={"term": {"ctl_id.keyword": cid}})["hits"]["hits"]
        except Exception:
            hits = []
        if hits: return hits[0]["_source"]
    die(f"!! đã gửi lệnh nhưng chưa thấy responder xác nhận sau {WAIT_S} s — xem: docker compose logs --tail 20 responder", 1)

def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__); return
    c, rest = argv[0], argv[1:]
    if c == "blocks": return cmd_blocks()
    if c == "exempt": return cmd_exempt()
    if c == "unblock" and len(rest) == 1:
        try: ip = str(ipaddress.ip_address(rest[0]))
        except ValueError: die(f"!! '{rest[0]}' không phải địa chỉ IP")
        d = send("unblock", ip=ip)
        if d.get("decision") != "unblock": die(f"!! responder từ chối: {d.get('reason')}", 1)
        print(f"Đã gỡ chặn {ip}." if d.get("was_blocked") else f"{ip} không nằm trong danh sách chặn (bộ đếm của IP này đã được xoá).")
        print("Cổng 1 áp dụng trong vài giây (nginx nạp lại danh sách).")
        return
    if c in ("exempt-add", "exempt-del") and len(rest) == 1:
        try: net = str(ipaddress.ip_network(rest[0], strict=False))
        except ValueError: die(f"!! '{rest[0]}' không phải dải địa chỉ (vd 10.10.10.0/28 hoặc 10.10.10.66)")
        d = send(c.replace("-", "_"), cidr=net)
        if d.get("decision") == "ctl_reject":
            die(f"!! responder từ chối: {d.get('reason')}" +
                (" (dải này không nằm trong danh sách thêm lúc chạy; dải theo cấu hình phải sửa trong docker-compose.yml)"
                 if d.get("reason") == "not_in_runtime_list" else ""), 1)
        print(("Đã thêm miễn trừ " if c == "exempt-add" else "Đã bỏ miễn trừ ") + net + ".")
        return
    if c == "mode" and not rest: return cmd_mode()
    if c == "mode" and len(rest) == 1 and rest[0] in ("dryrun", "enforce"):
        d = send("mode", mode=rest[0])
        if d.get("decision") != "mode": die(f"!! responder từ chối: {d.get('reason')}", 1)
        print(f"Chế độ responder: {d.get('mode_before')} -> {d.get('mode')}." +
              (' Từ giờ chỉ ghi "sẽ chặn" (would_block), không gửi lệnh chặn mới.' if rest[0] == "dryrun" else " Từ giờ chặn thật."))
        return
    if c == "rules" and not rest: return cmd_rules()
    if c == "rule-revoke" and len(rest) == 1 and rest[0].isdigit():
        d = send("rule_revoke", rule_id=int(rest[0]))
        if d.get("decision") != "rule_revoke": die(f"!! rulegen từ chối: {d.get('reason')}", 1)
        print(f"Đã gỡ luật {rest[0]} ({d.get('cls')} @ {d.get('target')}). Cổng 2 áp dụng trong vài giây; luật này không bị sinh lại trong 24 giờ.")
        return
    if c == "rule-revoke-all" and not rest:
        d = send("rule_revoke_all")
        if d.get("decision") != "rule_revoke_all": die(f"!! rulegen từ chối: {d.get('reason')}", 1)
        print(f"Đã gỡ {d.get('revoked')} luật tự sinh.")
        return
    die("!! lệnh không hợp lệ. Dùng: blocks | exempt | unblock <ip> | exempt-add <cidr> | exempt-del <cidr> | "
        "mode [dryrun|enforce] | rules | rule-revoke <mã> | rule-revoke-all")

if __name__ == "__main__":
    main(sys.argv[1:])

"""ctl: công cụ quản trị, chạy qua tools/nsmctl.sh (container dùng một lần, tài khoản Kafka 'ctl').

  blocks                  liệt kê IP đang bị chặn (đọc tệp trạng thái của responder, chỉ đọc)
  exempt                  liệt kê dải miễn trừ (cấu hình + thêm lúc chạy)
  unblock <ip>            gỡ chặn một IP ngay, không đụng tới các IP khác
  exempt-add <cidr>       thêm dải miễn trừ lúc đang chạy (IP đang bị chặn trong dải được gỡ luôn)
  exempt-del <cidr>       bỏ một dải đã thêm bằng exempt-add

Lệnh thay đổi được gửi vào topic nsm.control (chỉ tài khoản 'ctl' được ghi; responder là bên duy nhất đọc),
rồi chờ responder xác nhận qua nhật ký kiểm toán (audit-decisions). Không lệnh nào xoá trạng thái.
"""
import ipaddress, json, logging, sys, time, uuid
from common import es_client, iso, load_json, producer

logging.getLogger("elastic_transport").setLevel(logging.WARNING)     # công cụ dòng lệnh: chỉ in kết quả

STATE_PATH = "/state/responder.json"      # volume của responder, gắn CHỈ ĐỌC vào container này
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
    die("!! lệnh không hợp lệ. Dùng: blocks | exempt | unblock <ip> | exempt-add <cidr> | exempt-del <cidr>")

if __name__ == "__main__":
    main(sys.argv[1:])

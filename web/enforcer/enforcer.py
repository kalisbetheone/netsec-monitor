"""enforcer: agent cưỡng chế trên máy WEB.

Đọc lệnh từ Kafka (do responder/rulegen trên SOC gửi) rồi ghi vào tệp cấu hình
của hai cổng chặn. nginx và apache tự phát hiện tệp đổi và tự nạp lại,
nên enforcer KHÔNG cần quyền điều khiển container nào khác.

Topic tiêu thụ:
  enforce.blocklist : responder gửi toàn bộ danh sách IP đang chặn (snapshot).
                      payload: {"ips": ["10.10.10.66", ...], "fps": [["10.10.10.5", "<User-Agent>"], ...], "ts": <epoch>}
                      fps = chặn theo (IP, User-Agent) cho IP dùng chung (D1) -> blockfp.map
  enforce.rules     : rulegen gửi toàn bộ nội dung tệp luật ModSecurity.
                      payload: {"conf": "<nội dung autogen.conf>", "sha": "...", "ts": <epoch>}

Topic phát:
  enforce.status    : báo kết quả thi hành về SOC.
                      {"kind":"blocklist|rules","ok":true,"sha":"...","count":N,"ts":...}

An toàn:
  * Chỉ ghi những gì ĐÚNG ĐỊNH DẠNG: IP phải là địa chỉ hợp lệ; mỗi dòng luật phải khớp đúng mẫu
    SecRule do rulegen sinh. Nội dung lạ trên Kafka không thể thành chỉ thị nginx/Apache tuỳ ý.
  * Snapshot có `ts` cũ hơn bản đã áp bị bỏ qua (không để bản cũ ghi đè bản mới).
  * Không chặn vòng lặp khi chờ Apache kiểm cú pháp: lệnh chặn IP đến trong lúc đó vẫn được ghi ngay.
"""
import ipaddress, json, os, re, time
from common import Heartbeat, atomic_write, consumer, install_stop, load_json, log, producer, running

L = log("enforcer")
MAP_PATH   = "/blocklist/blocklist.map"
FP_PATH    = "/blocklist/blockfp.map"         # khoá "<ip>|<User-Agent>" cho map "$remote_addr|$http_user_agent" của nginx
UA_SAFE = re.compile(r'^[\x20-\x21\x23\x25-\x5b\x5d-\x7e]{0,256}$')   # không có " \ $ -> không phá được cú pháp nginx
RULES_PATH = "/rules/published/autogen.conf"
STATUS_JSON = "/rules/status.json"          # do watcher của apache ghi sau apachectl -t
RULES_WAIT = float(os.getenv("RULES_WAIT_S", "40"))

RULE_LINE = re.compile(
    r'^SecRule ARGS(?::[a-z0-9_.\-]{1,32})? '
    r'"@(?:contains [^"\\]{1,64}|rx (?:[^"\\]|\\.){1,400})" '
    # luật g0: t:urlDecodeUni,t:lowercase; luật đặc tả (G2r) thêm bộ biến đổi theo lớp — chỉ các tên trong
    # danh sách trắng của services/secrule.py (TRANSFORMS), luôn bắt đầu bằng urlDecodeUni
    r'"id:99\d{5},phase:2,t:none,t:urlDecodeUni,'
    r'(?:t:(?:removeNulls|replaceComments|htmlEntityDecode|normalizePathWin|compressWhitespace|lowercase),){1,6}'
    r'(?:deny,status:403|pass),log,'
    r"msg:'autogen [a-z]+ (?:shadow|active)',tag:'autogen/(?:shadow|active)'\"$")

last_ts = {"blocklist": 0.0, "rules": 0.0}
pending = None      # {"sha":..., "deadline":...} — đang chờ Apache báo kết quả kiểm cú pháp

def stale(kind, payload):
    ts = float(payload.get("ts") or 0)
    if ts and ts < last_ts[kind]:
        L.warning("bỏ qua %s cũ (ts=%.3f < đã áp %.3f)", kind, ts, last_ts[kind]); return True
    if ts: last_ts[kind] = ts
    return False

def write_blocklist(payload, p):
    if stale("blocklist", payload): return
    ips, bad = set(), 0
    for i in payload.get("ips", []):
        try: ips.add(str(ipaddress.ip_address(str(i).strip())))
        except ValueError: bad += 1
    if bad: L.warning("bỏ %d mục không phải địa chỉ IP trong enforce.blocklist", bad)
    fps, bad_fp = set(), 0
    for item in payload.get("fps", []) or []:
        try:
            ip, ua = item
            ip = str(ipaddress.ip_address(str(ip).strip())); ua = str(ua)
            if not UA_SAFE.match(ua): raise ValueError
            fps.add((ip, ua))
        except (ValueError, TypeError):
            bad_fp += 1
    if bad_fp: L.warning("bỏ %d dấu vân tay không hợp lệ trong enforce.blocklist", bad_fp)
    # ghi tệp dấu vân tay TRƯỚC: nginx nạp lại khi thấy blocklist.map đổi và đọc cả hai tệp
    atomic_write(FP_PATH, "# managed by enforcer — do not edit\n" + "".join(f'"{ip}|{ua}" 1;\n' for ip, ua in sorted(fps)))
    body = "# managed by enforcer — do not edit\n" + "".join(f"{ip} 1;\n" for ip in sorted(ips))
    atomic_write(MAP_PATH, body)
    L.info("blocklist.map: %d IP, blockfp.map: %d dấu vân tay", len(ips), len(fps))
    p.produce("enforce.status", key=b"blocklist", value=json.dumps(
        {"kind": "blocklist", "ok": True, "count": len(ips), "fp_count": len(fps), "ts": time.time()}).encode())

def valid_rules(conf):
    for n, line in enumerate(conf.splitlines(), 1):
        if not line.strip() or line.startswith("#"): continue
        if not RULE_LINE.match(line): return n
    return 0

def send_rules_status(p, sha, ok, why=None):
    L.info("apache configtest sha=%s ok=%s%s", sha, ok, f" ({why})" if why else "")
    p.produce("enforce.status", key=b"rules", value=json.dumps(
        {"kind": "rules", "ok": ok, "sha": sha, "why": why, "ts": time.time()}).encode())

def write_rules(payload, p):
    global pending
    if stale("rules", payload): return
    conf, sha = str(payload.get("conf", "")), str(payload.get("sha", ""))
    bad = valid_rules(conf)
    if bad:
        L.error("từ chối tệp luật sha=%s: dòng %d không đúng mẫu SecRule tự sinh", sha, bad)
        return send_rules_status(p, sha, False, f"invalid_line_{bad}")
    os.makedirs(os.path.dirname(RULES_PATH), exist_ok=True)
    atomic_write(RULES_PATH, conf)
    L.info("autogen.conf ghi (sha=%s), chờ apache kiểm tra cú pháp...", sha)
    pending = {"sha": sha, "deadline": time.time() + RULES_WAIT}

def poll_rules_status(p):
    """Không chặn: xem watcher của apache đã ghi kết quả cho sha đang chờ chưa."""
    global pending
    if pending is None: return
    st = load_json(STATUS_JSON, {})
    if str(st.get("sha", ""))[:16] == pending["sha"][:16]:
        send_rules_status(p, pending["sha"], bool(st.get("ok"))); pending = None
    elif time.time() > pending["deadline"]:
        send_rules_status(p, pending["sha"], None, "timeout"); pending = None

def main():
    install_stop()
    p = producer()
    c = consumer("enforcer", ["enforce.blocklist", "enforce.rules"])
    hb = Heartbeat("enforcer")          # máy WEB không nối Elasticsearch -> nhịp tim đi qua Kafka (logsink ghi hộ)
    L.info("enforcer started, bootstrap=%s", os.getenv("KAFKA_BOOTSTRAP"))
    while running():
        msg = c.poll(0.5)
        if msg is not None and msg.error():
            L.warning("kafka: %s", msg.error())
        elif msg is not None:
            try:
                payload = json.loads(msg.value()); hb.inc()
                if msg.topic() == "enforce.blocklist": write_blocklist(payload, p)
                else: write_rules(payload, p)
            except Exception:
                L.exception("lỗi xử lý lệnh")
        poll_rules_status(p)
        d = hb.tick(c, pending_rules=pending is not None)
        if d:
            p.produce("enforce.status", key=b"heartbeat",
                      value=json.dumps({"kind": "heartbeat", "doc": d, "ts": time.time()}).encode())
        p.poll(0)
    p.flush(5); c.close()

if __name__ == "__main__":
    main()

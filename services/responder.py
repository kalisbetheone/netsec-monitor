"""responder: tiêu thụ alerts → quyết định chặn (ngưỡng, TTL tăng dần, bộ dọn) →
GỬI snapshot danh sách IP qua Kafka topic enforce.blocklist; kiểm toán vào ES.

Chuỗi kiểm tra (đúng thứ tự của tài liệu mô tả, mục 2.2):
  1. miễn trừ  2. độ tin cậy >= θ  3. tuổi sự kiện  4. đếm ngưỡng  5. chặn kèm TTL  6. kiểm toán
Cửa sổ đếm dùng THỜI ĐIỂM SỰ KIỆN (alert.ts), không phải lúc xử lý; một request do hai cảm
biến cùng báo (nhật ký web + Suricata) chỉ được tính MỘT lần.

Ngoài cảnh báo, responder còn nhận LỆNH QUẢN TRỊ ở topic nsm.control (do tools/nsmctl.sh gửi; chỉ tài
khoản Kafka 'ctl' ghi được topic này): gỡ chặn một IP, thêm/bớt dải miễn trừ lúc đang chạy — không cần
xoá trạng thái hay khởi động lại. Mọi lệnh đều được ghi kiểm toán.

Thời hạn chặn theo bậc của tài liệu mô tả (E4): 15 phút → 1 giờ → 24 giờ (TTL_STEPS_S).

IP dùng chung (D1 — nhiều người sau một NAT): IP thuộc SHARED_CIDRS, hoặc được tier3 báo là có nhiều
User-Agent khác nhau trong cùng cửa sổ (thông điệp kind=ip_profile), thì bị chặn theo cặp (IP, User-Agent)
thay vì cả IP — người dùng khác sau cùng NAT không bị chặn theo. Kẻ tấn công đổi User-Agent liên tục thì
khi đủ SHARED_ESCALATE dấu vân tay bị chặn, cả IP bị chặn.
"""
import bisect, ipaddress, json, os, re, time
from collections import defaultdict
from urllib.parse import unquote
from common import (EsBuffer, Heartbeat, atomic_write, consumer, day_index, es_client, install_stop, iso,
                    load_json, log, producer, running)

L = log("responder")
VERSION = "responder v2.1"
EXEMPT = [ipaddress.ip_network(c.strip()) for c in os.getenv("EXEMPT_CIDRS", "127.0.0.0/8,10.10.30.0/24").split(",") if c.strip()]
MIN_CONF = float(os.getenv("MIN_CONFIDENCE", "0.90"))       # θ của tài liệu mô tả
MAX_AGE = float(os.getenv("MAX_AGE_S", "600"))              # bỏ cảnh báo cũ hơn 10 phút (E1)
WINDOW = float(os.getenv("WINDOW_S", "60"))
THRESHOLD = int(os.getenv("THRESHOLD", "5"))
LONG_WINDOW = float(os.getenv("LONG_WINDOW_S", "86400"))    # B5: cửa sổ quan sát dài 24h
LONG_THRESHOLD = int(os.getenv("LONG_THRESHOLD", "20"))     # phải LỚN HƠN THRESHOLD (xem cảnh báo lúc khởi động)
DEDUP_S = float(os.getenv("DEDUP_S", "5"))                  # cùng request, khác cảm biến, trong khoảng này = 1 lần
BASE_TTL = int(os.getenv("BASE_TTL_S", "900"))
MAX_TTL = int(os.getenv("MAX_TTL_S", "86400"))
# Bậc thời hạn theo số lần vi phạm (lần 1, 2, 3+). Để trống thì dùng BASE_TTL_S nhân đôi mỗi lần (kiểu cũ).
TTL_STEPS = [int(x) for x in os.getenv("TTL_STEPS_S", "900,3600,86400").split(",") if x.strip()]
SHARED_CIDRS = [ipaddress.ip_network(c.strip(), strict=False) for c in os.getenv("SHARED_CIDRS", "").split(",") if c.strip()]
SHARED_TTL = float(os.getenv("SHARED_TTL_S", "3600"))       # tier3 báo IP dùng chung -> nhớ trong ngần này
SHARED_ESCALATE = int(os.getenv("SHARED_ESCALATE", "3"))    # số dấu vân tay bị chặn cùng lúc trên một IP -> chặn cả IP
# User-Agent ghi được vào khoá map của nginx: ASCII in được, không có " \ $ (không thì chặn cả IP như cũ)
UA_SAFE = re.compile(r'^[\x20-\x21\x23\x25-\x5b\x5d-\x7e]{0,256}$')
OFFENSE_RESET = int(os.getenv("OFFENSE_RESET_S", str(7*86400)))
SWEEP_S = 10
CTL_MAX_AGE = float(os.getenv("CTL_MAX_AGE_S", "120"))      # lệnh quản trị cũ hơn ngần này bị bỏ (không phát lại lệnh cũ)
STATE_PATH = "/state/responder.json"

state = load_json(STATE_PATH, {"blocks": {}})
if not isinstance(state, dict):
    state = {}
state.setdefault("blocks", {})   # chịu được state cũ/hỏng thiếu khoá
if not isinstance(state.get("exempt_extra"), list): state["exempt_extra"] = []   # dải miễn trừ thêm lúc chạy (nsmctl)
if not isinstance(state.get("shared"), dict): state["shared"] = {}               # ip -> hạn (epoch) được coi là IP dùng chung
def _nets(items):
    out = []
    for c in items:
        try: out.append(ipaddress.ip_network(str(c).strip(), strict=False))
        except ValueError: pass
    return out
EXTRA = _nets(state["exempt_extra"])
hits = defaultdict(list)         # ip -> [ts sự kiện] đã sắp xếp, trong cửa sổ dài
for _ip, _ts in (state.get("hits") or {}).items():           # khôi phục bộ đếm sau khi khởi động lại
    if isinstance(_ts, list): hits[_ip] = sorted(float(t) for t in _ts)
seen = defaultdict(dict)         # ip -> {dấu vân tay request: {"t0": ts, "c": {nguồn: số lần}}}
dirty = False
es_buf = None
prod = None

def split_key(key):
    """Khoá chặn: '<ip>' (cả IP) hoặc '<ip>|<User-Agent>' (dấu vân tay, D1)."""
    ip, sep, ua = str(key or "").partition("|")
    return ip, (ua if sep else None)

def audit(decision, ip, reason, alert=None, **extra):
    ip, ua = split_key(ip) if ip else (ip, None)
    doc = {"@timestamp": iso(), "decision": decision, "src_ip": ip, "reason": reason,
           "decided_by": VERSION, **extra}
    if ua is not None: doc.update(scope="fingerprint", fp_ua=ua)
    if alert:
        doc.update(alert_id=alert.get("alert_id"), cls=alert.get("class"),
                   confidence=alert.get("confidence"), alert_source=alert.get("source"))
    es_buf.add(day_index("audit-decisions"), doc)

def save_state():
    global dirty
    state["hits"] = {ip: ts for ip, ts in hits.items() if ts}
    state["exempt_env"] = [str(n) for n in EXEMPT]            # chỉ để nsmctl hiển thị; nguồn thật là biến môi trường
    atomic_write(STATE_PATH, json.dumps(state)); dirty = False

def publish_blocklist():
    now = time.time()
    active = sorted(k for k, r in state["blocks"].items() if r.get("active") and r["expires"] > now)
    ips = [k for k in active if "|" not in k]
    fps = [list(split_key(k)) for k in active if "|" in k]
    # key cố định -> mọi snapshot vào CÙNG partition -> enforcer nhận đúng thứ tự phát
    prod.produce("enforce.blocklist", key=b"blocklist", value=json.dumps({"ips": ips, "fps": fps, "ts": now}).encode())
    prod.flush(5)
    save_state()
    L.info("enforce.blocklist gửi: %d IP, %d dấu vân tay", len(ips), len(fps))

def exempt(ip): return any(ip in n for n in EXEMPT) or any(ip in n for n in EXTRA)

def control(c):
    """Một lệnh quản trị từ nsm.control. Trả tên quyết định đã ghi kiểm toán."""
    global EXTRA, dirty
    now = time.time()
    cmd, cid = str(c.get("cmd") or ""), str(c.get("id") or "")[:64]
    try: age = now - float(c.get("ts"))
    except (TypeError, ValueError): age = float("inf")
    if abs(age) > CTL_MAX_AGE:
        audit("ctl_reject", None, "stale", ctl_id=cid, cmd=cmd); return "ctl_reject"
    try:
        if cmd == "unblock":
            ip = str(ipaddress.ip_address(str(c.get("ip") or "").strip()))
            was = False
            for k in [k for k in state["blocks"] if split_key(k)[0] == ip]:   # cả IP lẫn mọi dấu vân tay của IP đó
                rec = state["blocks"].pop(k)                   # gỡ hẳn: admin xác nhận chặn nhầm -> không tính tái phạm
                was = was or bool(rec.get("active") and rec["expires"] > now)
            for k in [k for k in list(hits) + list(seen) if split_key(k)[0] == ip]:
                hits.pop(k, None); seen.pop(k, None)
            publish_blocklist()
            audit("unblock", ip, "manual", ctl_id=cid, was_blocked=was); return "unblock"
        if cmd in ("exempt_add", "exempt_del"):
            net = ipaddress.ip_network(str(c.get("cidr") or "").strip(), strict=False)
            cur = {str(n) for n in EXTRA}
            if cmd == "exempt_add":
                cur.add(str(net))
                for k in [k for k in state["blocks"] if ipaddress.ip_address(split_key(k)[0]) in net]:   # đang chặn -> gỡ luôn
                    state["blocks"].pop(k, None); hits.pop(k, None); seen.pop(k, None)
            else:
                if str(net) not in cur:
                    audit("ctl_reject", str(net), "not_in_runtime_list", ctl_id=cid, cmd=cmd); return "ctl_reject"
                cur.discard(str(net))
            state["exempt_extra"] = sorted(cur); EXTRA = _nets(state["exempt_extra"])
            publish_blocklist()                                # cũng lưu trạng thái
            audit(cmd, str(net), "manual", ctl_id=cid); return cmd
    except ValueError:
        audit("ctl_reject", str(c.get("ip") or c.get("cidr") or "")[:64], "invalid_argument", ctl_id=cid, cmd=cmd)
        return "ctl_reject"
    audit("ctl_reject", None, "unknown_command", ctl_id=cid, cmd=cmd[:32]); return "ctl_reject"

def fingerprint(a):
    """Dấu vân tay của REQUEST gây ra cảnh báo (URL đã chuẩn hoá) để khử đếm trùng giữa các cảm biến."""
    t = str(a.get("target") or "")
    if not t: return None
    t = t.replace("+", " ")
    for _ in range(3):
        d = unquote(t)
        if d == t: break
        t = d
    return t.lower().strip()[:256]

def is_duplicate(key, a, ts):
    """True nếu cảnh báo này là bản thứ hai (từ cảm biến KHÁC) của một request đã được tính.
    Số request thật = số lần báo lớn nhất của một cảm biến trong DEDUP_S, nên cùng một URL
    gửi nhiều lần vẫn được đếm đủ."""
    fp = fingerprint(a)
    if not fp: return False
    src = str(a.get("source") or "?")
    rec = seen[key].get(fp)
    if rec is None or abs(ts - rec["t0"]) > DEDUP_S:
        seen[key][fp] = {"t0": ts, "c": {src: 1}}
        return False
    prev_max = max(rec["c"].values())
    rec["c"][src] = rec["c"].get(src, 0) + 1
    return rec["c"][src] <= prev_max

def ttl_for(offenses):
    if TTL_STEPS: t = TTL_STEPS[min(offenses, len(TTL_STEPS)) - 1]
    else: t = BASE_TTL * 2**(offenses-1)
    return min(t, MAX_TTL)

def block(key, rec, now, reason, a):
    offenses = rec["offenses"]+1 if rec and now - rec.get("last", 0) < OFFENSE_RESET else 1
    ttl = ttl_for(offenses)
    state["blocks"][key] = {"expires": now+ttl, "offenses": offenses, "last": now, "active": True}
    hits.pop(key, None); seen.pop(key, None)
    ip, ua = split_key(key)
    if ua is not None:                     # đủ nhiều dấu vân tay của cùng IP bị chặn cùng lúc -> chặn cả IP
        n_fp = sum(1 for k, r in state["blocks"].items()
                   if "|" in k and split_key(k)[0] == ip and r.get("active") and r["expires"] > now)
        if n_fp >= SHARED_ESCALATE:
            audit("block", key, reason, a, ttl_s=ttl, offenses=offenses, expires=iso(now+ttl))
            return block(ip, state["blocks"].get(ip), now, "shared_escalate", a)
    publish_blocklist()
    audit("block", key, reason, a, ttl_s=ttl, offenses=offenses, expires=iso(now+ttl))

def is_shared(ip_s, now):
    try: a = ipaddress.ip_address(ip_s)
    except ValueError: return False
    return any(a in n for n in SHARED_CIDRS) or state["shared"].get(ip_s, 0) > now

def fp_key(ip_s, a):
    """Khoá (IP, User-Agent) cho IP dùng chung; None nếu User-Agent không ghi được vào map của nginx."""
    ua = str(a.get("ua") if a.get("ua") is not None else "").strip()
    return f"{ip_s}|{ua}" if UA_SAFE.match(ua) else None

def decide(a):
    global dirty
    now = time.time()
    try: ip = ipaddress.ip_address(a.get("src_ip"))
    except (ValueError, TypeError): return audit("skip", a.get("src_ip"), "invalid_ip", a)
    key = str(ip)
    if a.get("kind") == "ip_profile":       # tier3: IP này có nhiều User-Agent khác nhau -> coi là IP dùng chung
        if exempt(ip): return None
        was = state["shared"].get(key, 0) > now
        state["shared"][key] = now + SHARED_TTL; dirty = True
        if not was: audit("profile", key, "shared_ip", uas=a.get("uas"))
        return None
    if exempt(ip): return audit("skip", key, "exempt", a)                                   # 1
    if float(a.get("confidence", 0)) < MIN_CONF: return audit("skip", key, "low_confidence", a)   # 2
    try: ts = float(a.get("ts", now))
    except (ValueError, TypeError): ts = now
    if now - ts > MAX_AGE: return audit("skip", key, "stale", a)                             # 3
    ts = min(ts, now)
    rec = state["blocks"].get(key)
    if rec and rec.get("active") and rec["expires"] > now: return audit("skip", key, "already_blocked", a)
    if is_shared(key, now):                 # D1: chặn theo (IP, User-Agent), không chặn cả NAT
        fk = fp_key(key, a)
        if fk is not None:
            key = fk; rec = state["blocks"].get(key)
            if rec and rec.get("active") and rec["expires"] > now: return audit("skip", key, "already_blocked", a)
    if a.get("immediate"):          # tầng 3 behaviour: đã tự gom cả cửa sổ hành vi -> không đếm lại
        return block(key, rec, now, f"immediate:{a.get('class')}", a)
    if is_duplicate(key, a, ts): return audit("skip", key, "duplicate_sensor", a)
    q = hits[key]; bisect.insort(q, ts); dirty = True                                        # 4
    ref = q[-1]
    del q[:bisect.bisect_left(q, ref - LONG_WINDOW)]
    n_short = len(q) - bisect.bisect_left(q, ref - WINDOW)
    n_long = len(q)
    short_hit, long_hit = n_short >= THRESHOLD, n_long >= LONG_THRESHOLD
    if not short_hit and not long_hit:
        return audit("count", key, f"{n_short}/{THRESHOLD} | {n_long}/{LONG_THRESHOLD}@long", a)
    block(key, rec, now, "threshold" if short_hit else "long_window", a)                     # 5 + 6

def sweep():
    global dirty
    now, changed = time.time(), False
    for ip, r in list(state["blocks"].items()):
        if r.get("active") and r["expires"] <= now:
            r["active"] = False; changed = True
            audit("unblock", ip, "ttl_expired", offenses=r["offenses"])
        elif not r.get("active") and now - r.get("last", 0) > OFFENSE_RESET:
            del state["blocks"][ip]; dirty = True
    for ip in list(hits):                                    # dọn bộ đếm đã hết cửa sổ (không để phình mãi)
        q = hits[ip]
        del q[:bisect.bisect_left(q, now - LONG_WINDOW)]
        if not q: del hits[ip]; dirty = True
    for ip in [i for i, t in state["shared"].items() if t <= now]:
        del state["shared"][ip]; dirty = True
    for ip in list(seen):
        fps = seen[ip]
        for fp in [f for f, r in fps.items() if now - r["t0"] > max(DEDUP_S * 4, 60)]: del fps[fp]
        if not fps: del seen[ip]
    if changed: publish_blocklist()
    elif dirty: save_state()

def main():
    global es_buf, prod
    install_stop()
    if LONG_THRESHOLD <= THRESHOLD and LONG_WINDOW >= WINDOW:
        L.warning("CẤU HÌNH: LONG_THRESHOLD=%d <= THRESHOLD=%d — ngưỡng cửa sổ dài sẽ luôn đạt trước, "
                  "THRESHOLD/WINDOW_S mất tác dụng. Hãy đặt LONG_THRESHOLD > THRESHOLD.", LONG_THRESHOLD, THRESHOLD)
    es_buf = EsBuffer(es_client(required=False)); prod = producer()
    os.makedirs("/state", exist_ok=True)
    sweep(); publish_blocklist()
    c = consumer("responder", ["alerts", "nsm.control"])
    hb = Heartbeat("responder", es_buf)
    L.info("%s started: θ=%.2f, ngắn %d/%ss, dài %d/%ss, tuổi tối đa %ss, thời hạn chặn %s", VERSION, MIN_CONF,
           THRESHOLD, WINDOW, LONG_THRESHOLD, LONG_WINDOW, MAX_AGE, TTL_STEPS or f"{BASE_TTL}×2^n")
    last_sweep = time.time()
    while running():
        msg = c.poll(0.5)
        if msg is not None and msg.error():
            L.warning("kafka: %s", msg.error())
        elif msg is not None:
            try:
                if msg.topic() == "nsm.control":
                    L.info("lệnh quản trị: %s", control(json.loads(msg.value())))
                else:
                    decide(json.loads(msg.value())); hb.inc()
            except Exception: L.exception("bad alert")
        if time.time() - last_sweep >= SWEEP_S:
            sweep(); last_sweep = time.time()
            hb.tick(c, blocked=sum(1 for r in state["blocks"].values() if r.get("active")), tracked_ips=len(hits),
                    shared_ips=len(state["shared"]))
        es_buf.maybe_flush(); prod.poll(0)
    L.info("responder dừng — lưu trạng thái")
    save_state(); es_buf.maybe_flush(force=True); prod.flush(5); c.close()

if __name__ == "__main__":
    main()

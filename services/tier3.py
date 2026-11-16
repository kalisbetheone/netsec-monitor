"""tier3: BEHAVIOUR-anomaly online. Gom web.logs theo cửa sổ TRƯỢT (IP, 60 giây gần nhất) ->
7 đặc trưng hành vi -> IsolationForest (học benign-only, tier3.joblib[behaviour]) + cổng
định hình -> alert 'immediate' khi bất thường. Bắt recon/bruteforce/enum/flood — thứ mà
classifier (xét TỪNG request) coi là benign nên tầng 1+2 không thấy.

Khác bản cũ:
  * Cửa sổ trượt, chấm lại sau mỗi EVAL_EVERY request hoặc HOP giây -> phát hiện trong vài giây,
    không phải chờ hết phút đồng hồ; một đợt tấn công không còn bị cắt đôi ở ranh giới phút.
  * Chịu được sự kiện đến lệch thứ tự (nhiều partition / phát lại): sự kiện giữ kèm thời điểm
    riêng, cửa sổ tính theo thời điểm sự kiện.
  * Cảnh báo mang THỜI ĐIỂM SỰ KIỆN -> responder lọc được cảnh báo cũ sau sự cố.
  * Cổng định hình là từng mẫu hình tấn công cụ thể (mỗi mẫu cần ĐỦ số lượng VÀ tỷ lệ), không
    còn 'chỉ cần 60% URI khác nhau' — điều mà mọi trình duyệt tải file tĩnh đều thoả.

Sửa sau đợt rà soát 12/11/2026:
  * Mẫu 'denied' (401/403 dồn dập) cần các mã từ chối rải trên ít nhất TIER3_MIN_DENY_URI đường dẫn khác
    nhau, hoặc phần lớn là 401: một người dùng gửi lại nhiều lần MỘT form bị CRS chặn nhầm không còn làm
    cả IP bị chặn (C4). Dò mật khẩu qua form vẫn do mẫu 'bruteforce' lo.
  * Thiếu tệp model: vẫn chạy bằng cổng định hình (mỗi mẫu vốn cần cả số lượng lẫn tỷ lệ), báo
    model_loaded=false trong nhịp tim thay vì đứng yên im lặng (T9).
  * IP có từ TIER3_SHARED_MIN_UA User-Agent khác nhau trong cửa sổ được báo cho responder là IP dùng chung
    (kind=ip_profile) để responder chặn theo (IP, User-Agent) thay vì cả NAT (D1).
"""
import ipaddress, json, os, time, uuid
from collections import Counter, deque
import joblib
from common import (EsBuffer, Heartbeat, consumer, day_index, es_client, install_stop, iso, log,
                    parse_json_line, producer, running)

L = log("tier3")
E = lambda k, d: float(os.getenv(k, d))
INTERNAL = [ipaddress.ip_network(c.strip()) for c in os.getenv("INTERNAL_CIDRS", "10.10.30.0/24").split(",") if c.strip()]
MODEL_PATH = os.getenv("TIER3_MODEL", "/models/tier3.joblib")
WINDOW = E("TIER3_WINDOW_MS", "60000") / 1000.0
HOP = E("TIER3_HOP_S", "10")
EVAL_EVERY = int(E("TIER3_EVAL_EVERY", "20"))
MIN_REQ = int(E("TIER3_MIN_REQ", "15"))
COOLDOWN = E("TIER3_COOLDOWN_S", "120")
CONFIRM = int(E("TIER3_CONFIRM", "1"))       # số lần chấm liên tiếp bị gắn cờ trước khi báo
MAX_EV = int(E("TIER3_MAX_EVENTS", "5000"))  # trần sự kiện giữ cho mỗi IP
# --- cổng định hình: mỗi mẫu hình cần cả SỐ LƯỢNG lẫn TỶ LỆ ---
N_HI = E("TIER3_N_HI", "100")                # flood: số request / cửa sổ
F404, MIN_404 = E("TIER3_FRAC404", "0.5"), E("TIER3_MIN_404", "10")            # recon: dò đường dẫn
FDENY, MIN_DENY = E("TIER3_FRAC_DENY", "0.5"), E("TIER3_MIN_DENY", "10")       # 401/403 dồn dập (dò mật khẩu, bị WAF chặn liên tục)
MIN_DENY_URI = E("TIER3_MIN_DENY_URI", "3")   # ...trên ít nhất ngần này đường dẫn khác nhau (hoặc phần lớn là 401)
MIN_DENY_SINGLE, FDENY_SINGLE = E("TIER3_MIN_DENY_SINGLE", "30"), E("TIER3_FRAC_DENY_SINGLE", "0.8")  # ...hoặc dồn vào MỘT
# đường dẫn nhưng rất dày (dò từng tham số để tìm cách vượt WAF); người dùng thật không gửi lại một form 30 lần / phút
SHARED_MIN_UA = int(E("TIER3_SHARED_MIN_UA", "4"))     # số User-Agent khác nhau / cửa sổ để coi IP là IP dùng chung (NAT)
SHARED_EVERY = E("TIER3_SHARED_EVERY_S", "300")         # báo lại tối đa mỗi ngần này giây / IP
FPOST, MIN_POST = E("TIER3_FRAC_POST", "0.8"), E("TIER3_MIN_POST", "30")       # bruteforce qua form POST
UQRATIO, MIN_ENUM = E("TIER3_UQRATIO", "0.9"), E("TIER3_MIN_ENUM", "30")       # enum: nhiều query khác nhau trên ít URI
# Request bị Cổng 1 GIỚI HẠN TỐC ĐỘ (429, 15/11/2026) không tới Apache nên không có trong web.logs. tier3 đọc thêm
# gate1.logs để vẫn thấy TOÀN BỘ lượng request một nguồn gửi (flood, dò mật khẩu vẫn được nhận ra đúng lúc như trước
# khi có giới hạn tốc độ), và có mẫu riêng 'ratelimit': nguồn vẫn dội request dù đang bị 429 liên tục.
MIN_429, F429 = E("TIER3_MIN_429", "40"), E("TIER3_FRAC_429", "0.3")
# CHIẾN DỊCH NHỒI TÀI KHOẢN PHÂN TÁN (15/11/2026). Mỗi IP chỉ thử vài lần nên các mẫu theo-từng-IP ở trên không thấy
# (kịch bản 10: 50 IP × 4 lần, 0 IP bị chặn). Bộ đếm này nhìn TOÀN HỆ THỐNG: trong một cửa sổ, nếu có >= STUFF_MIN_IPS
# địa chỉ mà MỖI địa chỉ thử đăng nhập >= STUFF_PER_IP lần, và tổng số lần thử của chúng >= STUFF_MIN_TOTAL, thì từng địa
# chỉ đó bị báo (mẫu 'stuffing'). Một người gõ sai mật khẩu vài lần KHÔNG bị báo trừ khi đang có cả chiến dịch.
# "Thử đăng nhập" = POST tới đường dẫn khớp TIER3_LOGIN_RE, hoặc bất kỳ phản hồi 401 nào (API trả 401 khi sai mật khẩu);
# từ 16/11/2026 lần đăng nhập rõ ràng thành công không được đếm (xem login_attempt bên dưới).
import re
LOGIN_RE = re.compile(os.getenv("TIER3_LOGIN_RE", r"/login"), re.I)
STUFF_PER_IP = int(E("TIER3_STUFF_PER_IP", "3"))
STUFF_MIN_IPS = int(E("TIER3_STUFF_MIN_IPS", "8"))
STUFF_MIN_TOTAL = int(E("TIER3_STUFF_MIN_TOTAL", "40"))
# 16/11/2026 — KHÔNG ĐẾM LẦN ĐĂNG NHẬP RÕ RÀNG THÀNH CÔNG (TIER3_LOGIN_COUNT=failed). Trước đó mọi POST tới /login đều được
# đếm, kể cả đăng nhập đúng, nên khi đang có chiến dịch thì khách thật đăng nhập >= 3 lần/phút bị khoá cùng botnet
# (client-booking bị khoá 7 lần trong hai ngày; Danh-sach-gioi-han, mục 23). Một POST tới đường dẫn đăng nhập:
#   - KHÔNG đếm khi RÕ RÀNG thành công: 3xx chuyển hướng tới trang KHÁC trang đăng nhập (profile.php, index.php);
#   - ĐẾM trong mọi trường hợp còn lại: >= 400 (401, 403, 429...), 3xx QUAY LẠI trang đăng nhập (DVWA: Location: login.php),
#     và 2xx — trang đăng nhập được trả lại kèm thông báo lỗi là cách báo sai mật khẩu phổ biến (DVWA trả 200 cho botnet của
#     kịch bản 10 và 38; vòng đo đầu ngày 16/11 coi 2xx là thành công nên bỏ lọt cả hai chiến dịch).
# Ứng dụng báo đăng nhập ĐÚNG bằng 200 (API trả token tại /login) thì đặt TIER3_LOGIN_2XX_OK=1. Cần trường "loc" (header
# Location của phản hồi) trong nhật ký truy cập — web/apache/logjson.conf; dòng nhật ký chưa có trường này thì 3xx được đếm
# như trước. TIER3_LOGIN_COUNT=all = cách đếm cũ.
LOGIN_COUNT = os.getenv("TIER3_LOGIN_COUNT", "failed")
LOGIN_2XX_OK = os.getenv("TIER3_LOGIN_2XX_OK", "0") == "1"
_LOC_HOST = re.compile(r"^[a-z][a-z0-9+.-]*://[^/]*", re.I)

def login_attempt(ev, status):
    """True nếu sự kiện là một lần thử đăng nhập được ĐẾM vào bộ đếm chiến dịch."""
    post_login = (ev.get("method") or "").upper() == "POST" and bool(LOGIN_RE.search(ev.get("uri") or ""))
    if LOGIN_COUNT == "all": return status == 401 or post_login
    if status == 401: return True
    if not post_login: return False
    if status >= 400: return True
    if 300 <= status < 400:
        if "loc" not in ev: return True               # nhật ký định dạng cũ: không biết chuyển hướng đi đâu -> đếm như trước
        loc = str(ev.get("loc") or "")
        if loc in ("", "-"): return False
        p = _LOC_HOST.sub("", loc.split("?", 1)[0].split("#", 1)[0])
        return bool(LOGIN_RE.search(p if p.startswith("/") else "/" + p))
    return not LOGIN_2XX_OK                           # 2xx (và 1xx): mơ hồ -> đếm, trừ khi ứng dụng báo thành công bằng 200

login_ev = deque(maxlen=200000)      # (ts, ip, ua) của mọi lần thử đăng nhập ĐƯỢC ĐẾM, toàn hệ thống
camp = {"last_alert": {}, "since": 0, "last_eval": 0.0, "max_ts": 0.0}

def attack_shape(d, c):
    """Trả tên mẫu hình tấn công mà cửa sổ thoả, hoặc None."""
    n = d["n_req"]
    if n >= N_HI: return "flood"
    if c.get("n429", 0) >= MIN_429 and c["n429"] / n >= F429: return "ratelimit"
    if c["n404"] >= MIN_404 and d["frac_404"] >= F404: return "recon"
    if c["ndeny"] >= MIN_DENY and c["ndeny"] / n >= FDENY and (
            c.get("deny_uri", MIN_DENY_URI) >= MIN_DENY_URI or c.get("n401", 0) * 2 >= c["ndeny"]
            or (c["ndeny"] >= MIN_DENY_SINGLE and c["ndeny"] / n >= FDENY_SINGLE)):
        return "denied"
    if c["npost"] >= MIN_POST and d["frac_post"] >= FPOST and d["uniq_uri"] <= 2: return "bruteforce"
    if n >= MIN_ENUM and d["uniq_q_ratio"] >= UQRATIO and d["uniq_uri"] <= 3: return "enum"
    return None

M = None
if os.path.exists(MODEL_PATH):
    M = joblib.load(MODEL_PATH)["behaviour"]
    L.info("tier3 behaviour model loaded, feats=%s tau=%.4f", M["feats"], M["tau_fp01"])
else:
    L.error("KHÔNG có model tier3 tại %s — chỉ dùng cổng định hình (độ nhạy khác với khi có model)", MODEL_PATH)

def is_internal(ip):
    try: a = ipaddress.ip_address(ip)
    except (ValueError, TypeError): return True
    return any(a in n for n in INTERNAL)

# ip -> trạng thái. ev: deque các (ts, uri, status, is_post, query, n_params, ua)
st = {}
def new_state(now): return {"ev": deque(maxlen=MAX_EV), "max_ts": 0.0, "wall": now, "last_eval": 0.0,
                            "since": 0, "streak": 0, "last_alert": 0.0, "last_doc": 0.0, "last_profile": 0.0}

def window(s, ref):
    lo = ref - WINDOW
    ev = s["ev"]
    while ev and ev[0][0] <= lo and ev[0][0] <= s["max_ts"] - WINDOW: ev.popleft()   # chỉ bỏ hẳn cái chắc chắn hết hạn
    return [e for e in ev if lo < e[0] <= ref]

def features(win):
    n = len(win)
    uri = {e[1] for e in win}; q = {e[4] for e in win}
    c = {"n404": sum(e[2] == 404 for e in win), "ndeny": sum(e[2] in (401, 403) for e in win),
         "n429": sum(e[2] == 429 for e in win),
         "npost": sum(e[3] for e in win), "n401": sum(e[2] == 401 for e in win),
         "deny_uri": len({e[1] for e in win if e[2] in (401, 403)})}
    d = {"n_req": n, "uniq_uri": len(uri), "uniq_ratio": len(uri) / n, "frac_404": c["n404"] / n,
         "frac_post": c["npost"] / n, "uniq_q_ratio": len(q) / n, "mean_params": sum(e[5] for e in win) / n}
    return d, c

def score(d):
    if M is None: return -1.0               # không có model: chỉ cổng định hình quyết định
    return float(M["iso"].decision_function(M["scaler"].transform([[float(d[k]) for k in M["feats"]]]))[0])

def evaluate(ip, s, ref, prod, es_buf):
    """Chấm cửa sổ (ref-WINDOW, ref] của một IP. ref là thời điểm sự kiện."""
    s["last_eval"], s["since"] = ref, 0
    win = window(s, ref)
    uas = Counter(e[6] for e in win)
    if len(uas) >= SHARED_MIN_UA and ref - s["last_profile"] >= SHARED_EVERY:
        s["last_profile"] = ref
        prod.produce("alerts", key=ip.encode(), value=json.dumps({
            "kind": "ip_profile", "ts": ref, "src_ip": ip, "uas": len(uas), "class": "ip_profile",
            "confidence": 0.0, "source": "behaviour"}).encode())
    if len(win) < MIN_REQ:
        s["streak"] = 0; return
    d, c = features(win)
    sc = score(d)
    shape = attack_shape(d, c)
    tau = M["tau_fp01"] if M is not None else 0.0
    flagged = sc < tau and shape is not None                  # IsoForest + cổng định hình
    s["streak"] = s["streak"] + 1 if flagged else 0
    alert = flagged and s["streak"] >= CONFIRM and ref - s["last_alert"] >= COOLDOWN
    if alert or ref - s["last_doc"] >= WINDOW:                # 1 bản ghi / cửa sổ, và mỗi lần báo
        s["last_doc"] = ref
        doc = {"@timestamp": iso(ref), "source": "behaviour", "src_ip": ip,
               "label": "behaviour" if flagged else "benign", "confidence": 0.9 if flagged else 0.0,
               "tier": 3, "anom_score": round(sc, 4), "b_shape": shape,
               **{f"b_{k}": v for k, v in d.items()}}
        es_buf.add(day_index("web-events", ref), doc)
        if flagged and os.getenv("ATTACK_ARCHIVE", "1") != "0":   # bản lưu dài 1 năm của sự kiện tấn công (xem classifier)
            es_buf.add(day_index("attack-events", ref), doc)
    if alert:
        s["last_alert"] = ref
        prod.produce("alerts", key=ip.encode(), value=json.dumps({
            "alert_id": str(uuid.uuid4()), "ts": ref, "src_ip": ip, "class": "behaviour",
            "confidence": 0.9, "tier": 3, "source": "behaviour", "immediate": True, "shape": shape,
            "ua": uas.most_common(1)[0][0] if uas else "",
            "detail": f"{shape}: n={d['n_req']} uri={d['uniq_uri']} 404={d['frac_404']:.2f} post={d['frac_post']:.2f}"}).encode())
        L.info("behaviour anomaly ip=%s shape=%s score=%.3f n=%d uri=%d 404=%.2f -> alert(immediate)",
               ip, shape, sc, d["n_req"], d["uniq_uri"], d["frac_404"])

def gate_event(ev):
    """Dòng gate1.json của nginx -> sự kiện cùng dạng web.logs, CHỈ cho request bị giới hạn tốc độ (429).
    403 của Cổng 1 là IP đã bị chặn (không cần chấm lại); 4xx khác là request dị dạng (nhánh khác lo)."""
    try:
        if int(ev.get("status") or 0) != 429: return None
    except (TypeError, ValueError): return None
    uri, _, q = str(ev.get("uri") or "").partition("?")
    try: ts_ms = float(ev.get("ts")) * 1000.0
    except (TypeError, ValueError): ts_ms = None
    return {"src_ip": ev.get("src_ip"), "ts_ms": ts_ms, "uri": uri, "query": q, "status": 429,
            "method": ev.get("method"), "ua": ev.get("ua")}

def campaign(prod, es_buf, force=False):
    """Chấm bộ đếm toàn hệ thống. Trả số địa chỉ vừa bị báo."""
    ref = camp["max_ts"]
    if not login_ev or (not force and camp["since"] < 10 and ref - camp["last_eval"] < HOP): return 0
    camp["since"], camp["last_eval"] = 0, ref
    while login_ev and login_ev[0][0] <= ref - WINDOW: login_ev.popleft()
    per, ua_of = Counter(), {}
    for ts, ip, ua in login_ev:
        per[ip] += 1; ua_of[ip] = ua
    cand = {ip: n for ip, n in per.items() if n >= STUFF_PER_IP}
    if len(cand) < STUFF_MIN_IPS or sum(cand.values()) < STUFF_MIN_TOTAL: return 0
    fired = 0
    for ip, n in cand.items():
        if ref - camp["last_alert"].get(ip, 0.0) < COOLDOWN: continue
        camp["last_alert"][ip] = ref; fired += 1
        doc = {"@timestamp": iso(ref), "source": "behaviour", "src_ip": ip, "label": "behaviour", "confidence": 0.9,
               "tier": 3, "b_shape": "stuffing", "b_n_req": n, "b_campaign_ips": len(cand),
               "b_campaign_attempts": sum(cand.values())}
        es_buf.add(day_index("web-events", ref), doc)
        if os.getenv("ATTACK_ARCHIVE", "1") != "0": es_buf.add(day_index("attack-events", ref), doc)
        prod.produce("alerts", key=ip.encode(), value=json.dumps({
            "alert_id": str(uuid.uuid4()), "ts": ref, "src_ip": ip, "class": "behaviour", "confidence": 0.9, "tier": 3,
            "source": "behaviour", "immediate": True, "shape": "stuffing", "ua": ua_of.get(ip, ""),
            "detail": f"stuffing: {n} lần thử đăng nhập; chiến dịch {len(cand)} IP, {sum(cand.values())} lần / {int(WINDOW)} s"}).encode())
    if fired:
        L.info("chiến dịch nhồi tài khoản: %d IP (mỗi IP >= %d lần), %d lần thử -> báo %d IP",
               len(cand), STUFF_PER_IP, sum(cand.values()), fired)
    for ip in [i for i, t in camp["last_alert"].items() if ref - t > COOLDOWN * 2]: del camp["last_alert"][ip]
    return fired

def add(ev, prod, es_buf):
    ip = ev.get("src_ip")
    if not ip or is_internal(ip): return
    now = time.time()
    ts = float(ev.get("ts_ms") or now * 1000) / 1000.0
    try: st_ = int(ev.get("status") or 0)
    except (TypeError, ValueError): st_ = 0
    if login_attempt(ev, st_):
        ua_ = ev.get("ua") or ""
        login_ev.append((ts, ip, "" if ua_ == "-" else ua_[:256]))
        camp["since"] += 1
        if ts > camp["max_ts"]: camp["max_ts"] = ts
        campaign(prod, es_buf)
    s = st.get(ip)
    if s is None: s = st[ip] = new_state(now)
    q = ev.get("query") or ""
    ua = ev.get("ua") or ""
    s["ev"].append((ts, ev.get("uri") or "", int(ev.get("status") or 0),
                    (ev.get("method") or "").upper() == "POST", q, (q.count("&") + 1) if q else 0,
                    "" if ua == "-" else ua[:256]))
    s["since"] += 1; s["wall"] = now
    if ts > s["max_ts"]: s["max_ts"] = ts
    if len(s["ev"]) >= MIN_REQ and (s["since"] >= EVAL_EVERY or s["max_ts"] - s["last_eval"] >= HOP
                                    or s["last_eval"] == 0.0):
        evaluate(ip, s, s["max_ts"], prod, es_buf)

def sweep(prod, es_buf):
    """Chấm nốt các IP còn request chưa chấm (đợt tấn công đã dừng) và dọn IP im lặng quá một cửa sổ."""
    now = time.time()
    for ip in list(st):
        s = st[ip]
        idle = now - s["wall"]
        if idle > WINDOW + HOP:
            del st[ip]; continue
        if s["since"] and idle >= 2.0:
            evaluate(ip, s, s["max_ts"], prod, es_buf)
    if camp["since"]: campaign(prod, es_buf, force=True)

def main():
    install_stop()
    es_buf = EsBuffer(es_client(required=False)); prod = producer()
    c = consumer("tier3", ["web.logs", "gate1.logs"])
    hb = Heartbeat("tier3", es_buf)
    L.info("tier3 started: cửa sổ trượt %ss, hop %ss, min_req=%d, cooldown=%ss", WINDOW, HOP, MIN_REQ, COOLDOWN)
    last = time.time()
    while running():
        msg = c.poll(0.5)
        if msg is not None and msg.error():
            L.warning("kafka: %s", msg.error())
        elif msg is not None:
            ev = parse_json_line(msg.value()); hb.inc()
            if isinstance(ev, dict) and msg.topic() == "gate1.logs":
                ev = gate_event(ev)
            if isinstance(ev, dict):
                try: add(ev, prod, es_buf)
                except Exception: L.exception("tier3 add failed")
        if time.time() - last >= 2:
            sweep(prod, es_buf); last = time.time()
            hb.tick(c, tracked_ips=len(st), model_loaded=M is not None)
        es_buf.maybe_flush(); prod.poll(0)
    es_buf.maybe_flush(force=True); prod.flush(5); c.close()

if __name__ == "__main__":
    main()

"""tools/sectest.py — kiểm tra ÂM TÍNH về xác thực và phân quyền (gọi qua tools/sectest.sh, không chạy tay).

Chạy trong một container ở mạng giám sát, đóng vai "kẻ đã vào được mạng nội bộ": thử đọc Elasticsearch và
ghi vào các topic Kafka nhạy cảm khi KHÔNG có mật khẩu, khi sai mật khẩu, và khi dùng tài khoản của một
thành phần khác vai trò. Mọi phép thử đều phải BỊ TỪ CHỐI. Không ghi dữ liệu rác vào hệ thống: các lệnh
ghi hoặc bị từ chối, hoặc (nếu hệ thống cấu hình sai và chấp nhận) chỉ là một danh sách chặn RỖNG / tài
liệu ở chỉ mục năm 2099.
"""
import base64, json, os, socket, sys, time, urllib.error, urllib.request
from confluent_kafka import Producer

E = os.environ
BOOT = E.get("KAFKA_BOOTSTRAP", "kafka:9092")
ES = E.get("ES_URL", "http://elasticsearch:9200").rstrip("/")
FAILS = []

def show(name, got, ok):
    print(("  ok   " if ok else "  FAIL ") + name + f"  -> {got}", flush=True)
    if not ok: FAILS.append(name)

def produce(topic, user=None, pw=None):
    """Trả None nếu broker NHẬN thông điệp, ngược lại trả mô tả lỗi."""
    conf = {"bootstrap.servers": BOOT, "message.timeout.ms": 8000, "socket.timeout.ms": 5000, "log_level": 0}
    if user:
        conf.update({"security.protocol": "SASL_PLAINTEXT", "sasl.mechanism": "PLAIN",
                     "sasl.username": user, "sasl.password": pw or ""})
    res = {}
    p = Producer(conf)
    p.produce(topic, key=b"sectest", value=json.dumps({"ips": [], "conf": "", "cmd": "noop", "ts": 1}).encode(),
              callback=lambda err, msg: res.update(err=str(err) if err else None))
    p.flush(12)
    return res.get("err", "không có phản hồi (hết thời gian)")

def es(path, user=None, pw=None, method="GET", body=None):
    rq = urllib.request.Request(ES + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                headers={"Content-Type": "application/json"})
    if user:
        rq.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode())
    try:
        with urllib.request.urlopen(rq, timeout=10) as r: return r.status
    except urllib.error.HTTPError as e: return e.code
    except Exception as e: return f"lỗi kết nối ({type(e).__name__})"

print("== Elasticsearch")
q = "/web-events-*/_search?ignore_unavailable=true&size=0"
r = es(q); show("đọc KHÔNG đăng nhập bị từ chối", r, r == 401)
r = es(q, "elastic", "sai-mat-khau"); show("sai mật khẩu bị từ chối", r, r == 401)
r = es(q, "elastic", E.get("ES_PASSWORD", "")); show("đúng mật khẩu thì đọc được (đối chứng)", r, r == 200)
r = es(q, "grafana_ro", E.get("GRAFANA_ES_PASSWORD", "")); show("tài khoản Grafana (grafana_ro) đọc được (đối chứng)", r, r == 200)
r = es("/audit-decisions-2099.01.01/_doc", "grafana_ro", E.get("GRAFANA_ES_PASSWORD", ""), "POST", {"decision": "sectest"})
show("grafana_ro KHÔNG ghi được nhật ký kiểm toán", r, r == 403)
r = es("/audit-decisions-*/_delete_by_query", "grafana_ro", E.get("GRAFANA_ES_PASSWORD", ""), "POST", {"query": {"match_none": {}}})
show("grafana_ro KHÔNG xoá được nhật ký kiểm toán", r, r == 403)

print("== Kafka")
def denied(name, topic, user=None, pw=None):
    r = produce(topic, user, pw); show(name, r, r is not None)
denied("ghi enforce.blocklist KHÔNG đăng nhập bị từ chối", "enforce.blocklist")
denied("ghi enforce.blocklist sai mật khẩu bị từ chối", "enforce.blocklist", "responder", "sai-mat-khau")
for user, var, topics in (("filebeat", "KAFKA_FILEBEAT_PASSWORD", ("enforce.blocklist", "enforce.rules", "nsm.control", "alerts")),
                          ("enforcer", "KAFKA_ENFORCER_PASSWORD", ("enforce.blocklist", "enforce.rules", "nsm.control")),
                          ("classifier", "KAFKA_CLASSIFIER_PASSWORD", ("enforce.blocklist", "enforce.rules")),
                          ("tier3", "KAFKA_TIER3_PASSWORD", ("enforce.blocklist",)),
                          ("logsink", "KAFKA_LOGSINK_PASSWORD", ("enforce.blocklist", "alerts")),
                          ("responder", "KAFKA_RESPONDER_PASSWORD", ("enforce.rules",)),
                          ("rulegen", "KAFKA_RULEGEN_PASSWORD", ("enforce.blocklist",)),
                          ("ctl", "KAFKA_CTL_PASSWORD", ("enforce.blocklist", "enforce.rules"))):
    for t in topics:
        denied(f"tài khoản {user} KHÔNG ghi được {t}", t, user, E.get(var, ""))
host = BOOT.split(":")[0]
s = socket.socket(); s.settimeout(3)
try: s.connect((host, 9093)); got = "MỞ"
except Exception as e: got = f"không nối được ({type(e).__name__})"
finally: s.close()
show("cổng CONTROLLER 9093 của Kafka không mở ra mạng", got, got != "MỞ")

print()
if FAILS:
    print(f"THẤT BẠI {len(FAILS)} mục — hệ thống đang chấp nhận truy cập lẽ ra phải bị từ chối:")
    for f in FAILS: print("  -", f)
    sys.exit(1)
print("TẤT CẢ ĐỀU ĐẠT — mọi truy cập trái phép đều bị từ chối.")

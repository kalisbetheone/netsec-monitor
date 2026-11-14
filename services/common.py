"""Tiện ích dùng chung cho cả enforcer (WEB) và classifier/tier3/responder/rulegen (SOC).

Chỉ confluent_kafka được import ở cấp module; elasticsearch được import trễ bên
trong es_client() để container enforcer (không cài elasticsearch) vẫn chạy được.
"""
import json, logging, os, re, signal, time
from datetime import datetime, timezone
from confluent_kafka import Consumer, Producer

BOOT = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
ES_URL = os.getenv("ES_URL", "http://elasticsearch:9200")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
logging.getLogger("confluent_kafka").setLevel(logging.WARNING)

def log(name): return logging.getLogger(name)

def iso(ts=None):
    ts = time.time() if ts is None else ts
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def day_index(prefix, ts=None):
    ts = time.time() if ts is None else ts
    return f"{prefix}-{datetime.fromtimestamp(ts, tz=timezone.utc):%Y.%m.%d}"

_TZ_NOCOLON = re.compile(r"([+-]\d{2})(\d{2})$")
def parse_ts(s, default=None):
    """Chuỗi thời gian ISO-8601 (vd Suricata '2026-11-09T09:00:00.123456+0000') -> epoch giây.
    Trả `default` nếu không đọc được. Dùng để cảnh báo mang THỜI ĐIỂM SỰ KIỆN, không phải lúc xử lý."""
    if isinstance(s, (int, float)): return float(s)
    if not isinstance(s, str) or not s: return default
    try:
        t = _TZ_NOCOLON.sub(r"\1:\2", s.strip().replace("Z", "+00:00"))
        d = datetime.fromisoformat(t)
        if d.tzinfo is None: d = d.replace(tzinfo=timezone.utc)
        return d.timestamp()
    except ValueError:
        return default

def kafka_auth():
    """Đăng nhập Kafka (SASL/PLAIN) khi có KAFKA_USER. Mỗi dịch vụ một tài khoản riêng, quyền do
    soc/kafka-init.sh cấp; thiếu biến thì nối không xác thực (chỉ dùng cho kiểm thử cục bộ)."""
    u = os.getenv("KAFKA_USER")
    if not u: return {}
    return {"security.protocol": "SASL_PLAINTEXT", "sasl.mechanism": "PLAIN",
            "sasl.username": u, "sasl.password": os.getenv("KAFKA_PASSWORD", "")}

# Kết nối lại nhanh sau khi Kafka trở lại (mặc định librdkafka giãn tới 10 giây giữa các lần thử)
_RECONNECT = {"reconnect.backoff.ms": 200, "reconnect.backoff.max.ms": int(os.getenv("KAFKA_RECONNECT_MAX_MS", "2000"))}

def consumer(group, topics):
    c = Consumer({**kafka_auth(), **_RECONNECT, "bootstrap.servers": BOOT, "group.id": group,
                  "auto.offset.reset": "earliest", "enable.auto.commit": True,
                  # Kafka khởi động lại thì nạp lại cả các thành viên CŨ của nhóm và chờ chúng hết phiên trước khi
                  # chia lại partition: với mặc định 45 giây, đo được chặn trễ ~45 giây sau khi Kafka trở lại (C3)
                  "session.timeout.ms": int(os.getenv("KAFKA_SESSION_TIMEOUT_MS", "10000")),
                  "heartbeat.interval.ms": 3000,
                  # topic được tạo SAU khi dịch vụ đã subscribe (khởi động chạy đua, hoặc Kafka ở máy
                  # khác) phải được nhận ra trong 30 giây, không phải 5 phút mặc định
                  "topic.metadata.refresh.interval.ms": 30000})
    c.subscribe(topics)
    return c

KAFKA_FAIL = {"n": 0}     # số thông điệp gửi Kafka thất bại (đưa vào nhịp tim)

def _delivery(err, msg):
    """Gọi trong poll()/flush(): trước đây lỗi gửi (hết thời gian chờ, mất quyền, thông điệp quá lớn)
    bị bỏ qua im lặng — cảnh báo hay lệnh chặn có thể mất mà không ai biết."""
    if err is not None:
        KAFKA_FAIL["n"] += 1
        if KAFKA_FAIL["n"] == 1 or KAFKA_FAIL["n"] % 100 == 0:
            log("kafka").error("gửi Kafka thất bại (tổng %d): topic=%s lỗi=%s", KAFKA_FAIL["n"],
                               msg.topic() if msg is not None else "?", err)

def producer():
    # acks=all: chỉ coi là đã gửi khi broker đã ghi; thử lại tới 2 phút (Kafka khởi động lại vẫn kịp)
    # nén lz4: snapshot danh sách chặn lớn vẫn dưới giới hạn kích thước thông điệp
    return Producer({**kafka_auth(), **_RECONNECT, "bootstrap.servers": BOOT, "linger.ms": 20, "acks": "all",
                     "enable.idempotence": True, "message.timeout.ms": 120000, "compression.type": "lz4",
                     "message.max.bytes": 8 * 1024 * 1024, "on_delivery": _delivery})

def es_client(required=True):
    """Tạo client Elasticsearch.

    required=True (rulegen, ctl — cần ES mới làm được việc): chờ ES tối đa ~3 phút rồi báo lỗi.
    required=False (classifier, tier3, responder, logsink — nằm trên đường phát hiện/cưỡng chế):
    chỉ thử ngắn rồi trả client dù ES chưa lên, để dịch vụ vẫn khởi động được khi ES đang hỏng
    (spec E3). Bản ghi chờ trong EsBuffer và được ghi khi ES trở lại. Sai mật khẩu vẫn dừng ngay."""
    from elasticsearch import Elasticsearch
    user, pw = os.getenv("ES_USER"), os.getenv("ES_PASSWORD")
    es = Elasticsearch(ES_URL, request_timeout=30, **({"basic_auth": (user, pw or "")} if user else {}))
    tries = 90 if required else int(os.getenv("ES_START_TRIES", "5"))
    for _ in range(tries):
        try:
            es.info(); return es          # info() phân biệt được 'chưa lên' với 'sai mật khẩu' (ping() nuốt cả hai)
        except Exception as e:
            if getattr(getattr(e, "meta", None), "status", None) in (401, 403):
                raise RuntimeError("Elasticsearch từ chối đăng nhập — kiểm tra ES_USER/ES_PASSWORD (.env)") from e
        time.sleep(2)
    if required:
        raise RuntimeError("Elasticsearch unreachable")
    log("es").warning("Elasticsearch chưa trả lời — vẫn khởi động, bản ghi sẽ chờ trong bộ đệm")
    return es

# ---- dừng êm: SIGTERM/SIGINT -> vòng lặp chính thoát, kịp flush bộ đệm ES/Kafka ----
RUN = {"on": True}
def install_stop():
    def _stop(*_): RUN["on"] = False
    for s in (signal.SIGTERM, signal.SIGINT):
        try: signal.signal(s, _stop)
        except (ValueError, OSError): pass
def running(): return RUN["on"]

# ---- đọc một dòng log JSON của Apache/Suricata/ModSec ----
# Apache (ap_escape_logitem) ghi ký tự đặc biệt thành \xhh và \v — cả hai KHÔNG hợp lệ
# trong JSON. Ta đi qua từng cặp "\<ký tự>" theo đúng thứ tự (nên "\\x41" = dấu \ + "x41"
# không bị sửa nhầm) và đổi các escape lạ về dạng \uXXXX.
_ESC = re.compile(r"\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)", re.S)
_JSON_ESC = set('"\\/bfnrt')
_C_ESC = {"v": 0x0b, "a": 0x07, "e": 0x1b, "0": 0x00}
def _fix_escape(m):
    g = m.group(1)
    if len(g) == 5 and g[0] == "u": return m.group(0)
    if len(g) == 3 and g[0] == "x": return "\\u00" + g[1:]
    if g in _JSON_ESC: return m.group(0)
    return "\\u%04x" % _C_ESC.get(g, ord(g))

def _fix_utf8(v):
    """Apache ghi từng byte UTF-8 thành \\xhh -> sau khi parse là ký tự U+0080..U+00FF. Ghép lại."""
    if isinstance(v, str) and any("\x80" <= ch <= "\xff" for ch in v):
        try: return v.encode("latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError): return v
    return v

BAD_LINES = {"n": 0}
def parse_json_line(raw):
    s = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
    try: return json.loads(s)
    except json.JSONDecodeError: pass
    try:
        ev = json.loads(_ESC.sub(_fix_escape, s))
        if isinstance(ev, dict):
            ev = {k: _fix_utf8(v) for k, v in ev.items()}
        return ev
    except json.JSONDecodeError:
        BAD_LINES["n"] += 1
        if BAD_LINES["n"] == 1 or BAD_LINES["n"] % 100 == 0:   # không im lặng: dòng hỏng = sự kiện bị mất
            log("parse").warning("không đọc được dòng log JSON (tổng %d): %.200r", BAD_LINES["n"], s)
        return None

def atomic_write(path, text):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)

def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f: return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default

class EsBuffer:
    """Bộ đệm ghi ES theo lô, ghi ở LUỒNG NỀN.

    add() chỉ đưa bản ghi vào hàng đợi rồi trả về ngay: vòng lặp phát hiện/cưỡng chế không bao giờ
    phải chờ Elasticsearch (trước đây helpers.bulk chạy đồng bộ trong vòng lặp chính, ES dừng là việc
    chặn dừng theo — trái spec E3). Khi ES lỗi: giữ lại để thử lại với thời gian chờ tăng dần
    (1 → 30 giây); quá max_buf bản ghi thì bỏ bản cũ nhất và đếm vào `dropped`."""
    def __init__(self, es, flush_n=500, flush_s=2.0, max_buf=None, timeout_s=None, start=True):
        import collections, threading
        self.es, self.flush_n, self.flush_s = es, flush_n, flush_s
        self.max_buf = int(os.getenv("ES_BUFFER_MAX", "200000")) if max_buf is None else max_buf
        self.timeout_s = float(os.getenv("ES_BULK_TIMEOUT_S", "10")) if timeout_s is None else timeout_s
        self.buf = collections.deque()
        self.failures = 0            # số lần ghi ES thất bại / bị từ chối (đưa vào nhịp tim)
        self.dropped = 0             # số bản ghi bị bỏ vì bộ đệm đầy
        self._lock = threading.Lock(); self._wake = threading.Event(); self._idle = threading.Event()
        self._idle.set(); self._backoff = 0.0
        if start:
            threading.Thread(target=self._run, name="es-writer", daemon=True).start()

    def add(self, index, doc, _id=None):
        # 'create' (chỉ thêm, không ghi đè): đủ với quyền create_doc của tài khoản nsm_writer
        a = {"_op_type": "create", "_index": index, "_source": doc}
        if _id: a["_id"] = _id
        with self._lock:
            self.buf.append(a); self._idle.clear()
            over = len(self.buf) - self.max_buf
            for _ in range(max(0, over)): self.buf.popleft()
            if over > 0:
                self.dropped += over
                if self.dropped == over or self.dropped % 1000 < over:
                    log("es").warning("bộ đệm ES đầy (%d) — đã bỏ tổng %d bản ghi cũ nhất", self.max_buf, self.dropped)
            n = len(self.buf)
        if n >= self.flush_n and not self._backoff: self._wake.set()   # đang chờ thử lại thì không đánh thức sớm

    def maybe_flush(self, force=False, wait_s=10.0):
        """Không chặn. force=True (lúc dừng dịch vụ): đánh thức luồng ghi và chờ tối đa wait_s giây."""
        if force:
            self._backoff = 0.0; self._wake.set(); self._idle.wait(wait_s)

    def _take(self):
        with self._lock:
            n = min(len(self.buf), max(self.flush_n, 1) * 4)
            return [self.buf.popleft() for _ in range(n)]

    def _put_back(self, batch):
        with self._lock:
            self.buf.extendleft(reversed(batch))
            over = len(self.buf) - self.max_buf
            for _ in range(max(0, over)): self.buf.popleft()   # vượt trần: bỏ bản cũ nhất
            if over > 0: self.dropped += over

    def write_once(self):
        """Ghi một lô (dùng trong luồng nền; kiểm thử gọi trực tiếp). Trả True nếu ghi được hoặc không có gì."""
        batch = self._take()
        if not batch:
            self._idle.set(); return True
        from elasticsearch import helpers
        try:
            client = self.es.options(request_timeout=self.timeout_s) if hasattr(self.es, "options") else self.es
            _, errors = helpers.bulk(client, batch, raise_on_error=False, raise_on_exception=True)
            if errors:   # ES nhận lô nhưng từ chối một số bản ghi (vd xung đột mapping)
                self.failures += len(errors)
                log("es").warning("ES từ chối %d/%d bản ghi; lỗi đầu: %.300s", len(errors), len(batch), errors[0])
            self._backoff = 0.0
            return True
        except Exception as e:
            self.failures += 1
            self._put_back(batch)
            self._backoff = min(30.0, max(1.0, self._backoff * 2))
            log("es").warning("ghi ES thất bại (%s) — giữ %d bản ghi, thử lại sau %.0f giây",
                              str(e)[:200], len(self.buf), self._backoff)
            return False

    def _run(self):
        while True:
            self._wake.wait(self._backoff or self.flush_s); self._wake.clear()
            while self.buf:
                if not self.write_once(): break
            with self._lock:
                if not self.buf: self._idle.set()

# ---- nhịp tim: mỗi dịch vụ tự báo "còn sống, đã xử lý bao nhiêu, có ứ đọng / lỗi không" ----
def consumer_lag(c):
    """Tổng số thông điệp Kafka chưa đọc của consumer `c` trên các partition được giao (None nếu không đo được)."""
    try:
        total = 0
        for tp in c.assignment():
            lo, hi = c.get_watermark_offsets(tp, timeout=2, cached=False)
            pos = c.position([tp])[0].offset
            if pos is None or pos < 0:
                pos = c.committed([tp], timeout=2)[0].offset
            if pos is None or pos < 0: pos = lo
            total += max(0, hi - pos)
        return total
    except Exception:
        return None

ALIVE_PATH = os.getenv("ALIVE_PATH", "/tmp/alive")

class Heartbeat:
    """Cứ `every` giây tạo một bản ghi sức khoẻ. Có `es_buf` thì ghi thẳng vào chỉ mục nsm-health-*;
    không có (enforcer trên máy WEB không nối ES) thì tick() trả bản ghi để nơi gọi gửi qua Kafka."""
    def __init__(self, service, es_buf=None, every=None):
        self.service, self.buf = service, es_buf
        self.every = float(os.getenv("HEARTBEAT_S", "30")) if every is None else every
        self.start = time.time(); self.last = self.start - self.every + 5     # nhịp đầu sau ~5 giây
        self.n = 0; self._n_last = 0; self._t_last = self.start; self._alive = 0.0
        self._prev = {}                       # giá trị đếm dồn ở nhịp trước -> số MỚI trong nhịp này
    def inc(self, k=1): self.n += k
    def tick(self, consumer=None, **extra):
        now = time.time()
        if now - self._alive >= 5:            # tệp sống cho healthcheck của Docker (vòng lặp chính còn quay)
            self._alive = now
            try:
                with open(ALIVE_PATH, "w") as f: f.write(str(int(now)))
            except OSError: pass
        if now - self.last < self.every: return None
        dt = max(now - self._t_last, 1e-6)
        doc = {"@timestamp": iso(now), "service": self.service, "uptime_s": int(now - self.start),
               "processed": self.n, "rate": round((self.n - self._n_last) / dt, 2), "bad_lines": BAD_LINES["n"],
               "kafka_send_failures": KAFKA_FAIL["n"]}
        if consumer is not None: doc["kafka_lag"] = consumer_lag(consumer)
        if self.buf is not None:
            doc["es_failures"] = getattr(self.buf, "failures", 0); doc["es_buffered"] = len(getattr(self.buf, "buf", []))
            doc["es_dropped"] = getattr(self.buf, "dropped", 0)
        for k in ("kafka_send_failures", "es_failures", "es_dropped"):    # cảnh báo dựa trên số mới, không phải số dồn
            if k in doc:
                doc[k + "_new"] = doc[k] - self._prev.get(k, 0); self._prev[k] = doc[k]
        doc.update(extra)
        self.last, self._n_last, self._t_last = now, self.n, now
        if self.buf is not None: self.buf.add(day_index("nsm-health", now), doc)
        return doc

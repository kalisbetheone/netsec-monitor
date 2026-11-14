"""logsink: gom các nguồn nhật ký PHỤ vào Elasticsearch, tách khỏi đường xử lý chính của classifier.

  gate1.logs     nginx (Cổng 1): request bị từ chối — 403 vì IP (hoặc IP + User-Agent) đang bị chặn, 429 vì vượt
                 giới hạn kết nối, 400/414/431/505... vì request dị dạng (nginx từ chối trước khi tới Apache).
                 -> chỉ mục gate-events-*: cho thấy IP bị chặn VẪN đang làm gì (trước đây không thấy được).
  web.errors     error.log của Apache (gồm thông báo ModSecurity, lỗi PHP, lỗi máy chủ).
                 -> chỉ mục apache-errors-*.
  enforce.status nhịp tim của enforcer (máy WEB không nối được Elasticsearch nên gửi qua Kafka).
                 -> chỉ mục nsm-health-*.

Cả hai nguồn nhật ký có thể rất dày khi bị tấn công (một IP bị chặn vẫn bắn hàng trăm request/giây; mỗi
request bị CRS chặn sinh vài dòng error.log), nên KHÔNG ghi từng dòng: gom theo khoá trong FLUSH_S giây
rồi ghi một bản ghi kèm số lần (`count`). Lưu lượng ghi vào Elasticsearch vì thế bị chặn trên.
"""
import json, os, re, time
from collections import Counter
from datetime import datetime, timezone
from common import (EsBuffer, Heartbeat, consumer, day_index, es_client, install_stop, iso, log,
                    parse_json_line, running)

L = log("logsink")
FLUSH_S = float(os.getenv("LOGSINK_FLUSH_S", "10"))
MAX_KEYS = int(os.getenv("LOGSINK_MAX_KEYS", "5000"))      # trần số khoá gom trong một cửa sổ (chống phình bộ nhớ)

gate = {}      # (ip, lý do, mã) -> {"n", "t0", "t1", "targets": Counter, "ua"}
errs = {}      # (module, mức, ip, mã luật, thông điệp rút gọn) -> {"n", "t1", "msg"}
dropped = {"gate": 0, "errs": 0}

# [Wed Nov 11 15:23:01.313763 2026] [security2:error] [pid 66:tid 66] [client 10.10.10.20:0] nội dung...
ERR_LINE = re.compile(r"^\[(?P<ts>[^\]]+)\] \[(?P<module>[^:\]]*):(?P<level>[^\]]+)\] \[pid [^\]]+\] "
                      r"(?:\[client (?P<client>[^\]]+)\] )?(?P<msg>.*)$", re.S)
MS_ID, MS_MSG = re.compile(r'\[id "(\d+)"\]'), re.compile(r'\[msg "([^"]*)"\]')
MS_CLIENT = re.compile(r"^\[client ([^\]]+)\] ")
VOLATILE = re.compile(r"\d+")              # số (pid, cổng, mã yêu cầu...) không tham gia khoá gom

def _ts(v, default):
    try: return float(v)
    except (TypeError, ValueError): return default

def add_gate(ev, now=None):
    now = time.time() if now is None else now
    ip = ev.get("src_ip")
    if not ip: return
    status = int(_ts(ev.get("status"), 0))
    blocked = str(ev.get("blocked", "1")) == "1"
    # 403 do chặn IP / dấu vân tay; 429 do vượt giới hạn kết nối; các mã 4xx/5xx khác do nginx từ chối
    # request dị dạng (dòng request quá dài, header hỏng, phiên bản HTTP lạ...) — C5
    if status == 403 and blocked:
        reason = "fingerprint" if str(ev.get("fp_blocked", "0")) == "1" else "blocklist"
    elif status == 429: reason = "limit"
    elif status in (400, 408, 413, 414, 431, 494, 501, 505): reason = "rejected"
    else: reason = "other"
    key = (ip, reason, status)
    a = gate.get(key)
    if a is None:
        if len(gate) >= MAX_KEYS: dropped["gate"] += 1; return
        a = gate[key] = {"n": 0, "t0": _ts(ev.get("ts"), now), "t1": 0.0, "targets": Counter(), "ua": ""}
    a["n"] += 1
    a["t1"] = max(a["t1"], _ts(ev.get("ts"), now))
    t = f'{ev.get("method") or "?"} {str(ev.get("uri") or "")[:200]}'
    if t in a["targets"] or len(a["targets"]) < 50: a["targets"][t] += 1
    a["ua"] = str(ev.get("ua") or "")[:200]
    if reason == "rejected" and ev.get("request"): a["request"] = str(ev.get("request"))[:300]

def parse_err_ts(s, default):
    try: return datetime.strptime(s, "%a %b %d %H:%M:%S.%f %Y").replace(tzinfo=timezone.utc).timestamp()
    except ValueError: return default

def add_err(line, now=None):
    now = time.time() if now is None else now
    line = line.rstrip("\r\n")
    if not line: return
    m = ERR_LINE.match(line)
    if not m:                                   # dòng nối tiếp / định dạng lạ: vẫn giữ, không bỏ im lặng
        module, level, client, msg, ts = "", "unknown", None, line, now
    else:
        module, level, msg = m.group("module"), m.group("level"), m.group("msg")
        client = (m.group("client") or "").rsplit(":", 1)[0] or None
        ts = parse_err_ts(m.group("ts"), now)
    rule_id = None
    if module == "security2":
        c2 = MS_CLIENT.match(msg)               # ModSecurity tự ghi thêm "[client <ip thật>]"
        if c2: client, msg = c2.group(1), msg[c2.end():]
        i, t = MS_ID.search(msg), MS_MSG.search(msg)
        rule_id = i.group(1) if i else None
        short = t.group(1) if t else msg[:160]
    else:
        short = msg[:300]
    key = (module, level, client, rule_id, VOLATILE.sub("#", short)[:200])
    a = errs.get(key)
    if a is None:
        if len(errs) >= MAX_KEYS: dropped["errs"] += 1; return
        a = errs[key] = {"n": 0, "t1": 0.0, "msg": short}
    a["n"] += 1; a["t1"] = max(a["t1"], ts)

def flush(buf, now=None):
    now = time.time() if now is None else now
    for (ip, reason, status), a in gate.items():
        ts = a["t1"] or now
        top = a["targets"].most_common(5)
        buf.add(day_index("gate-events", ts), {
            "@timestamp": iso(ts), "src_ip": ip, "reason": reason, "status": status, "count": a["n"],
            "window_s": round(max(0.0, a["t1"] - a["t0"]), 1), "top_target": top[0][0] if top else "",
            "targets": [f"{t} ×{n}" for t, n in top], "uniq_targets": len(a["targets"]), "ua": a["ua"],
            **({"request": a["request"]} if a.get("request") else {})})
    for (module, level, client, rule_id, _), a in errs.items():
        ts = a["t1"] or now
        buf.add(day_index("apache-errors", ts), {
            "@timestamp": iso(ts), "module": module, "level": level, "src_ip": client, "rule_id": rule_id,
            "message": a["msg"], "count": a["n"]})
    gate.clear(); errs.clear()

def main():
    install_stop()
    buf = EsBuffer(es_client(required=False))
    c = consumer("logsink", ["gate1.logs", "web.errors", "enforce.status"])
    hb = Heartbeat("logsink", buf)
    L.info("logsink started: gom mỗi %ss (gate1.logs, web.errors, nhịp tim enforcer)", FLUSH_S)
    last = time.time()
    while running():
        msg = c.poll(0.5)
        if msg is not None and msg.error():
            L.warning("kafka: %s", msg.error())
        elif msg is not None:
            hb.inc()
            try:
                t = msg.topic()
                if t == "gate1.logs":
                    ev = parse_json_line(msg.value())
                    if isinstance(ev, dict): add_gate(ev)
                elif t == "web.errors":
                    add_err(msg.value().decode("utf-8", "replace"))
                else:
                    st = json.loads(msg.value())
                    if isinstance(st, dict) and st.get("kind") == "heartbeat" and isinstance(st.get("doc"), dict):
                        buf.add(day_index("nsm-health"), st["doc"])
            except Exception:
                L.exception("lỗi xử lý dòng nhật ký")
        now = time.time()
        if now - last >= FLUSH_S:
            flush(buf, now); last = now
            hb.tick(c, dropped_gate=dropped["gate"], dropped_errors=dropped["errs"])
        buf.maybe_flush()
    flush(buf); buf.maybe_flush(force=True); c.close()

if __name__ == "__main__":
    main()

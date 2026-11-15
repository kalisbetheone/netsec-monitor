#!/usr/bin/env python3
"""tools/d1grace_inject.py — hai lệnh nhỏ cho tools/d1grace.sh (kiểm nhánh hạ cấp D1 của responder trên hệ thống thật).

  inject <ip>          gửi vào topic 'alerts' MỘT thông điệp ip_profile giống hệt thông điệp tier3 phát khi thấy một IP có
                       nhiều User-Agent (services/tier3.py, hàm evaluate). Chạy trong container của dịch vụ tier3 để dùng đúng
                       tài khoản Kafka của tier3 (quyền ghi 'alerts').
  audit <ip> <epoch>   in các quyết định của responder cho <ip> từ <epoch> (chỉ mục audit-decisions-*), dạng JSON mỗi dòng.
                       Chạy trong container của nsmctl (tài khoản ES nsm_ctl, chỉ đọc kiểm toán).

Lý do phải tiêm tay: sau khi một IP bị chặn cả ở Cổng 1, request của IP đó không còn tới Apache nên tier3 (đọc web.logs, và
gate1.logs chỉ cho mã 429) không chấm lại IP đó nữa — không dựng được thứ tự "chặn trước, báo dùng chung sau" bằng lưu lượng
thường. Phép kiểm này kiểm phần còn lại của chuỗi: responder hạ lệnh chặn -> enforcer -> nginx.
"""
import base64, json, os, sys, time, urllib.request


def inject(ip):
    sys.path.insert(0, "/app")
    from common import producer                     # tài khoản Kafka lấy từ KAFKA_USER / KAFKA_PASSWORD của dịch vụ tier3
    p = producer()
    msg = {"kind": "ip_profile", "ts": time.time(), "src_ip": ip, "uas": 4, "class": "ip_profile",
           "confidence": 0.0, "source": "behaviour"}
    p.produce("alerts", key=ip.encode(), value=json.dumps(msg).encode())
    left = p.flush(15)
    print(json.dumps({"injected": msg, "unsent": left}))
    return 0 if left == 0 else 1


def audit(ip, since):
    body = {"size": 200, "sort": [{"@timestamp": "asc"}], "query": {"bool": {"filter": [
        {"term": {"src_ip.keyword": ip}},
        {"range": {"@timestamp": {"gte": int(float(since) * 1000), "format": "epoch_millis"}}}]}}}
    url = os.getenv("ES_URL", "http://elasticsearch:9200").rstrip("/") + "/audit-decisions-*/_search"
    rq = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                headers={"Content-Type": "application/json"})
    cred = f"{os.getenv('ES_USER', 'elastic')}:{os.getenv('ES_PASSWORD', '')}".encode()
    rq.add_header("Authorization", "Basic " + base64.b64encode(cred).decode())
    hits = json.loads(urllib.request.urlopen(rq, timeout=30).read())["hits"]["hits"]
    for h in hits:
        s = h["_source"]
        print(json.dumps({k: s.get(k) for k in ("@timestamp", "decision", "reason", "scope", "fp_ua", "ttl_s", "offenses")},
                         ensure_ascii=False))
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "inject":
        sys.exit(inject(sys.argv[2]))
    if len(sys.argv) >= 4 and sys.argv[1] == "audit":
        sys.exit(audit(sys.argv[2], sys.argv[3]))
    print(__doc__); sys.exit(2)

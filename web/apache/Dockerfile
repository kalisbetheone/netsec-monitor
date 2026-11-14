FROM php:8.3-apache-bookworm

# ModSecurity 2.9.7 (Debian) + tiện ích + ext PHP cho DVWA. CRS cài riêng bên dưới (bản 4.25.0, không dùng gói 3.3.4)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libapache2-mod-security2 inotify-tools git \
      libpng-dev default-mysql-client \
 && docker-php-ext-install mysqli pdo pdo_mysql gd \
 && rm -rf /var/lib/apt/lists/* \
 && a2enmod security2 remoteip unique_id headers rewrite \
 && cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf \
 && sed -i 's/^SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf \
 && sed -i 's#^SecResponseBodyAccess On#SecResponseBodyAccess Off#' /etc/modsecurity/modsecurity.conf \
 && mkdir -p /etc/modsecurity/autogen /var/log/apache-json /rules/published \
 && touch /etc/modsecurity/autogen/active.conf

# DVWA — giữ nguyên config.inc.php gốc. Bản DVWA hiện tại tự đọc cấu hình CSDL
# từ biến môi trường (DB_SERVER, DB_PASSWORD...), các biến này được đặt trong docker-compose.yml.
# DVWA_REF: MÃ COMMIT của DVWA (cố định 15/11/2026 — trước đây lấy nhánh master nên mỗi lần dựng lại có thể ra một
# ứng dụng khác với bản đã đo). Đổi bản: --build-arg DVWA_REF=<mã commit / tag / nhánh>.
ARG DVWA_REF=a1978a2fed195acd093010af6395f86a281537ca
RUN git config --global --add safe.directory /var/www/html && git init -q /var/www/html && cd /var/www/html  && git remote add origin https://github.com/digininja/DVWA.git  && git fetch -q --depth 1 origin "${DVWA_REF}" && git checkout -q FETCH_HEAD  && cp /var/www/html/config/config.inc.php.dist /var/www/html/config/config.inc.php \
 && chown -R www-data:www-data /var/www/html \
 && chmod -R 777 /var/www/html/hackable/uploads /var/www/html/config

# OWASP CRS 4.25.0 (LTS) từ tệp phát hành lưu sẵn trong web/apache/crs/ (build không cần mạng, phiên bản cố định).
# Nạp qua /usr/share/modsecurity-crs/*.load như gói Debian cũ, nên thứ tự giữ nguyên: modsecurity.conf -> CRS ->
# conf-enabled/zz-autogen.conf (luật tự sinh của rulegen, /etc/modsecurity/autogen/active.conf).
COPY crs/coreruleset-4.25.0-minimal.tar.gz /tmp/crs.tar.gz
COPY crs/owasp-crs4.load /usr/share/modsecurity-crs/owasp-crs4.load
RUN echo "409a0da1f4daed0719150fcee5173c351e08ffa33b5b2f8936f30968b3ad4ff0  /tmp/crs.tar.gz" | sha256sum -c - \
 && mkdir -p /etc/modsecurity/crs4 \
 && tar -xzf /tmp/crs.tar.gz -C /etc/modsecurity/crs4 --strip-components=1 \
 && rm -f /tmp/crs.tar.gz \
 && cp /etc/modsecurity/crs4/crs-setup.conf.example /etc/modsecurity/crs4/crs-setup.conf \
 && tr -d "\r" < /usr/share/modsecurity-crs/owasp-crs4.load > /tmp/x && cat /tmp/x > /usr/share/modsecurity-crs/owasp-crs4.load
# Tinh chỉnh CRS của NSM (14/11/2026): text/plain được phép, ngoại lệ hẹp cho GraphQL — lý do và số đo trong từng tệp
COPY crs/nsm-tuning-config.conf crs/nsm-tuning-before.conf /etc/modsecurity/crs4/plugins/
RUN sed -i 's/\r$//' /etc/modsecurity/crs4/plugins/nsm-tuning-config.conf /etc/modsecurity/crs4/plugins/nsm-tuning-before.conf
# Tầng 1 của classifier chạy ĐỒNG BỘ ở Cổng 2 (14/11/2026): request tấn công đầu tiên mà CRS bỏ lọt bị 403 ngay, không
# chờ đường ống phát hiện. Sinh từ services/classifier.py bằng tools/gen_tier1_modsec.py; nạp trong zz-autogen.conf, SAU
# luật tự sinh. KHÔNG đặt trong /etc/modsecurity/*.conf (thư mục đó nạp TRƯỚC CRS).
COPY nsm-tier1.conf /etc/modsecurity/nsm-sync/tier1.conf
RUN sed -i 's/\r$//' /etc/modsecurity/nsm-sync/tier1.conf

COPY logjson.conf zz-autogen.conf /etc/apache2/conf-available/
COPY 000-default.conf /etc/apache2/sites-available/000-default.conf
RUN a2enconf logjson zz-autogen

# ModSec audit log sang JSON (có request body) + ghi vào volume để filebeat đọc
RUN sed -i 's#^SecAuditLog .*#SecAuditLog /var/log/apache-json/modsec_audit.json#' /etc/modsecurity/modsecurity.conf \
 && sed -i 's/^SecAuditLogType .*/SecAuditLogType Serial/' /etc/modsecurity/modsecurity.conf \
 && sed -i 's/^SecAuditLogParts .*/SecAuditLogParts ABCEFHJKZ/' /etc/modsecurity/modsecurity.conf \
 && ( grep -q '^SecAuditLogFormat' /etc/modsecurity/modsecurity.conf \
      && sed -i 's/^SecAuditLogFormat .*/SecAuditLogFormat JSON/' /etc/modsecurity/modsecurity.conf \
      || printf '\nSecAuditLogFormat JSON\n' >> /etc/modsecurity/modsecurity.conf )

# Cổng đặt chỗ giả lập (booking.local) — ứng dụng được bảo vệ trong bài toán "bảo vệ máy chủ dịch vụ trực tuyến và dữ
# liệu khách hàng" (15/11/2026). PHP + SQLite, dữ liệu tổng hợp sinh lúc build; DVWA vẫn là vhost mặc định (dvwa.local).
# Chi tiết: web/apache/booking/README.md.
COPY booking/ /var/www/booking/
RUN find /var/www/booking -type f \( -name '*.php' -o -name '*.conf' -o -name '*.txt' -o -name '*.css' \) -exec sed -i 's/\r$//' {} + \
 && mkdir -p /var/lib/booking \
 && BOOKING_DB=/var/lib/booking/booking.db php /var/www/booking/seed.php \
 && chown -R root:root /var/www/booking && chmod -R a+rX,go-w /var/www/booking \
 && chown -R www-data:www-data /var/lib/booking && chmod 750 /var/lib/booking && chmod 640 /var/lib/booking/booking.db \
 && cp /var/www/booking/booking-vhost.conf /etc/apache2/sites-available/010-booking.conf && a2ensite 010-booking

COPY watch-rules.sh entrypoint.sh /usr/local/bin/
RUN for f in /usr/local/bin/watch-rules.sh /usr/local/bin/entrypoint.sh \
             /etc/apache2/conf-available/logjson.conf /etc/apache2/conf-available/zz-autogen.conf \
             /etc/apache2/sites-available/000-default.conf; do \
      tr -d "\r" < "$f" > /tmp/x && cat /tmp/x > "$f"; done \
 && chmod +x /usr/local/bin/watch-rules.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

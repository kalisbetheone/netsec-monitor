FROM nginx:1.27-alpine
RUN apk add --no-cache inotify-tools openssl
COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh /entrypoint.sh
RUN for f in /entrypoint.sh /etc/nginx/nginx.conf; do tr -d "\r" < $f > /tmp/x && cat /tmp/x > $f; done && chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

FROM alpine:3.24

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    HOME=/tmp \
    TMPDIR=/tmp \
    XDG_CACHE_HOME=/tmp \
    XDG_RUNTIME_DIR=/run

RUN apk add --no-cache \
        python3 \
        py3-flask \
        py3-gunicorn \
        py3-dnspython \
        py3-cryptography \
        py3-yaml \
        nginx \
        nsd \
        openssl \
    && rm -f /etc/nginx/http.d/default.conf /etc/nginx/conf.d/default.conf \
    && mkdir -p /opt/data/log /opt/data/zones /opt/data/etc /opt/data/nsd/zones /opt/data/nsd/xfr /opt/data/secrets \
    && rm -rf /run /tmp /var/log/nginx \
    && ln -s /dev/shm /run \
    && ln -s /dev/shm /tmp \
    && ln -s /tmp/nginx-log /var/log/nginx

WORKDIR /app
COPY gunicorn.conf.py ./
COPY src ./src
RUN python3 -m compileall -q /app/src /app/gunicorn.conf.py
COPY deploy/root-anchors.ds ./deploy/root-anchors.ds
COPY deploy/config.example.yaml /usr/local/share/dns-host/config.example.yaml
COPY deploy/inittab /etc/inittab
COPY deploy/crontabs/root /etc/crontabs/root
COPY bin/ /usr/local/bin/
RUN chmod 755 /usr/local/bin/start_up /usr/local/bin/start_syslog \
        /usr/local/bin/start_api /usr/local/bin/start_controller \
        /usr/local/bin/start_dns_udp /usr/local/bin/start_dns_axfr \
        /usr/local/bin/start_nsd /usr/local/bin/start_nginx \
        /usr/local/bin/start_cron /usr/local/bin/start_shutdown

VOLUME ["/opt/data"]
EXPOSE 80 53/tcp 53/udp 9100

HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1/health', timeout=2).read()"

COPY build.txt /usr/local/etc/build.txt
CMD ["/usr/local/bin/start_up"]

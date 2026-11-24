from pathlib import Path

from dns_host.render_nginx import render

_ROOT = Path(__file__).resolve().parents[1]


def test_nginx_is_plain_http_and_trusts_only_configured_proxies():
    text = render(80,
                  1048576, ["172.28.9.0/24", "10.1.2.3/32"],
                  internal_port=8081)
    assert "listen 80;" in text
    assert "listen 127.0.0.1:8081;" in text
    assert "user nginx;" in text
    assert "listen 443" not in text
    assert "ssl_certificate" not in text
    assert "set_real_ip_from 172.28.9.0/24;" in text
    assert "set_real_ip_from 10.1.2.3/32;" in text
    assert "real_ip_header X-Forwarded-For;" in text
    assert "X-Forwarded-Proto $forwarded_proto;" in text
    assert "location = /config {" in text
    assert "proxy_pass http://127.0.0.1:8000/ext/config;" in text
    assert "proxy_pass http://127.0.0.1:8000/ext/;" in text
    assert "proxy_pass http://127.0.0.1:8000/int/;" in text
    assert "pid /run/nginx.pid;" in text
    assert "/tmp/nginx-body" in text
    assert "/opt/data" not in text


def test_read_only_root_uses_dev_shm_and_an_explicit_gunicorn_socket():
    dockerfile = (_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "rm -rf /run /tmp" in dockerfile
    assert "ln -s /dev/shm /run" in dockerfile
    assert "ln -s /dev/shm /tmp" in dockerfile
    gunicorn_conf = (_ROOT / "gunicorn.conf.py").read_text(encoding="utf-8")
    assert 'control_socket = "/run/gunicorn.ctl"' in gunicorn_conf
    launch = (_ROOT / "src/dns_host/serve_api.py").read_text(encoding="utf-8")
    assert '"--control-socket"' in launch
    assert '"/run/gunicorn.ctl"' in launch
    compose = (_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "read_only: true" in compose
    assert "shm_size:" in compose
    assert "tmpfs:" not in compose


def test_nginx_without_trusted_proxies_does_not_rewrite_addresses():
    text = render(80, 100, [])
    assert "\n        set_real_ip_from " not in text
    assert "listen 80;" in text

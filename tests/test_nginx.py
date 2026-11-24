from pathlib import Path

from dns_host.render_nginx import render

_ROOT = Path(__file__).resolve().parents[1]


def test_nginx_is_plain_http_and_trusts_only_configured_proxies():
    text = render(1048576, ["172.28.9.0/24", "10.1.2.3/32"])
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


def test_port_80_does_not_route_metrics():
    text = render(1048576, [])
    blocks = text.split("\n    server {")[1:]
    public = next(block for block in blocks if "listen 80;" in block)
    metrics = next(block for block in blocks if "listen 9100;" in block)
    assert "/metrics" not in public
    assert "location = /metrics {" in metrics
    assert "proxy_pass http://127.0.0.1:8000/int/metrics;" in metrics
    assert "listen 127.0.0.1:9100;" not in text


def test_nginx_without_trusted_proxies_does_not_rewrite_addresses():
    text = render(100, [])
    assert "\n        set_real_ip_from " not in text
    assert "listen 80;" in text


def test_generated_nginx_conf_is_written_on_tmpfs(monkeypatch):
    from dns_host.config import Settings
    from dns_host.serve_nginx import NGINX_CONF, main

    captured = {}
    settings = Settings(
        service_ns=["ns1.example.net."],
        trusted_proxies=["172.28.9.0/24"],
        max_body_bytes=100,
    )

    def capture_write(path, text):
        captured["path"] = path
        captured["text"] = text

    def capture_exec(program, argv):
        captured["program"] = program
        captured["argv"] = argv

    monkeypatch.setattr("dns_host.serve_nginx.atomic_write", capture_write)
    monkeypatch.setattr("dns_host.serve_nginx.os.execvp", capture_exec)
    monkeypatch.setattr("dns_host.serve_nginx.log_effective",
                        lambda _settings: None)
    monkeypatch.setattr("dns_host.serve_nginx.Settings.load", lambda: settings)
    main()
    assert captured["path"] == Path("/run/nginx/nginx.conf")
    assert captured["path"] == NGINX_CONF
    assert "listen 80;" in captured["text"]
    assert "set_real_ip_from 172.28.9.0/24;" in captured["text"]
    assert "/opt/data" not in captured["text"]
    assert captured["program"] == "nginx"
    assert captured["argv"][captured["argv"].index("-c") +
                            1] == str(NGINX_CONF)
    start_nginx = (_ROOT / "bin/start_nginx").read_text(encoding="utf-8")
    start_up = (_ROOT / "bin/start_up").read_text(encoding="utf-8")
    assert "/run/nginx" in start_nginx
    assert "/run/nginx" in start_up
    assert 'data_dir() / "etc" / "nginx.conf"' not in (
        _ROOT / "src/dns_host/serve_nginx.py").read_text(encoding="utf-8")

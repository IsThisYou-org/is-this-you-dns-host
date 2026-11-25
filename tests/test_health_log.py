"""Health checks stay available and stay out of the success logs."""

import json
import logging
from pathlib import Path

from dns_host.healthlog import SkipSuccessfulHealth
from dns_host.logutil import log
from dns_host.render_nginx import render

_ROOT = Path(__file__).resolve().parents[1]


def _record(name: str, msg: str, args=None, level=logging.INFO):
    return logging.LogRecord(name, level, __file__, 0, msg,
                             args if args is not None else (), None)


def test_health_location_does_not_write_an_access_log():
    text = render(100, [])
    assert "access_log syslog:server=unix:/dev/log combined;" in text
    health = text.split("location = /health {", 1)[1].split("\n        }",
                                                            1)[0]
    assert "access_log off;" in health
    assert "error_log off" not in health
    config = text.split("location = /config {", 1)[1].split("\n        }",
                                                            1)[0]
    assert "access_log off;" not in config
    assert text.count("location = /health {") == text.count("access_log off;")


def test_health_endpoints_and_dockerfile_check_stay():
    dockerfile = (_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "HEALTHCHECK" in dockerfile
    assert "--interval=30s" in dockerfile
    assert "--timeout=3s" in dockerfile
    assert 'CMD ["/usr/local/bin/healthcheck"]' in dockerfile
    script = (_ROOT / "bin" / "healthcheck").read_text(encoding="utf-8")
    assert "http://127.0.0.1/health" in script
    assert "dig -N -s 127.0.0.1:53 -t SOA" in script
    assert "ln -s /tmp/nginx-log /var/log/nginx" in dockerfile


def test_successful_health_access_is_filtered_and_a_failure_is_kept():
    checker = SkipSuccessfulHealth()
    quiet = _record(
        "gunicorn.access",
        "%(U)s %(s)s",
        {
            "U": "/ext/health",
            "s": "200",
            "r": "GET /ext/health HTTP/1.1"
        },
    )
    failed = _record(
        "gunicorn.access",
        "%(U)s %(s)s",
        {
            "U": "/health",
            "s": "503",
            "r": "GET /health HTTP/1.1"
        },
    )
    other = _record(
        "gunicorn.access",
        "%(U)s %(s)s",
        {
            "U": "/ext/v1/zones/user.example.",
            "s": "200"
        },
    )
    werkzeug = _record(
        "werkzeug",
        '127.0.0.1 - - [time] "GET /int/health HTTP/1.1" 200 -',
    )
    werkzeug_error = _record(
        "werkzeug",
        '127.0.0.1 - - [time] "GET /int/health HTTP/1.1" 503 -',
        level=logging.ERROR,
    )
    assert checker.filter(quiet) is False
    assert checker.filter(failed) is True
    assert checker.filter(other) is True
    assert checker.filter(werkzeug) is False
    assert checker.filter(werkzeug_error) is True


def test_gunicorn_access_logger_uses_the_health_filter():
    text = (_ROOT / "gunicorn.conf.py").read_text(encoding="utf-8")
    assert "dns_host.healthlog.SkipSuccessfulHealth" in text
    assert '"filters": ["skip_successful_health"]' in text


def test_app_log_skips_successful_health_and_keeps_failures(
        env, monkeypatch, capsys):
    for path in ("/health", "/ext/health", "/int/health"):
        assert env.client.get(path).status_code == 200
    assert capsys.readouterr().out == ""

    with env.client.application.test_request_context("/ext/health"):
        log("info", "routine health")
        log("error", "health broke", error="dns down")
    with env.client.application.test_request_context("/config"):
        log("info", "config hit")
    messages = [
        json.loads(line)["msg"]
        for line in capsys.readouterr().out.splitlines()
    ]
    assert messages == ["health broke", "config hit"]

    env.settings.health_check_dns = True
    monkeypatch.setattr("dns_host.app._dns_soa_ok", lambda settings: False)
    failed = env.client.get("/health")
    assert failed.status_code == 503
    assert failed.get_json()["dns"] == "down"
    body = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert body[-1]["msg"] == "health check failed"
    assert body[-1]["level"] == "error"
    assert body[-1]["path"] == "/health"

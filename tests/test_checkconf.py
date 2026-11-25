"""Generated nginx and NSD configs are checked before the daemon starts."""

import subprocess
from pathlib import Path

import pytest

from dns_host import checkconf
from dns_host.config import Settings
from dns_host.nsdconf import render_nsd, write_nsd_config
from dns_host.serve_nginx import NGINX_CONF, write_nginx_config


@pytest.fixture(autouse=True)
def _stamp_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(checkconf, "STAMP_DIR", tmp_path / "stamps")


def _failed(argv, stderr: str):
    return subprocess.CompletedProcess(argv, 1, "", stderr)


def _ok(argv):
    return subprocess.CompletedProcess(argv, 0, "", "")


def test_bad_tsig_algorithm_reaches_nsd_conf_and_stops(tmp_path, monkeypatch,
                                                       capsys):
    monkeypatch.setattr("dns_host.config.DATA_DIR", tmp_path)
    settings = Settings.from_mapping({
        "service_ns": ["ns1.example.net."],
        "secondaries": [{
            "ip": "192.0.2.10",
            "tsig_key_name": "transfer.example.",
            "tsig_secret": "c2VjcmV0MQ==",
            "tsig_algo": "not-a-real-algorithm",
        }],
    })
    assert "algorithm: not-a-real-algorithm" in render_nsd(settings)
    monkeypatch.setattr(
        checkconf.subprocess,
        "run",
        lambda argv, **kwargs: _failed(
            argv, "unknown algorithm not-a-real-algorithm"),
    )

    with pytest.raises(SystemExit) as raised:
        write_nsd_config(settings)
    assert raised.value.code == 1
    written = tmp_path / "nsd" / "nsd.conf"
    assert "algorithm: not-a-real-algorithm" in written.read_text(
        encoding="utf-8")
    logged = capsys.readouterr().out
    assert str(written) in logged
    assert "unknown algorithm not-a-real-algorithm" in logged
    assert "config.yaml is the likely cause" in logged
    assert '"level":"error"' in logged

    with pytest.raises(SystemExit):
        write_nsd_config(settings)
    assert capsys.readouterr().out == ""


def test_a_new_checker_error_is_logged_again(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("dns_host.config.DATA_DIR", tmp_path)
    settings = Settings.from_mapping({"service_ns": ["ns1.example.net."]})
    messages = iter(("first problem", "second problem"))
    monkeypatch.setattr(
        checkconf.subprocess,
        "run",
        lambda argv, **kwargs: _failed(argv, next(messages)),
    )
    with pytest.raises(SystemExit):
        write_nsd_config(settings)
    assert "first problem" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        write_nsd_config(settings)
    assert "second problem" in capsys.readouterr().out


def test_a_valid_nsd_config_is_checked_and_kept(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("dns_host.config.DATA_DIR", tmp_path)
    settings = Settings.from_mapping({"service_ns": ["ns1.example.net."]})
    seen = []

    def run(argv, **kwargs):
        seen.append(argv)
        return _ok(argv)

    monkeypatch.setattr(checkconf.subprocess, "run", run)
    path = write_nsd_config(settings)
    assert path.is_file()
    assert seen == [["nsd-checkconf", str(path)]]
    assert "server:" in path.read_text(encoding="utf-8")
    assert capsys.readouterr().out == ""


def test_nginx_checker_failure_stops_before_exec(tmp_path, monkeypatch,
                                                 capsys):
    conf = tmp_path / "nginx.conf"
    monkeypatch.setattr("dns_host.serve_nginx.NGINX_CONF", conf)
    monkeypatch.setattr("dns_host.serve_nginx.NGINX_TEMP_DIRS",
                        (tmp_path / "body", tmp_path / "log"))
    monkeypatch.setattr(
        checkconf.subprocess,
        "run",
        lambda argv, **kwargs: _failed(
            argv, "nginx: [emerg] unexpected end of file"),
    )
    executed = []
    monkeypatch.setattr("dns_host.serve_nginx.os.execvp",
                        lambda *args: executed.append(args))
    settings = Settings.from_mapping({
        "service_ns": ["ns1.example.net."],
        "max_body_bytes": 100,
    })
    with pytest.raises(SystemExit) as raised:
        write_nginx_config(settings)
    assert raised.value.code == 1
    assert executed == []
    assert (tmp_path / "body").is_dir()
    assert (tmp_path / "log").is_dir()
    logged = capsys.readouterr().out
    assert str(conf) in logged
    assert "unexpected end of file" in logged
    assert "config.yaml is the likely cause" in logged


def test_nginx_good_path_checks_then_execs(tmp_path, monkeypatch):
    from dns_host.serve_nginx import main

    conf = tmp_path / "nginx" / "nginx.conf"
    monkeypatch.setattr("dns_host.serve_nginx.NGINX_CONF", conf)
    monkeypatch.setattr("dns_host.serve_nginx.NGINX_TEMP_DIRS",
                        (tmp_path / "body", ))
    seen = []
    monkeypatch.setattr(
        checkconf.subprocess,
        "run",
        lambda argv, **kwargs: seen.append(argv) or _ok(argv),
    )
    executed = []
    monkeypatch.setattr("dns_host.serve_nginx.os.execvp",
                        lambda *args: executed.append(args))
    monkeypatch.setattr(
        "dns_host.serve_nginx.Settings.load",
        lambda: Settings.from_mapping({"service_ns": ["ns1.example.net."]}),
    )
    main()
    assert seen == [["nginx", "-t", "-c", str(conf)]]
    assert conf.is_file()
    assert "listen 80;" in conf.read_text(encoding="utf-8")
    assert executed == [(
        "nginx",
        [
            "nginx", "-e", "/tmp/nginx-startup.log", "-c",
            str(conf), "-g", "daemon off;"
        ],
    )]
    assert NGINX_CONF == Path("/run/nginx/nginx.conf")

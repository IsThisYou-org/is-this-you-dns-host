"""Strict checks for /opt/data/etc/config.yaml."""

import json
from pathlib import Path

import pytest

from dns_host.config import CONFIG_PATH, Settings, _INT_FIELDS
from dns_host.logutil import set_log_level

_ROOT = Path(__file__).resolve().parents[1]


def test_unknown_key_suggests_a_close_match():
    with pytest.raises(SystemExit) as raised:
        Settings.from_mapping({"gunicorn_worker": 2})
    message = str(raised.value)
    assert "unknown key 'gunicorn_worker'" in message
    assert "did you mean 'gunicorn_workers'" in message
    assert raised.value.__cause__ is None


def test_out_of_range_int_names_the_key():
    with pytest.raises(SystemExit) as raised:
        Settings.from_mapping({"gunicorn_workers": 0})
    message = str(raised.value)
    assert "gunicorn_workers" in message
    assert "0" in message
    assert "1" in message


def test_non_int_is_rejected():
    with pytest.raises(SystemExit) as raised:
        Settings.from_mapping({"axfr_children": "five"})
    assert "axfr_children" in str(raised.value)
    assert "five" in str(raised.value)

    with pytest.raises(SystemExit) as raised:
        Settings.from_mapping({"axfr_children": 1.5})
    assert "axfr_children" in str(raised.value)

    with pytest.raises(SystemExit) as raised:
        Settings.from_mapping({"axfr_children": True})
    message = str(raised.value)
    assert "axfr_children" in message
    assert "boolean" in message


def test_bool_must_already_be_a_boolean(tmp_path):
    assert Settings.from_mapping({}).health_check_dns is True
    assert Settings.from_mapping({
        "health_check_dns": None
    }).health_check_dns is True
    assert Settings.from_mapping({
        "health_check_dns": False
    }).health_check_dns is False

    for bad in ("true", "yes", "on", "false", 1, 0, ""):
        with pytest.raises(SystemExit, match="health_check_dns") as raised:
            Settings.from_mapping({"health_check_dns": bad})
        message = str(raised.value)
        assert "boolean" in message
        assert repr(bad) in message

    path = tmp_path / "config.yaml"
    path.write_text("health_check_dns: true\n", encoding="utf-8")
    assert Settings.load(path).health_check_dns is True
    path.write_text("health_check_dns: false\n", encoding="utf-8")
    assert Settings.load(path).health_check_dns is False
    # PyYAML turns an unquoted yes into a bool before the check runs.
    path.write_text("health_check_dns: yes\n", encoding="utf-8")
    assert Settings.load(path).health_check_dns is True
    path.write_text('health_check_dns: "yes"\n', encoding="utf-8")
    with pytest.raises(SystemExit, match="health_check_dns"):
        Settings.load(path)
    path.write_text("health_check_dns: 1\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="health_check_dns"):
        Settings.load(path)
    path.write_text("health_check_dns:\n", encoding="utf-8")
    assert Settings.load(path).health_check_dns is True


def test_bad_rr_type_is_rejected():
    with pytest.raises(SystemExit) as raised:
        Settings.from_mapping({"type_allowlist": ["A", "NOT_A_TYPE"]})
    message = str(raised.value)
    assert "type_allowlist" in message
    assert "NOT_A_TYPE" in message

    settings = Settings.from_mapping(
        {"type_allowlist": ["A", "aaaa", "NXNAME", "WALLET"]})
    assert settings.type_allowlist == frozenset(
        {"A", "AAAA", "NXNAME", "WALLET"})


def test_min_ttl_cannot_exceed_max_ttl():
    with pytest.raises(SystemExit) as raised:
        Settings.from_mapping({"min_ttl": 500, "max_ttl": 100})
    message = str(raised.value)
    assert "min_ttl" in message
    assert "max_ttl" in message
    assert "500" in message
    assert "100" in message
    assert Settings.from_mapping({"min_ttl": 30, "max_ttl": 30}).min_ttl == 30


def test_other_timer_cross_checks():
    with pytest.raises(SystemExit, match="soa_retry") as raised:
        Settings.from_mapping({"soa_retry": 4000, "soa_refresh": 3000})
    assert "soa_refresh" in str(raised.value)

    with pytest.raises(SystemExit, match="soa_expire") as raised:
        Settings.from_mapping({"soa_expire": 1000, "soa_refresh": 3000})
    assert "soa_refresh" in str(raised.value)

    with pytest.raises(SystemExit,
                       match="rrsig_min_remaining_seconds") as raised:
        Settings.from_mapping({
            "rrsig_min_remaining_seconds": 100,
            "rrsig_max_lifetime_seconds": 100,
        })
    assert "rrsig_max_lifetime_seconds" in str(raised.value)


def test_multiple_errors_are_reported_together(monkeypatch):
    logged = []

    def capture(level, msg, **fields):
        logged.append((level, msg, fields))

    monkeypatch.setattr("dns_host.logutil.log", capture)
    with pytest.raises(SystemExit) as raised:
        Settings.from_mapping({
            "gunicorn_worker": 4,
            "min_ttl": 5000,
            "max_ttl": 10,
            "health_check_dns": "yes",
            "axfr_children": "many",
            "service_ns": ["*.example."],
        })
    text = str(raised.value)
    assert raised.value.__cause__ is None
    header = f"{CONFIG_PATH} is invalid:"
    assert text.startswith(header + "\n")
    lines = [line for line in text.splitlines() if line.strip()]
    assert lines[0] == header
    assert len(lines) >= 6
    assert any("gunicorn_worker" in line and "gunicorn_workers" in line
               for line in lines)
    assert any("min_ttl" in line and "max_ttl" in line for line in lines)
    assert any("health_check_dns" in line for line in lines)
    assert any("axfr_children" in line for line in lines)
    assert any("service_ns" in line for line in lines)
    assert len(logged) == 1
    level, msg, fields = logged[0]
    assert level == "error"
    assert msg == "invalid configuration"
    assert fields["error"] == text


def test_doh_timeout_must_be_a_positive_number():
    with pytest.raises(SystemExit, match="doh_timeout_seconds"):
        Settings.from_mapping({"doh_timeout_seconds": 0})
    with pytest.raises(SystemExit, match="doh_timeout_seconds"):
        Settings.from_mapping({"doh_timeout_seconds": -1})
    with pytest.raises(SystemExit, match="doh_timeout_seconds"):
        Settings.from_mapping({"doh_timeout_seconds": True})
    with pytest.raises(SystemExit, match="doh_timeout_seconds"):
        Settings.from_mapping({"doh_timeout_seconds": "5"})
    assert Settings.from_mapping({
        "doh_timeout_seconds": 2
    }).doh_timeout_seconds == 2.0
    assert Settings.from_mapping({
        "doh_timeout_seconds": 1.5
    }).doh_timeout_seconds == 1.5


def test_removed_handshake_settings_are_unknown_keys():
    with pytest.raises(SystemExit,
                       match="unknown key 'handshake_root_servers'"):
        Settings.from_mapping({"handshake_root_servers": ["hs.example."]})
    with pytest.raises(SystemExit,
                       match="unknown key 'handshake_trust_anchor_file'"):
        Settings.from_mapping({"handshake_trust_anchor_file": "/no/such"})


def test_ds_digest_types_is_rejected_as_an_unknown_key():
    with pytest.raises(SystemExit,
                       match="unknown key 'ds_digest_types'") as raised:
        Settings.from_mapping({"ds_digest_types": [2, 4]})
    assert raised.value.__cause__ is None


def test_duplicate_top_level_key_warns_with_both_line_numbers(
        tmp_path, syslog_lines):
    set_log_level("info")
    path = tmp_path / "config.yaml"
    path.write_text(
        "secondaries:\n  - ip: 192.0.2.10\nsecondaries: []\n",
        encoding="utf-8",
    )
    settings = Settings.load(path)
    assert settings.secondaries == []
    assert len(syslog_lines) == 1
    record = json.loads(syslog_lines[0])
    assert record["level"] == "warning"
    assert record["msg"] == (
        "duplicate key 'secondaries' at lines 1 and 3; the later one wins")
    assert record["key"] == "secondaries"
    assert record["first_line"] == 1
    assert record["later_line"] == 3


def test_duplicate_nested_key_warns_and_keeps_the_later_value(
        tmp_path, syslog_lines):
    set_log_level("info")
    path = tmp_path / "config.yaml"
    path.write_text(
        "secondaries:\n  - ip: 192.0.2.10\n    ip: 192.0.2.11\n",
        encoding="utf-8",
    )
    settings = Settings.load(path)
    assert [item.host for item in settings.secondaries] == ["192.0.2.11"]
    record = json.loads(syslog_lines[0])
    assert record["level"] == "warning"
    assert record["msg"] == (
        "duplicate key 'ip' at lines 2 and 3; the later one wins")


def test_normal_config_does_not_warn_about_duplicate_keys(syslog_lines):
    set_log_level("info")
    Settings.load(_ROOT / "deploy/config.example.yaml")
    Settings.load(_ROOT / "deploy/config.tls.yaml")
    assert syslog_lines == []


def test_example_config_loads(monkeypatch):
    logged = []
    monkeypatch.setattr(
        "dns_host.logutil.log",
        lambda *args, **kwargs: logged.append((args, kwargs)),
    )
    settings = Settings.load(_ROOT / "deploy/config.example.yaml")
    assert logged == []
    assert settings.health_check_dns is True
    assert settings.gunicorn_workers == 3
    assert settings.min_ttl <= settings.max_ttl
    assert settings.soa_retry <= settings.soa_refresh < settings.soa_expire
    assert [name.to_text() for name in settings.service_ns] == [
        "ns1.example.net.",
        "ns2.example.net.",
    ]
    tls = Settings.load(_ROOT / "deploy/config.tls.yaml")
    assert tls.trusted_proxies == ["172.28.9.0/24"]
    text = (_ROOT / "deploy/config.example.yaml").read_text(encoding="utf-8")
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    assert "Unknown keys are rejected" in text
    assert "Unknown keys are rejected" in readme


def test_validation_error_names_the_loaded_file(tmp_path, monkeypatch):
    logged = []

    def capture(level, msg, **fields):
        logged.append((level, msg, fields))

    monkeypatch.setattr("dns_host.logutil.log", capture)
    path = tmp_path / "operator.yaml"
    path.write_text("gunicorn_workers: 0\n", encoding="utf-8")
    with pytest.raises(SystemExit) as raised:
        Settings.load(path)
    text = str(raised.value)
    header = f"{path} is invalid:"
    assert text.startswith(header + "\n")
    assert "gunicorn_workers" in text.splitlines()[1]
    assert len(logged) == 1
    level, msg, fields = logged[0]
    assert level == "error"
    assert msg == "invalid configuration"
    assert fields["error"] == text


def test_broken_yaml_is_a_config_error_without_a_traceback(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("service_ns: [\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="YAML") as raised:
        Settings.load(path)
    assert raised.value.__cause__ is None
    assert str(raised.value).startswith(f"{path} is invalid:\n")
    path.write_text("- just-a-list\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="mapping") as raised:
        Settings.load(path)
    assert str(raised.value).startswith(f"{path} is invalid:\n")


def test_mapping_defaults_match_direct_construction():
    loaded = Settings.from_mapping({})
    bare = Settings()
    for name, (default, _low, _high) in _INT_FIELDS.items():
        assert getattr(loaded, name) == default
        assert getattr(bare, name) == default
    assert loaded.doh_timeout_seconds == bare.doh_timeout_seconds == 5.0
    assert loaded.health_check_dns is True
    assert loaded.log_level == "info"


def test_start_scripts_sleep_after_a_startup_error():
    # nginx (1001) and NSD (1002) already sleep when their own check fails.
    # The app and AXFR scripts sleep when config.yaml is rejected.
    expected = {
        "bin/start_api": "1003",
        "bin/start_controller": "1004",
        "bin/start_dns_udp": "1005",
        "bin/start_dns_axfr": "1006",
    }
    for name, seconds in expected.items():
        text = (_ROOT / name).read_text(encoding="utf-8")
        assert "Settings.load()" in text
        assert f"exec sleep {seconds}\n" in text
        assert text.index("Settings.load()") < text.index(
            f"exec sleep {seconds}")
        assert text.index(f"exec sleep {seconds}") < text.index(
            "exec python3 -m")
    nginx = (_ROOT / "bin/start_nginx").read_text(encoding="utf-8")
    nsd = (_ROOT / "bin/start_nsd").read_text(encoding="utf-8")
    assert "exec sleep 1001" in nginx
    assert "exec sleep 1002" in nsd
    assert "exec sleep 1003" not in nginx
    assert "exec sleep 1003" not in nsd


def test_soa_retry_may_equal_soa_refresh():
    settings = Settings.from_mapping({"soa_retry": 60, "soa_refresh": 60})
    assert settings.soa_retry == settings.soa_refresh == 60

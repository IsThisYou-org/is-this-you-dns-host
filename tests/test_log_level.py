"""Configurable syslog log_level for application logs and gunicorn."""

import ast
import json
import syslog
from pathlib import Path

import pytest

from dns_host import logutil
from dns_host.config import Settings
from dns_host.logutil import log, parse_log_level, python_level_name, set_log_level

_ROOT = Path(__file__).resolve().parents[1]
_GUNICORN = _ROOT / "gunicorn.conf.py"
_ORDER = ("debug", "info", "notice", "warning", "err", "crit", "alert",
          "emerg")
_ROUTINE = {
    "zone accepted",
    "zone rejected",
    "rate limited",
    "NOTIFY sent",
    "retrying parent walk from handshake root",
    "zone installed from spool",
}


@pytest.fixture(autouse=True)
def _restore_log_level():
    set_log_level("info")
    yield
    set_log_level("info")


def test_default_log_level_is_info(tmp_path):
    assert Settings().log_level == "info"
    assert Settings.from_mapping({}).log_level == "info"
    assert Settings.load(tmp_path / "absent.yaml").log_level == "info"
    blank = tmp_path / "blank.yaml"
    blank.write_text("log_level:\n", encoding="utf-8")
    assert Settings.load(blank).log_level == "info"
    empty = tmp_path / "empty.yaml"
    empty.write_text('log_level: ""\n', encoding="utf-8")
    assert Settings.load(empty).log_level == "info"


@pytest.mark.parametrize("raw", list(_ORDER))
def test_syslog_names_are_case_insensitive(raw):
    assert parse_log_level(raw.upper()) == raw
    assert parse_log_level(f"  {raw.title()}  ") == raw
    assert Settings.from_mapping({"log_level": raw.upper()}).log_level == raw


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [("warn", "warning"), ("WARN", "warning"), ("error", "err"),
     ("Error", "err")],
)
def test_warn_and_error_aliases(raw, canonical):
    assert parse_log_level(raw) == canonical
    assert Settings.from_mapping({"log_level": raw}).log_level == canonical


@pytest.mark.parametrize("raw",
                         ["verbose", "fatal", "trace", 1, True, ["info"]])
def test_invalid_log_level_is_a_config_error(raw, tmp_path):
    with pytest.raises(SystemExit, match="invalid log_level") as raised:
        Settings.from_mapping({"log_level": raw})
    message = str(raised.value)
    assert repr(raw) in message
    for name in _ORDER:
        assert name in message
    assert "warn" in message and "error" in message

    path = tmp_path / "config.yaml"
    path.write_text("log_level: verbose\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="invalid log_level 'verbose'"):
        Settings.load(path)
    with pytest.raises(SystemExit, match="invalid log_level"):
        Settings(log_level="nope")


@pytest.mark.parametrize(
    ("level", "python_name"),
    [
        ("debug", "DEBUG"),
        ("info", "INFO"),
        ("notice", "INFO"),
        ("warning", "WARNING"),
        ("warn", "WARNING"),
        ("err", "ERROR"),
        ("error", "ERROR"),
        ("crit", "CRITICAL"),
        ("alert", "CRITICAL"),
        ("emerg", "CRITICAL"),
    ],
)
def test_python_level_names(level, python_name):
    assert python_level_name(level) == python_name


def test_example_config_leaves_log_level_commented():
    text = (_ROOT / "deploy" /
            "config.example.yaml").read_text(encoding="utf-8")
    lines = text.splitlines()
    mentioned = [
        index for index, line in enumerate(lines) if "log_level" in line
    ]
    assert mentioned
    assert all(lines[index].lstrip().startswith("#") for index in mentioned)
    note = []
    for index in mentioned:
        note.extend(lines[max(0, index - 4):index + 1])
    assert any("warning" in line.lower() for line in note)
    assert Settings.load(_ROOT / "deploy" /
                         "config.example.yaml").log_level == "info"
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    assert "`log_level`" in readme
    for name in _ORDER:
        assert f"`{name}`" in readme


def test_log_drops_messages_below_the_configured_level_on_stdout_and_syslog(
        capsys, monkeypatch):
    recorded = []
    monkeypatch.setattr(logutil, "_opened", False)
    monkeypatch.setattr(syslog, "openlog", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        syslog, "syslog", lambda priority, line: recorded.append(
            (priority, line)))

    set_log_level("warning")
    log("debug", "hidden-debug")
    log("info", "hidden-info", client_ip="203.0.113.10")
    log("notice", "hidden-notice")
    log("INFO", "hidden-info-case")
    log("warning", "kept-warning")
    log("warn", "kept-warn")
    log("error", "kept-error")
    log("err", "kept-err")
    log("crit", "kept-crit")
    log("alert", "kept-alert")
    log("emerg", "kept-emerg")

    stdout = capsys.readouterr().out.splitlines()
    assert [json.loads(line)["msg"] for line in stdout] == [
        "kept-warning",
        "kept-warn",
        "kept-error",
        "kept-err",
        "kept-crit",
        "kept-alert",
        "kept-emerg",
    ]
    assert [line for _priority, line in recorded] == stdout
    assert [priority for priority, _line in recorded] == [
        syslog.LOG_WARNING,
        syslog.LOG_WARNING,
        syslog.LOG_ERR,
        syslog.LOG_ERR,
        syslog.LOG_CRIT,
        syslog.LOG_ALERT,
        syslog.LOG_EMERG,
    ]
    assert json.loads(stdout[2])["level"] == "error"
    assert "client_ip" not in json.loads(stdout[0])


def test_debug_threshold_emits_every_level_with_its_syslog_priority(
        capsys, monkeypatch):
    recorded = []
    monkeypatch.setattr(logutil, "_opened", False)
    monkeypatch.setattr(syslog, "openlog", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        syslog, "syslog", lambda priority, line: recorded.append(
            (priority, line)))
    set_log_level("DeBuG")
    for name in _ORDER:
        log(name, name)
    captured = capsys.readouterr().out
    assert [json.loads(line)["msg"]
            for line in captured.splitlines()] == list(_ORDER)
    assert [priority for priority, _line in recorded] == [
        syslog.LOG_DEBUG,
        syslog.LOG_INFO,
        syslog.LOG_NOTICE,
        syslog.LOG_WARNING,
        syslog.LOG_ERR,
        syslog.LOG_CRIT,
        syslog.LOG_ALERT,
        syslog.LOG_EMERG,
    ]


def test_notice_keeps_notice_and_drops_info(capsys, monkeypatch):
    recorded = []
    monkeypatch.setattr(logutil, "_opened", False)
    monkeypatch.setattr(syslog, "openlog", lambda *args, **kwargs: None)
    monkeypatch.setattr(syslog, "syslog",
                        lambda priority, line: recorded.append(priority))
    Settings(log_level="notice")
    log("info", "hidden")
    log("notice", "kept")
    log("warning", "also")
    assert [
        json.loads(line)["msg"]
        for line in capsys.readouterr().out.splitlines()
    ] == ["kept", "also"]
    assert recorded == [syslog.LOG_NOTICE, syslog.LOG_WARNING]


def test_invalid_level_does_not_change_the_active_threshold(
        capsys, monkeypatch):
    monkeypatch.setattr(logutil, "_opened", False)
    monkeypatch.setattr(syslog, "openlog", lambda *args, **kwargs: None)
    monkeypatch.setattr(syslog, "syslog", lambda priority, line: None)
    set_log_level("warning")
    with pytest.raises(SystemExit):
        Settings.from_mapping({"log_level": "verbose"})
    log("info", "still-hidden")
    log("warning", "still-kept")
    assert [
        json.loads(line)["msg"]
        for line in capsys.readouterr().out.splitlines()
    ] == ["still-kept"]


def test_gunicorn_loggers_follow_log_level(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text("log_level: alert\n", encoding="utf-8")
    monkeypatch.setattr("dns_host.config.CONFIG_PATH", path)
    namespace = {"__file__": str(_GUNICORN)}
    exec(
        compile(_GUNICORN.read_text(encoding="utf-8"), str(_GUNICORN), "exec"),
        namespace)
    config = namespace["logconfig_dict"]
    assert namespace["control_socket"] == "/run/gunicorn.ctl"
    for logger in ("gunicorn.error", "gunicorn.access"):
        assert config["loggers"][logger]["level"] == "CRITICAL"
        assert config["loggers"][logger]["handlers"] == ["syslog"]
        assert config["loggers"][logger]["propagate"] is False
    assert config["root"]["level"] == "CRITICAL"
    assert config["root"]["handlers"] == ["syslog"]


@pytest.mark.parametrize(
    ("raw", "python_name"),
    [
        ("debug", "DEBUG"),
        ("info", "INFO"),
        ("notice", "INFO"),
        ("warning", "WARNING"),
        ("warn", "WARNING"),
        ("err", "ERROR"),
        ("error", "ERROR"),
        ("crit", "CRITICAL"),
        ("emerg", "CRITICAL"),
    ],
)
def test_gunicorn_conf_maps_each_name(tmp_path, monkeypatch, raw, python_name):
    path = tmp_path / "config.yaml"
    path.write_text(f"log_level: {raw}\n", encoding="utf-8")
    monkeypatch.setattr("dns_host.config.CONFIG_PATH", path)
    namespace = {}
    exec(
        compile(_GUNICORN.read_text(encoding="utf-8"), str(_GUNICORN), "exec"),
        namespace)
    assert namespace["logconfig_dict"]["loggers"]["gunicorn.error"][
        "level"] == python_name
    assert namespace["logconfig_dict"]["loggers"]["gunicorn.access"][
        "level"] == python_name
    assert namespace["logconfig_dict"]["root"]["level"] == python_name


def test_gunicorn_conf_rejects_an_invalid_log_level(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text("log_level: loud\n", encoding="utf-8")
    monkeypatch.setattr("dns_host.config.CONFIG_PATH", path)
    with pytest.raises(SystemExit, match="invalid log_level 'loud'"):
        exec(
            compile(_GUNICORN.read_text(encoding="utf-8"), str(_GUNICORN),
                    "exec"), {})


def test_missing_config_leaves_gunicorn_at_info(tmp_path, monkeypatch):
    monkeypatch.setattr("dns_host.config.CONFIG_PATH",
                        tmp_path / "absent.yaml")
    namespace = {}
    exec(
        compile(_GUNICORN.read_text(encoding="utf-8"), str(_GUNICORN), "exec"),
        namespace)
    assert namespace["logconfig_dict"]["root"]["level"] == "INFO"


def test_per_request_logs_are_info_or_debug():
    found = {}
    for path in (_ROOT / "src").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Name) or func.id != "log":
                continue
            if len(node.args) < 2:
                continue
            level, msg = node.args[0], node.args[1]
            if not isinstance(msg, ast.Constant) or msg.value not in _ROUTINE:
                continue
            assert isinstance(level, ast.Constant)
            found[msg.value] = level.value
    assert set(found) == _ROUTINE
    assert set(found.values()) <= {"info", "debug"}

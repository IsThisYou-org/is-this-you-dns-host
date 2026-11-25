"""Container health check: nginx /health and an NSD catalog SOA."""

import os
import stat
import subprocess
from pathlib import Path

import dns.name

from dns_host.config import Settings
from dns_host.nsdconf import render_nsd

_SCRIPT = Path(__file__).resolve().parents[1] / "bin" / "healthcheck"


def _write_exec(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _run(tmp_path, conf: Path, python_rc: int, dig_rc: int, dig_stdout: str):
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True)
    _write_exec(
        bindir / "python3",
        "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$PYTHON_LOG\"\n"
        "exit \"$PYTHON_RC\"\n",
    )
    _write_exec(
        bindir / "dig",
        "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$DIG_LOG\"\n"
        "printf '%s\\n' \"$DIG_STDOUT\"\nexit \"$DIG_RC\"\n",
    )
    env = os.environ.copy()
    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
    env["HEALTHCHECK_NSD_CONF"] = str(conf)
    env["PYTHON_LOG"] = str(tmp_path / "python.log")
    env["PYTHON_RC"] = str(python_rc)
    env["DIG_LOG"] = str(tmp_path / "dig.log")
    env["DIG_RC"] = str(dig_rc)
    env["DIG_STDOUT"] = dig_stdout
    return subprocess.run(
        ["sh", str(_SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_both_checks_pass_quietly_using_the_generated_catalog_zone(tmp_path):
    settings = Settings(catalog_zone=dns.name.from_text("catalog.other.test."))
    conf = tmp_path / "nsd.conf"
    conf.write_text(render_nsd(settings), encoding="utf-8")
    result = _run(tmp_path, conf, 0, 0, "DNS OK: 0.001 seconds")
    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""
    python_log = (tmp_path / "python.log").read_text(encoding="utf-8")
    assert "http://127.0.0.1/health" in python_log
    assert "timeout=2" in python_log
    dig_log = (tmp_path / "dig.log").read_text(encoding="utf-8").strip()
    assert dig_log == "-N -s 127.0.0.1:53 -t SOA catalog.other.test."
    assert "catalog-member" not in dig_log


def test_each_failed_part_is_named(tmp_path):
    conf = tmp_path / "nsd.conf"
    conf.write_text(
        "\n".join([
            "pattern:",
            '    name: "catalog-member"',
            "zone:",
            '    name: "decoy.example"',
            "zone:",
            '    name: "zones.catalog.test"',
            "    catalog: consumer",
            "",
        ]),
        encoding="utf-8",
    )
    rest = _run(tmp_path / "rest", conf, 1, 0, "DNS OK: fine")
    assert rest.returncode == 1
    assert rest.stdout.splitlines() == ["REST health check failed"]
    assert (tmp_path / "rest" / "dig.log").read_text(
        encoding="utf-8").strip().endswith("zones.catalog.test.")

    dns = _run(tmp_path / "dns", conf, 0, 2,
               "DNS FAILED: 5.005 seconds - TIME-OUT")
    assert dns.returncode == 1
    assert dns.stdout.splitlines() == [
        "DNS health check failed",
        "DNS FAILED: 5.005 seconds - TIME-OUT",
    ]

    both = _run(tmp_path / "both", conf, 1, 1, "DNS FAILED: down")
    assert both.returncode == 1
    assert both.stdout.splitlines() == [
        "REST health check failed",
        "DNS health check failed",
        "DNS FAILED: down",
    ]


def test_missing_catalog_zone_fails_the_dns_check(tmp_path):
    conf = tmp_path / "nsd.conf"
    conf.write_text("server:\n    port: 53\n", encoding="utf-8")
    result = _run(tmp_path, conf, 0, 0, "DNS OK: should not run")
    assert result.returncode == 1
    assert result.stdout == (
        "DNS health check failed: catalog zone not found in "
        f"{conf}\n")
    assert not (tmp_path / "dig.log").exists()

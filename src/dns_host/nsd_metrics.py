"""Prometheus text for NSD, from ``nsd-control stats_noreset``.

No client library. The exposition is written directly. ``nsd-control`` reads
the generated ``nsd.conf``, which points remote-control at 127.0.0.1 and at
the certificates under the data directory.
"""

from __future__ import annotations

import re
import subprocess

from dns_host.config import data_dir
from dns_host.logutil import log

PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
NSD_STATS_TIMEOUT = 2

_SERVER_PREFIX = re.compile(r"^server\d+\.(.+)$")
_NUMBER = re.compile(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$")

_PROTOCOLS = ("udp", "udp6", "tcp", "tcp6", "tls", "tls6")

_GAUGES = {
    "num.zones": "nsd_zones",
    "num.zone.master": "nsd_zones_master",
    "num.zone.slave": "nsd_zones_slave",
}

_LABELLED = (
    ("num.type.", "nsd_queries_by_type_total", "type",
     "Queries received, by RR type."),
    ("num.rcode.", "nsd_queries_by_rcode_total", "rcode",
     "Queries received, by response code."),
    ("num.opcode.", "nsd_queries_by_opcode_total", "opcode",
     "Queries received, by opcode."),
    ("num.class.", "nsd_queries_by_class_total", "class",
     "Queries received, by class."),
)

_COUNTER_HELP = {
    "num.queries": "Queries received.",
    "num.edns": "Queries with EDNS.",
    "num.ednserr": "EDNS failures.",
    "num.answer_wo_aa": "Answers sent without AA.",
    "num.rxerr": "Receive errors.",
    "num.txerr": "Transmit errors.",
    "num.raxfr": "AXFR requests received.",
    "num.truncated": "Truncated answers.",
    "num.dropped": "Dropped queries.",
}


def collect_nsd_stats() -> tuple[bool, str]:
    """Run ``nsd-control stats_noreset``. False means the scrape failed."""

    conf = data_dir() / "nsd" / "nsd.conf"
    try:
        completed = subprocess.run(
            ["nsd-control", "-c",
             str(conf), "stats_noreset"],
            check=False,
            capture_output=True,
            text=True,
            timeout=NSD_STATS_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        log("warning", "nsd-control timed out")
        return False, ""
    except OSError as exc:
        log("warning", "nsd-control failed", error=str(exc))
        return False, ""
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        log("warning", "nsd-control failed", error=detail)
        return False, ""
    return True, completed.stdout


def parse_stats(text: str) -> dict[str, str]:
    """Parse ``key=value`` lines.

    Per-server keys (``server0.num.queries``) are ignored when NSD also
    printed the aggregate. If only per-server keys are present, they are
    summed.
    """

    aggregate: dict[str, str] = {}
    per_server: dict[str, list[str]] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, raw_value = stripped.split("=", 1)
        key = key.strip()
        value = _number(raw_value.strip())
        if not key or value is None:
            continue
        match = _SERVER_PREFIX.match(key)
        if match:
            per_server.setdefault(match.group(1), []).append(value)
        else:
            aggregate[key] = value
    if aggregate:
        return aggregate
    summed: dict[str, str] = {}
    for key, values in per_server.items():
        if all(_is_int(item) for item in values):
            summed[key] = str(sum(int(item) for item in values))
        else:
            total = sum(float(item) for item in values)
            summed[key] = _format_float(total)
    return summed


def format_exposition(stats: dict[str, str], *, up: bool) -> str:
    """Prometheus text. A failed scrape is only ``nsd_up 0``."""

    lines = [
        "# HELP nsd_up Whether nsd-control stats_noreset succeeded.",
        "# TYPE nsd_up gauge",
        "nsd_up {}".format(1 if up else 0),
    ]
    if not up:
        return "\n".join(lines) + "\n"
    families: dict[str, dict] = {}
    for key in sorted(stats):
        sample = _sample(key, stats[key])
        if sample is None:
            continue
        name, labels, value, kind, help_text = sample
        family = families.get(name)
        if family is None:
            family = {"kind": kind, "help": help_text, "samples": []}
            families[name] = family
        family["samples"].append((labels, value))
    for name in sorted(families):
        family = families[name]
        lines.append("# HELP {} {}".format(name, _escape_help(family["help"])))
        lines.append("# TYPE {} {}".format(name, family["kind"]))
        for labels, value in sorted(family["samples"]):
            if labels:
                rendered = ",".join(
                    '{}="{}"'.format(label, _escape_label(text))
                    for label, text in labels)
                lines.append("{}{{{}}} {}".format(name, rendered, value))
            else:
                lines.append("{} {}".format(name, value))
    return "\n".join(lines) + "\n"


def render_metrics() -> tuple[str, int]:
    """Return ``(body, status)``. Status is 503 when NSD cannot be scraped."""

    ok, text = collect_nsd_stats()
    if not ok:
        return format_exposition({}, up=False), 503
    return format_exposition(parse_stats(text), up=True), 200


def _sample(key: str, value: str):
    if key in _GAUGES:
        return (_GAUGES[key], (), value, "gauge", "Current NSD " + key + ".")
    if key.startswith("time."):
        name = "nsd_" + key.replace(".", "_")
        return (name, (), value, "gauge", "NSD " + key + ".")
    if key.startswith("size."):
        name = "nsd_" + key.replace(".", "_")
        return (name, (), value, "gauge", "NSD " + key + ".")
    for prefix, metric, label, help_text in _LABELLED:
        if key.startswith(prefix):
            item = key[len(prefix):]
            if not item:
                return None
            return (metric, ((label, item), ), value, "counter", help_text)
    if key.startswith("num.") and key[len("num."):] in _PROTOCOLS:
        protocol = key[len("num."):]
        return (
            "nsd_queries_by_protocol_total",
            (("protocol", protocol), ),
            value,
            "counter",
            "Queries received, by transport.",
        )
    if key.startswith("num."):
        rest = key[len("num."):].replace(".", "_")
        if not rest:
            return None
        name = "nsd_" + rest + "_total"
        help_text = _COUNTER_HELP.get(key, "NSD counter " + key + ".")
        return (name, (), value, "counter", help_text)
    safe = key.replace(".", "_")
    if not safe:
        return None
    return ("nsd_" + safe, (), value, "gauge", "NSD statistic " + key + ".")


def _number(raw: str) -> str | None:
    if not raw or _NUMBER.fullmatch(raw) is None:
        return None
    return raw


def _is_int(raw: str) -> bool:
    if raw[:1] in "+-":
        raw = raw[1:]
    return raw.isdigit()


def _format_float(value: float) -> str:
    return format(value, "f").rstrip("0").rstrip(".") or "0"


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _escape_help(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n")

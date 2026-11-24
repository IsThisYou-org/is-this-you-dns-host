"""Parser and formatter for nsd-control stats_noreset output."""

import dns.name

from dns_host.config import Settings
from dns_host.nsd_metrics import (
    format_exposition,
    parse_stats,
    render_metrics,
)
from dns_host.nsdconf import render_nsd

# stats_noreset from NSD with server-count 1. Aggregate lines and the
# server0. copies of the same counters.
SAMPLE = """\
num.queries=14
server0.num.queries=14
num.type.A=8
server0.num.type.A=8
num.type.AAAA=3
server0.num.type.AAAA=3
num.class.IN=14
server0.num.class.IN=14
num.opcode.QUERY=13
server0.num.opcode.QUERY=13
num.opcode.NOTIFY=1
server0.num.opcode.NOTIFY=1
num.rcode.NOERROR=12
server0.num.rcode.NOERROR=12
num.rcode.NXDOMAIN=2
server0.num.rcode.NXDOMAIN=2
num.udp=10
server0.num.udp=10
num.udp6=1
server0.num.udp6=1
num.tcp=3
server0.num.tcp=3
num.tcp6=0
server0.num.tcp6=0
num.tls=0
server0.num.tls=0
num.tls6=0
server0.num.tls6=0
num.edns=6
server0.num.edns=6
num.raxfr=2
server0.num.raxfr=2
num.zone.master=0
num.zone.slave=1
num.zones=2
time.boot=1700000000.125000
time.elapsed=3600.5
size.db.mem=1048576
size.xfrd.mem=8192
"""


def test_sample_becomes_prometheus_text():
    text = format_exposition(parse_stats(SAMPLE), up=True)
    assert text.endswith("\n")
    assert "# HELP nsd_up Whether nsd-control stats_noreset succeeded." in text
    assert "# TYPE nsd_up gauge" in text
    assert "nsd_up 1" in text
    assert "# TYPE nsd_queries_by_type_total counter" in text
    assert 'nsd_queries_by_type_total{type="A"} 8' in text
    assert 'nsd_queries_by_type_total{type="AAAA"} 3' in text
    assert 'nsd_queries_by_type_total{type="A"} 16' not in text
    assert 'nsd_queries_by_rcode_total{rcode="NOERROR"} 12' in text
    assert 'nsd_queries_by_rcode_total{rcode="NXDOMAIN"} 2' in text
    assert 'nsd_queries_by_opcode_total{opcode="QUERY"} 13' in text
    assert 'nsd_queries_by_opcode_total{opcode="NOTIFY"} 1' in text
    assert 'nsd_queries_by_protocol_total{protocol="udp"} 10' in text
    assert 'nsd_queries_by_protocol_total{protocol="tcp6"} 0' in text
    assert 'nsd_queries_by_class_total{class="IN"} 14' in text
    assert "# TYPE nsd_queries_total counter" in text
    assert "nsd_queries_total 14" in text
    assert "nsd_raxfr_total 2" in text
    assert "# TYPE nsd_zones gauge" in text
    assert "nsd_zones 2\n" in text
    assert "nsd_zones_total" not in text
    assert "nsd_zones_master 0\n" in text
    assert "nsd_zones_slave 1\n" in text
    assert "# TYPE nsd_time_boot gauge" in text
    assert "nsd_time_boot 1700000000.125000" in text
    assert "# TYPE nsd_time_elapsed gauge" in text
    assert "nsd_time_elapsed 3600.5" in text
    assert "nsd_time_boot_total" not in text
    assert "# TYPE nsd_size_db_mem gauge" in text
    assert "nsd_size_db_mem 1048576" in text
    assert "server0" not in text


def test_per_server_lines_are_summed_when_there_is_no_aggregate():
    text = "server0.num.queries=2\nserver1.num.queries=3\nserver0.num.type.A=2\n"
    parsed = parse_stats(text)
    assert parsed == {"num.queries": "5", "num.type.A": "2"}


def test_failed_scrape_is_only_nsd_up_zero():
    text = format_exposition({}, up=False)
    assert text == (
        "# HELP nsd_up Whether nsd-control stats_noreset succeeded.\n"
        "# TYPE nsd_up gauge\n"
        "nsd_up 0\n")


def test_label_values_are_escaped():
    text = format_exposition({'num.type.A"B': "1"}, up=True)
    assert 'nsd_queries_by_type_total{type="A\\"B"} 1' in text


def test_render_metrics_status(monkeypatch):
    monkeypatch.setattr("dns_host.nsd_metrics.collect_nsd_stats", lambda:
                        (True, SAMPLE))
    body, status = render_metrics()
    assert status == 200
    assert "nsd_up 1" in body
    monkeypatch.setattr("dns_host.nsd_metrics.collect_nsd_stats", lambda:
                        (False, ""))
    body, status = render_metrics()
    assert status == 503
    assert "nsd_up 0" in body


def test_remote_control_listens_on_localhost_only():
    settings = Settings(
        catalog_zone=dns.name.from_text("catalog.example.net."))
    text = render_nsd(settings, [])
    assert "control-enable: yes" in text
    assert "control-interface: 127.0.0.1" in text
    assert "control-port: 8952" in text
    assert "control-interface: /run/nsd/nsd.control" not in text
    assert "/opt/data/nsd/nsd_server.key" in text
    assert "/opt/data/nsd/nsd_control.pem" in text

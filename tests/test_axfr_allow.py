"""axfr_allow: extra NSD transfer clients, not NOTIFY targets."""

from pathlib import Path

import dns.message
import dns.name
import pytest

from dns_host.config import Secondary, Settings
from dns_host.notify import UdpNotifier
from dns_host.nsdconf import render_nsd

_ROOT = Path(__file__).resolve().parents[1]


def _acl(text: str, key: str) -> list[str]:
    prefix = f"{key}:"
    return [
        line.split(prefix, 1)[1].strip() for line in text.splitlines()
        if line.strip().startswith(prefix)
    ]


def test_axfr_allow_defaults_to_empty(tmp_path):
    assert Settings().axfr_allow == []
    assert Settings.from_mapping({}).axfr_allow == []
    assert Settings.from_mapping({"axfr_allow": None}).axfr_allow == []
    assert Settings.from_mapping({"axfr_allow": ""}).axfr_allow == []
    assert Settings.from_mapping({"axfr_allow": []}).axfr_allow == []
    blank = tmp_path / "blank.yaml"
    blank.write_text("axfr_allow:\n", encoding="utf-8")
    assert Settings.load(blank).axfr_allow == []


def test_axfr_allow_normalises_bare_addresses_and_prefixes():
    settings = Settings.from_mapping({
        "axfr_allow": [
            "203.0.113.50",
            "192.0.2.10/24",
            "2001:DB8::5",
            "2001:db8:1::/48",
            "203.0.113.50",
        ],
    })
    assert settings.axfr_allow == [
        "203.0.113.50/32",
        "192.0.2.0/24",
        "2001:db8::5/128",
        "2001:db8:1::/48",
    ]
    comma = Settings.from_mapping(
        {"axfr_allow": "198.51.100.8, 2001:db8::/32"})
    assert comma.axfr_allow == ["198.51.100.8/32", "2001:db8::/32"]


@pytest.mark.parametrize(
    "value",
    [
        ["192.0.2.0/33"],
        ["nope"],
        ["192.0.2.10:53"],
        ["2001:db8::/129"],
        [24],
        {
            "cidr": "10.0.0.0/8"
        },
    ],
)
def test_bad_axfr_allow_is_a_startup_error(value, tmp_path):
    with pytest.raises(SystemExit, match="invalid axfr_allow") as raised:
        Settings.from_mapping({"axfr_allow": value})
    message = str(raised.value)
    assert "CIDR" in message or "list of CIDRs" in message
    with pytest.raises(SystemExit, match="invalid axfr_allow"):
        Settings(axfr_allow=value)

    path = tmp_path / "config.yaml"
    path.write_text("axfr_allow:\n  - 10.1.2.3/33\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="invalid axfr_allow '10.1.2.3/33'"):
        Settings.load(path)


def test_provide_xfr_includes_axfr_allow_and_notify_does_not():
    settings = Settings(
        secondaries=[
            Secondary(
                "192.0.2.10",
                53,
                tsig_key_name="one.example.",
                tsig_secret="c2VjcmV0MQ==",
            ),
            Secondary("192.0.2.11", 5353),
        ],
        axfr_allow=["203.0.113.9/24", "2001:db8::1", "198.51.100.8"],
        catalog_zone=dns.name.from_text("catalog.example.net."),
    )
    text = render_nsd(settings)
    provide = _acl(text, "provide-xfr")
    notify = _acl(text, "notify")
    assert provide.count("192.0.2.10 one.example.") == 2
    assert provide.count("192.0.2.11@5353 NOKEY") == 2
    assert provide.count("203.0.113.0/24 NOKEY") == 2
    assert provide.count("2001:db8::1/128 NOKEY") == 2
    assert provide.count("198.51.100.8/32 NOKEY") == 2
    assert notify.count("192.0.2.10 one.example.") == 2
    assert notify.count("192.0.2.11@5353 NOKEY") == 2
    assert all("203.0.113" not in line for line in notify)
    assert all("2001:db8" not in line for line in notify)
    assert all("198.51.100" not in line for line in notify)
    assert "request-xfr: AXFR 127.0.0.1@5353 NOKEY" in text


def test_allowed_axfr_ips_matches_secondary_hosts_and_subnets():
    settings = Settings(
        secondaries=[
            Secondary("192.0.2.10", 53),
            Secondary("2001:db8::10", 53),
        ],
        axfr_allow=["203.0.113.0/24", "2001:db8:1::/48"],
    )
    allow = settings.allowed_axfr_ips
    assert "192.0.2.10" in allow
    assert "192.0.2.11" not in allow
    assert "2001:db8::10" in allow
    assert "2001:db8::11" not in allow
    assert "203.0.113.1" in allow
    assert "203.0.113.255" in allow
    assert "203.0.114.1" not in allow
    assert "2001:db8:1::abcd" in allow
    assert "2001:db8:2::1" not in allow
    assert "not-an-ip" not in allow
    assert list(allow) == [
        "192.0.2.10/32",
        "2001:db8::10/128",
        "203.0.113.0/24",
        "2001:db8:1::/48",
    ]
    everyone = Settings(axfr_allow=["0.0.0.0/0"])
    assert "198.51.100.1" in everyone.allowed_axfr_ips
    assert "2001:db8::1" not in everyone.allowed_axfr_ips


def test_notify_targets_stay_on_the_secondary_list(monkeypatch):
    calls = []

    def fake_udp(query, host, timeout=2, port=53, **_kwargs):
        calls.append((host, port))
        return dns.message.make_response(query)

    monkeypatch.setattr("dns.query.udp", fake_udp)
    settings = Settings(
        secondaries=[Secondary("192.0.2.10", 5353)],
        axfr_allow=["203.0.113.0/24", "198.51.100.8"],
    )

    class Counter:

        def incr(self, key):
            return None

    UdpNotifier(settings, Counter()).notify("user.example.", None)
    assert calls == [("192.0.2.10", 5353)]


def test_sample_configs_ship_an_empty_axfr_allow():
    example = (_ROOT /
               "deploy/config.example.yaml").read_text(encoding="utf-8")
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    assert "axfr_allow: []" in example
    assert "axfr_allow" in readme
    assert Settings.load(_ROOT / "deploy/config.example.yaml").axfr_allow == []
    assert Settings.load(_ROOT / "deploy/config.tls.yaml").axfr_allow == []

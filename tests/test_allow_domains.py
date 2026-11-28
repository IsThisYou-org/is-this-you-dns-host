"""allow-domains: strict child names, refused before any other work."""

from pathlib import Path

import pytest

from dns_host.admit import admit
from dns_host.catalogfile import Catalog
from dns_host.config import Settings
from dns_host.controller import Controller
from dns_host.errors import ApiError
from dns_host.names import normalise_name
from dns_host.notify import RecordingNotifier
from dns_host.spool import submit
from tests.conftest import post
from tests.test_architecture import _job, _settings, _store

_ROOT = Path(__file__).resolve().parents[1]


def _forbid_further_work(monkeypatch, env):

    def explode(*_args, **_kwargs):
        raise AssertionError("a refused domain did further work")

    monkeypatch.setattr("dns_host.app._read_body", explode)
    monkeypatch.setattr("dns_host.app.normalise_apex", explode)
    monkeypatch.setattr(env.store, "allow_rate", explode)
    monkeypatch.setattr(env.store, "incr", explode)
    monkeypatch.setattr(env.store, "negative_get", explode)
    monkeypatch.setattr("dns_host.admit.Catalog.load", explode)
    monkeypatch.setattr("dns_host.admit.parse_upload", explode)
    monkeypatch.setattr("dns_host.admit.parent_checks", explode)
    monkeypatch.setattr("dns_host.admit.offline_checks", explode)


def _post_apex(env, apex, body=b"not-json", content_type="text/plain"):
    return env.client.post(
        f"/v1/zones/{apex}",
        data=body,
        headers={
            "Content-Type": content_type,
            "X-Real-IP": "203.0.113.10",
        },
    )


def test_missing_or_empty_list_allows_every_domain(tmp_path):
    bare = Settings()
    assert bare.allow_domains == []
    assert bare.domain_allowed("isthisyou.me")
    assert bare.domain_allowed("notisthisyou.me")
    assert bare.domain_allowed("james.isthisyou.me")

    loaded = Settings.from_mapping({})
    assert loaded.allow_domains == []
    assert loaded.domain_allowed("isthisyou.me.")
    for empty in (None, "", []):
        settings = Settings.from_mapping({"allow-domains": empty})
        assert settings.allow_domains == []
        assert settings.domain_allowed("notisthisyou.me")

    blank = tmp_path / "blank.yaml"
    blank.write_text("allow-domains:\n", encoding="utf-8")
    assert Settings.load(blank).allow_domains == []


def test_strict_child_match_is_whole_labels():
    settings = Settings(allow_domains=["IsThisYou.Me.", "isthisyou.me"])
    assert settings.allow_domains == ["isthisyou.me"]
    assert settings.domain_allowed("james.isthisyou.me")
    assert settings.domain_allowed("James.IsThisYou.Me.")
    assert settings.domain_allowed("a.b.isthisyou.me")
    assert settings.domain_allowed("a.b.ISTHISYOU.ME.")
    assert not settings.domain_allowed("isthisyou.me")
    assert not settings.domain_allowed("isthisyou.me.")
    assert not settings.domain_allowed("IsThisYou.Me")
    assert not settings.domain_allowed("notisthisyou.me")
    assert not settings.domain_allowed("notisthisyou.me.")
    assert not settings.domain_allowed("isthisyou.me.evil.example")

    either = Settings(allow_domains=["example.net", "isthisyou.me"])
    assert either.domain_allowed("a.example.net")
    assert either.domain_allowed("a.b.isthisyou.me")
    assert not either.domain_allowed("a.example.com")
    assert not either.domain_allowed("example.net")


def test_unicode_name_matches_its_dns_form():
    settings = Settings.from_mapping({"allow-domains": ["Bücher.example."]})
    assert settings.allow_domains == ["xn--bcher-kva.example"]
    assert settings.domain_allowed("www.Bücher.example")
    assert settings.domain_allowed("www.xn--bcher-kva.example.")
    assert settings.domain_allowed("a.b.bücher.example")
    assert not settings.domain_allowed("Bücher.example")
    assert not settings.domain_allowed("xn--bcher-kva.example.")
    assert not settings.domain_allowed("notbücher.example")


def test_configured_names_must_be_a_list_of_domain_names(tmp_path):
    with pytest.raises(SystemExit, match="allow-domains") as raised:
        Settings.from_mapping({
            "allow-domains": ["*.example", 3],
            "gunicorn_workers": 0,
        })
    text = str(raised.value)
    assert "wildcard" in text
    assert "3" in text
    assert "gunicorn_workers" in text

    for bad in ("isthisyou.me", ["not a domain"], ["-bad.example"], ["."], [True], {"name": "example"}):
        with pytest.raises(SystemExit, match="allow-domains"):
            Settings.from_mapping({"allow-domains": bad})
        with pytest.raises(SystemExit, match="allow-domains"):
            Settings(allow_domains=bad)

    path = tmp_path / "config.yaml"
    path.write_text("allow-domains:\n  - '*.example'\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="allow-domains"):
        Settings.load(path)

    with pytest.raises(SystemExit, match="unknown key 'allow_domains'"):
        Settings.from_mapping({"allow_domains": ["example"]})


def test_underscore_labels_are_valid_domain_names():
    settings = Settings(allow_domains=["_auth.example"])
    assert settings.allow_domains == ["_auth.example"]
    assert settings.domain_allowed("www._auth.example")
    assert not settings.domain_allowed("_auth.example")


def test_example_config_ships_an_empty_allow_list():
    example = (_ROOT / "deploy/config.example.yaml").read_text(encoding="utf-8")
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    docker = (_ROOT / "docker-README.md").read_text(encoding="utf-8")
    assert "allow-domains: []" in example
    assert "allow-domains" in readme
    assert "allow-domains" in docker
    assert "behaviour" in readme
    loaded = Settings.load(_ROOT / "deploy/config.example.yaml")
    assert loaded.allow_domains == []
    assert loaded.domain_allowed("notisthisyou.me")
    tls = Settings.load(_ROOT / "deploy/config.tls.yaml")
    assert tls.allow_domains == []


def test_refused_url_does_no_other_work(env, monkeypatch):
    env.settings.allow_domains = ["isthisyou.me"]
    _forbid_further_work(monkeypatch, env)
    for apex in (
            "isthisyou.me",
            "isthisyou.me.",
            "IsThisYou.Me",
            "notisthisyou.me",
            "notisthisyou.me.",
    ):
        response = _post_apex(env, apex)
        assert response.status_code == 403, response.get_json()
        body = response.get_json()
        assert body["error"] == "domain_not_allowed"
        assert apex in body["message"]
        assert "allow-domains" in body["message"]
        assert "child" in body["message"]
    external = env.client.post(
        "/ext/v1/zones/notisthisyou.me",
        data=b"not-json",
        headers={"Content-Type": "text/plain"},
    )
    assert external.status_code == 403
    assert external.get_json()["error"] == "domain_not_allowed"
    assert env.lab.calls == []


def test_otherwise_valid_zone_is_refused_before_lookups(env, monkeypatch):
    env.settings.allow_domains = ["user.example"]
    _forbid_further_work(monkeypatch, env)
    response = post(env, env.lab.zone())
    assert response.status_code == 403, response.get_json()
    body = response.get_json()
    assert body["error"] == "domain_not_allowed"
    assert "user.example" in body["message"]
    assert env.lab.calls == []


def test_strict_child_still_goes_through_admission(env):
    env.settings.allow_domains = ["example"]
    response = post(env, env.lab.zone())
    assert response.status_code == 201, response.get_json()
    assert response.get_json()["apex"] == "user.example."
    assert env.lab.calls


def test_deeper_child_passes_the_gate_and_is_validated_next(env, monkeypatch):
    env.settings.allow_domains = ["isthisyou.me"]

    def explode(*_args, **_kwargs):
        raise AssertionError("parent lookup ran")

    monkeypatch.setattr("dns_host.admit.parent_checks", explode)
    response = _post_apex(
        env,
        "a.b.IsThisYou.Me.",
        body=b"{}",
        content_type="application/json",
    )
    assert response.status_code == 400, response.get_json()
    assert response.get_json()["error"] == "bad_request"
    assert env.lab.calls == []

    wildcard = _post_apex(
        env,
        "*.james.isthisyou.me",
        body=b"{}",
        content_type="application/json",
    )
    assert wildcard.status_code == 422, wildcard.get_json()
    assert wildcard.get_json()["error"] == "bad_label"


def test_admit_refuses_before_catalog_or_database():
    settings = Settings(allow_domains=["isthisyou.me"])

    class Boom:

        def __getattr__(self, name):
            raise AssertionError(name)

    with pytest.raises(ApiError) as caught:
        admit(
            {"apex": "notisthisyou.me."},
            normalise_name("notisthisyou.me."),
            settings,
            Boom(),
            Boom(),
            None,
            "203.0.113.10",
        )
    assert caught.value.status == 403
    assert caught.value.error == "domain_not_allowed"
    assert "notisthisyou.me." in caught.value.message


def test_empty_list_still_installs_any_apex(tmp_path, monkeypatch):
    settings = _settings(tmp_path, now=1_700_000_000, monkeypatch=monkeypatch)
    assert settings.allow_domains == []
    store = _store(settings)
    controller = Controller(settings, store, notifier=RecordingNotifier())
    submit(tmp_path / "spool", _job(apex="notisthisyou.me.", serial=10, expires_at=1_800_000_000))
    controller.run_once()
    catalog = Catalog(settings)
    catalog.load()
    assert catalog.has("notisthisyou.me.")
    assert store.list_members() == ["notisthisyou.me."]


def test_controller_installs_only_a_strict_child(tmp_path, monkeypatch):
    settings = _settings(tmp_path, now=1_700_000_000, monkeypatch=monkeypatch)
    settings.allow_domains = ["isthisyou.me"]
    store = _store(settings)
    calls = []
    real = store.replace_zone

    def wrapped(**kwargs):
        calls.append(kwargs["apex"])
        return real(**kwargs)

    monkeypatch.setattr(store, "replace_zone", wrapped)
    controller = Controller(settings, store, notifier=RecordingNotifier())
    spool = tmp_path / "spool"
    far = 1_800_000_000
    submit(spool, _job(apex="notisthisyou.me.", serial=10, expires_at=far))
    submit(spool, _job(apex="isthisyou.me.", serial=11, expires_at=far))
    submit(spool, _job(apex="james.isthisyou.me.", serial=12, expires_at=far))
    submit(spool, _job(apex="a.b.isthisyou.me.", serial=13, expires_at=far))
    controller.run_once()
    catalog = Catalog(settings)
    catalog.load()
    installed = ["a.b.isthisyou.me.", "james.isthisyou.me."]
    assert sorted(calls) == installed
    assert sorted(catalog.zones) == installed
    assert store.list_members() == installed

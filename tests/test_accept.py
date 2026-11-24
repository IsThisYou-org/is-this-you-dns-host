from tests.conftest import post


def test_valid_zone_is_admitted_and_catalog_is_notified_first(env):
    response = post(env, env.lab.zone())
    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    assert body["apex"] == "user.example."
    assert body["catalogUpdated"] is True
    assert body["serial"] == env.clock.t
    assert "nextExpireHint" in body
    assert env.notifier.zones == ["catalog.svc.test.", "user.example."]
    assert env.lab.calls, "parent lookup should run for a valid zone"
    assert any(call["server"] for call in env.lab.calls)
    assert all(call["rd"] == 0 and call["do"] == 1 for call in env.lab.calls)

    env.notifier.zones.clear()
    before = len(env.lab.calls)
    again = post(env, env.lab.zone(serial=env.clock.t + 10))
    assert again.status_code == 200, again.get_json()
    assert again.get_json()["catalogUpdated"] is False
    assert env.notifier.zones == ["catalog.svc.test.", "user.example."]
    assert len(env.lab.calls) > before


def test_nsec_zone_is_rejected(env):
    response = post(env, env.lab.zone(nsec3=False, serial=env.clock.t + 3))
    assert response.status_code == 422, response.get_json()
    assert response.get_json()["error"] == "type_not_allowed"
    assert env.lab.calls == []


def test_health_and_metrics(env, monkeypatch):
    health = env.client.get("/health")
    assert health.status_code == 200
    assert health.get_json()["dns"] == "skipped"
    assert health.get_json()["catalogZone"] == "catalog.svc.test."
    monkeypatch.setattr("dns_host.nsd_metrics.collect_nsd_stats", lambda:
                        (False, ""))
    metrics = env.client.get("/metrics")
    assert metrics.status_code == 503
    assert "version=0.0.4" in metrics.content_type
    assert "nsd_up 0" in metrics.get_data(as_text=True)
    assert env.client.get("/ext/metrics").status_code == 404


def test_config_lists_service_nameservers(env):
    response = env.client.get("/config")
    assert response.status_code == 200
    assert response.get_json() == {"ns": ["ns1.svc.test.", "ns2.svc.test."]}
    assert response.headers["Cache-Control"] == "public, max-age=300"
    missing = env.client.get("/v1/config")
    assert missing.status_code == 404

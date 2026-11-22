"""The administrator: retention that really deletes (and archives first), alerts that can be taken down without breaking
their proof, a public counter that never drops, French titles, and a role analysts do not have."""
import gzip
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from checkam import ledger, retention, security, store
from checkam.app import app

client = TestClient(app)


def token(email: str, password: str, role: str) -> dict:
    store.add_analyst(email, password, email.split("@")[0], "Test", role=role)
    security._hits.clear()
    if role == "admin":
        # an administrator signs in with a code as well (tested in test_totp.py); here the session is issued directly
        return {"Authorization": "Bearer " + store.make_token(email)}
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


@pytest.fixture()
def admin():
    return token("boss@example.org", "a-long-test-password", "admin")


@pytest.fixture()
def plain():
    return token("desk@example.org", "another-test-password", "analyst")


def iso(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat(timespec="seconds")


def put_check(cid: str, days_ago: int, verdict="scam", scheme="prize"):
    with store._lock:
        store.conn().execute("INSERT OR REPLACE INTO checks (id, created, masked_text, verdict, scheme, language) VALUES (?,?,?,?,?,'en')", (cid, iso(days_ago), f"text {cid}", verdict, scheme))
        store.conn().commit()


def test_admin_routes_need_the_admin_role(admin, plain):
    for method, path in (("get", "/admin/overview"), ("get", "/admin/alerts"), ("get", "/admin/archive/checks-2025-01.jsonl.gz")):
        assert getattr(client, method)(path).status_code == 401
        assert getattr(client, method)(path, headers=plain).status_code == 403
    assert client.get("/admin/overview", headers=admin).status_code == 200
    assert client.post("/admin/retention", json={"dry_run": True}, headers=plain).status_code == 403


def test_settings_are_checked_and_logged(admin):
    assert client.post("/admin/settings", json={"check_keep_days": 5}, headers=admin).status_code == 400
    r = client.post("/admin/settings", json={"check_keep_days": 400, "alert_show_days": 60}, headers=admin)
    assert r.status_code == 200 and r.json()["settings"]["check_keep_days"] == 400
    assert any(a["action"] == "settings" for a in store.admin_audit(10))
    client.post("/admin/settings", json={"check_keep_days": 730, "alert_show_days": 90}, headers=admin)


def test_a_dry_run_changes_nothing_and_a_real_run_archives_then_deletes(admin, monkeypatch, tmp_path):
    monkeypatch.setattr(retention, "archive_dir", lambda: tmp_path)
    monkeypatch.setattr(retention.world, "forget", lambda *a, **k: {"observations": 0, "edges": 0, "entities": 0})
    put_check("C-0ld00001", 900)
    put_check("C-0ld00002", 900, verdict="suspicious", scheme="job")
    put_check("C-ne000001", 3)
    before = store.check_stats()["total"]

    dry = client.post("/admin/retention", json={"dry_run": True}, headers=admin).json()
    assert dry["dry_run"] and dry["checks_due"] >= 2
    assert store.get_check("C-0ld00001") is not None and not list(tmp_path.glob("*.gz"))

    real = client.post("/admin/retention", json={"dry_run": False}, headers=admin).json()
    assert real["archived"] >= 2 and real["deleted"]["checks"] >= 2
    assert store.get_check("C-0ld00001") is None and store.get_check("C-ne000001") is not None
    files = list(tmp_path.glob("checks-*.jsonl.gz"))
    assert files
    rows = [json.loads(line) for f in files for line in gzip.open(f, "rt", encoding="utf-8")]
    assert {"C-0ld00001", "C-0ld00002"} <= {r["id"] for r in rows}
    assert store.check_stats()["total"] == before, "the public counter never goes down when old checks are archived"
    assert client.get("/admin/archive/" + files[0].name, headers=admin).status_code == 200
    for bad in ("..%2F..%2Fetc%2Fpasswd", "checks-2025-01.jsonl.gz%00", "..", "checks-9999-99.jsonl.gz"):
        r = client.get("/admin/archive/" + bad, headers=admin)
        assert r.status_code in (404, 422) or ("<html" in r.text.lower() and "root:" not in r.text), (bad, r.status_code)


def test_archives_past_their_time_are_deleted(monkeypatch, tmp_path):
    monkeypatch.setattr(retention, "archive_dir", lambda: tmp_path)
    old, recent = tmp_path / "checks-2010-01.jsonl.gz", tmp_path / f"checks-{datetime.now(timezone.utc):%Y-%m}.jsonl.gz"
    for f in (old, recent):
        f.write_bytes(b"x")
    gone = retention._expire_archives(store.settings())
    assert old.name in gone and recent.exists()


def test_retracting_an_alert_hides_it_but_the_signed_chain_still_verifies(admin):
    a = store.publish_alert({"campaign_id": "cmp_t", "title": "Beware of test links", "body_en": "Avoid them.", "body_fr": "Evitez-les.", "numbers": [], "published_by": "x", "run_id": "", "contract_id": "k"})
    b = store.publish_alert({"campaign_id": "cmp_t2", "title": "Another warning", "body_en": "Be careful.", "body_fr": "", "numbers": [], "published_by": "x", "run_id": "", "contract_id": "k"})
    assert {a["id"], b["id"]} <= {x["id"] for x in client.get("/alerts").json()["alerts"]}
    assert client.post(f"/admin/alerts/{a['id']}/retract", json={"reason": "published by mistake"}, headers=admin).status_code == 200
    shown = {x["id"] for x in client.get("/alerts").json()["alerts"]}
    assert a["id"] not in shown and b["id"] in shown
    assert ledger.verify_chain(store.alerts(10_000, oldest_first=True))["valid"], "retraction must not break the proof"
    assert client.post(f"/admin/alerts/{a['id']}/restore", headers=admin).status_code == 200
    assert a["id"] in {x["id"] for x in client.get("/alerts").json()["alerts"]}


def test_alerts_older_than_the_display_window_leave_the_page_but_not_the_log(admin):
    # dated before it is signed, so its proof stays valid (the date is part of what is signed)
    a = store.publish_alert({"created": iso(200), "campaign_id": "cmp_old", "title": "An old warning", "body_en": "x", "body_fr": "", "numbers": [], "published_by": "x", "run_id": "", "contract_id": "k"})
    assert a["id"] not in {x["id"] for x in store.alerts(50, display=True)}
    assert a["id"] in {x["id"] for x in store.alerts(10_000)}
    assert ledger.verify_chain(store.alerts(10_000, oldest_first=True))["valid"]


def test_french_titles_sit_beside_the_signed_record():
    a = store.publish_alert({"campaign_id": "cmp_fr", "title": "Prize scam targets Cameroon", "body_en": "x", "body_fr": "y", "numbers": [], "published_by": "x", "run_id": "", "contract_id": "k"})
    assert a["id"] in {x["id"] for x in store.alerts_missing_title_fr()}
    store.set_title_fr(a["id"], "Une arnaque aux faux gains vise le Cameroun")
    got = next(x for x in store.alerts(50, display=True) if x["id"] == a["id"])
    assert got["title_fr"].startswith("Une arnaque")
    assert ledger.verify(next(x for x in store.alerts(10_000) if x["id"] == a["id"]))["valid"]


def test_the_administrator_can_delete_one_check_everywhere(admin, monkeypatch):
    monkeypatch.setattr(retention.world, "forget", lambda *a, **k: {"observations": 1, "edges": 2, "entities": 0})
    put_check("C-de1e7e01", 2)
    r = client.post("/admin/checks/delete", json={"check_id": "C-de1e7e01"}, headers=admin)
    assert r.status_code == 200 and r.json()["checks"] == 1
    assert store.get_check("C-de1e7e01") is None
    assert client.post("/admin/checks/delete", json={"check_id": "../etc"}, headers=admin).status_code == 422


def test_the_administrator_manages_analyst_accounts(admin):
    r = client.post("/admin/analysts", json={"email": "new.analyst@example.org", "name": "New Analyst", "org": "CERT", "password": "twelve-chars-ok"}, headers=admin)
    assert r.status_code == 200
    assert client.post("/admin/analysts", json={"email": "new.analyst@example.org", "name": "Again", "password": "twelve-chars-ok"}, headers=admin).status_code == 409
    assert client.post("/admin/analysts", json={"email": "short@example.org", "name": "S", "password": "short"}, headers=admin).status_code == 422
    assert client.post("/admin/analysts", json={"email": "not-an-email", "name": "S", "password": "twelve-chars-ok"}, headers=admin).status_code == 422
    assert store.analyst_role("new.analyst@example.org") == "analyst"
    # a new analyst can sign in but is not an administrator
    security._hits.clear()
    login = client.post("/auth/login", json={"email": "new.analyst@example.org", "password": "twelve-chars-ok"})
    assert login.status_code == 200 and login.json()["analyst"]["role"] == "analyst"
    assert client.get("/admin/overview", headers={"Authorization": "Bearer " + login.json()["token"]}).status_code == 403
    assert client.post("/admin/analysts/delete", json={"email": "boss@example.org"}, headers=admin).status_code == 400  # not yourself
    assert client.post("/admin/analysts/delete", json={"email": "new.analyst@example.org"}, headers=admin).status_code == 200
    assert store.analyst_role("new.analyst@example.org") == ""
    assert client.post("/admin/analysts/delete", json={"email": "nobody@example.org"}, headers=admin).status_code == 404
    log = [a["action"] for a in store.admin_audit(20)]
    assert "add_analyst" in log and "remove_analyst" in log


def test_an_administrator_account_cannot_be_removed_from_the_screen(admin):
    token("second.boss@example.org", "a-long-test-password-2", "admin")
    assert client.post("/admin/analysts/delete", json={"email": "second.boss@example.org"}, headers=admin).status_code == 400


def test_the_archive_sits_beside_the_database_so_it_survives_a_redeploy():
    from checkam import config
    if not config.env("CHECKAM_ARCHIVE_DIR"):
        assert config.ARCHIVE_DIR == config.DB_PATH.parent / "archive"


def test_an_analyst_can_open_the_whole_story_of_a_check(plain):
    put_check("C-5ee0de01", 1, verdict="suspicious", scheme="job")
    store.add_flag("C-5ee0de01", "scam", "looks like the fake job from last week")
    assert client.get("/analyst/checks/C-5ee0de01").status_code == 401
    r = client.get("/analyst/checks/C-5ee0de01", headers=plain)
    assert r.status_code == 200
    body = r.json()
    assert body["check"]["id"] == "C-5ee0de01" and body["check"]["scheme"] == "job"
    assert body["flags"] and body["flags"][0]["suggested"] == "scam" and body["flags"][0]["status"] == "open"
    assert isinstance(body["trace"], list)
    assert client.get("/analyst/checks/C-00000000", headers=plain).status_code == 404


def test_the_administrator_can_change_a_password_and_the_old_one_stops_working(admin):
    store.add_analyst("old.judge@example.org", "the-old-password-1", "Judge", "Hackathon", role="analyst")
    r = client.post("/admin/analysts/update", json={"email": "old.judge@example.org", "org": "CheckAm", "password": "a-brand-new-password-2"}, headers=admin)
    assert r.status_code == 200
    security._hits.clear()
    assert client.post("/auth/login", json={"email": "old.judge@example.org", "password": "the-old-password-1"}).status_code == 401
    ok = client.post("/auth/login", json={"email": "old.judge@example.org", "password": "a-brand-new-password-2"})
    assert ok.status_code == 200 and ok.json()["analyst"]["org"] == "CheckAm" and ok.json()["analyst"]["role"] == "analyst"
    assert client.post("/admin/analysts/update", json={"email": "old.judge@example.org", "password": "short"}, headers=admin).status_code == 422
    assert client.post("/admin/analysts/update", json={"email": "nobody@example.org", "name": "X"}, headers=admin).status_code == 404
    assert any(a["action"] == "update_analyst" and "password changed" in a["detail"] for a in store.admin_audit(10))

"""Abuse limits, headers, input bounds, auth and privacy of what we log."""
import os

os.environ["CHECKAM_SEED_ON_START"] = "false"
from fastapi.testclient import TestClient  # noqa: E402

from checkam import security, store  # noqa: E402
from checkam.app import app  # noqa: E402
from checkam.trace import Trace  # noqa: E402

client = TestClient(app)


def test_security_headers_on_every_page():
    r = client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_sign_in_is_throttled():
    security._hits.clear()
    codes = [client.post("/auth/login", json={"email": "x@y.z", "password": "wrong"}).status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[-1] == 429


def test_checks_are_rate_limited_per_client():
    security._hits.clear()
    for _ in range(8):
        assert security.allowed("1.2.3.4", "check")[0]
    assert not security.allowed("1.2.3.4", "check")[0]
    assert security.allowed("5.6.7.8", "check")[0], "one client must not block another"


def test_oversized_input_is_refused():
    security._hits.clear()
    assert client.post("/check", json={"text": "x" * 5000}).status_code == 422


def test_analyst_routes_need_a_valid_token():
    assert client.get("/analyst/campaigns").status_code == 401
    assert client.get("/analyst/campaigns", headers={"Authorization": "Bearer forged|9999999999|abc"}).status_code == 401
    store.add_analyst("a@b.c", "s3cret-pass", "A")
    good = store.make_token("a@b.c")
    email, exp, sig = good.split("|")
    assert store.read_token(f"other@b.c|{exp}|{sig}") is None, "a token cannot be moved to another account"


def test_traces_never_hold_a_real_number():
    t = Trace(echo=False)
    line = t.log("Intake", "facts", input="Send back to 677 12 34 56 now")
    assert "12 34 56" not in line["input_summary"]


def test_desk_figures_split_by_operator_from_stored_checks(tmp_path, monkeypatch):
    from checkam import config, store
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "desk.db")
    monkeypatch.setattr(store, "_conn", None)
    base = {"masked_text": "x", "confidence": 0.9, "language": "en", "links": [], "scam_types": [], "campaign_id": None, "run_id": "r", "channel": "text"}
    store.save_check({**base, "id": "1", "created": "2026-10-25T01:00:00", "verdict": "scam", "numbers": [], "operator": "mtn", "amount_fcfa": 25000})
    store.save_check({**base, "id": "2", "created": "2026-10-25T02:00:00", "verdict": "looks_genuine", "numbers": [], "operator": "orange", "amount_fcfa": 5000})
    allops, mtn = store.analytics(), store.analytics(operator="mtn")
    assert allops["kept_fcfa"] == 25000 and allops["by_operator"]["mtn"] == {"checks": 1, "flagged": 1}
    assert mtn["total"] == 1 and [f["id"] for f in mtn["flagged"]] == ["1"]
    assert store.analytics(operator="orange")["kept_fcfa"] == 0
    monkeypatch.setattr(store, "_conn", None)

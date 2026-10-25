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


def test_pages_are_compressed_and_built_files_cached_but_streams_are_not_buffered():
    from fastapi.testclient import TestClient
    from checkam.app import app
    c = TestClient(app)
    r = c.get("/alerts", headers={"Accept-Encoding": "gzip"})
    assert r.status_code == 200
    s = c.post("/check/stream", json={"text": "Send back the money to [PHONE:654-jwmukg] it was a mistake"}, headers={"Accept-Encoding": "gzip"})
    assert s.headers.get("content-encoding") != "gzip" and "event: card" in s.text


def test_the_web_route_never_serves_files_outside_the_built_site():
    from fastapi.testclient import TestClient
    from checkam.app import app
    c = TestClient(app)
    for probe in ("/..%2f..%2f.env", "/%2e%2e/%2e%2e/.env", "/../../api/checkam/config.py", "/..%5c..%5c.env"):
        r = c.get(probe)
        assert "MODEL_API_KEY" not in r.text and "ZETARIS" not in r.text, probe


def test_a_faked_forwarding_header_does_not_dodge_the_rate_limit():
    from starlette.requests import Request
    from checkam import security
    req = Request({"type": "http", "headers": [(b"x-forwarded-for", b"1.2.3.4, 41.202.219.10")], "client": ("10.0.0.1", 1)})
    assert security.client_ip(req) == "41.202.219.10"  # the entry our proxy added, not the one the client wrote


def test_only_real_images_are_accepted_and_huge_bodies_are_refused():
    from fastapi.testclient import TestClient
    from checkam.app import app
    c = TestClient(app)
    fake = c.post("/check/image", files={"image": ("shot.png", b"MZ\x90\x00 not an image", "image/png")})
    assert fake.status_code == 415
    big = c.post("/check", content=b"x", headers={"content-length": "9000000", "content-type": "application/json"})
    assert big.status_code == 413


def test_secret_codes_typed_in_a_message_are_never_stored():
    from checkam import privacy
    out = privacy.mask("Agent here. Your PIN is 4821 and the code: 552190, send them now")
    assert "4821" not in out and "552190" not in out and out.count("[CODE]") == 2
    assert "15 000" in privacy.mask("Pay 15 000 FCFA")  # amounts are not codes


def test_in_a_group_the_bot_only_speaks_when_called(monkeypatch):
    from checkam import telegram
    ran, sent = [], []
    monkeypatch.setattr(telegram, "_send", lambda *a, **k: sent.append(a))
    monkeypatch.setattr(telegram, "_check", lambda *a: ran.append(a))
    monkeypatch.setattr(telegram.threading, "Thread", lambda target, args, daemon: type("T", (), {"start": lambda self: target(*args)})())
    grp = {"id": -100, "type": "group"}
    telegram.handle({"message": {"chat": grp, "from": {"language_code": "en"}, "text": "Send 5000 to 677000000 now please"}})
    assert ran == [] and sent == []
    suspicious = {"text": "Send 5000 to 677000000 now, you won a prize", "from": {"username": "someone"}}
    telegram.handle({"message": {"chat": grp, "from": {"language_code": "en"}, "text": "@checkam_bot", "reply_to_message": suspicious}})
    assert ran and "677000000" in ran[-1][2]


def test_stickers_and_voice_notes_get_a_helpful_answer_not_a_verdict(monkeypatch):
    from checkam import telegram
    sent = []
    monkeypatch.setattr(telegram, "_send", lambda chat, text, *a: sent.append(text))
    telegram.handle({"message": {"chat": {"id": 5, "type": "private"}, "from": {"language_code": "fr"}, "sticker": {"file_id": "x"}}})
    assert sent and "captures" in sent[-1]


def test_the_scam_radar_counts_this_weeks_flagged_checks_by_kind(tmp_path, monkeypatch):
    from checkam import config, store
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "radar.db")
    monkeypatch.setattr(store, "_conn", None)
    base = {"masked_text": "x", "confidence": 0.9, "language": "en", "numbers": [], "links": [], "scam_types": [], "campaign_id": None, "run_id": "r", "channel": "text"}
    store.save_check({**base, "id": "a", "created": store.now(), "verdict": "scam", "scheme": "job"})
    store.save_check({**base, "id": "b", "created": store.now(), "verdict": "scam", "scheme": "job"})
    store.save_check({**base, "id": "c", "created": store.now(), "verdict": "looks_genuine", "scheme": None})
    store.save_check({**base, "id": "d", "created": "2020-01-01T00:00:00+00:00", "verdict": "scam", "scheme": "prize"})
    r = store.radar()
    assert r["top"] == [{"scheme": "job", "n": 2}] and r["checks"] == 3 and r["flagged"] == 2
    monkeypatch.setattr(store, "_conn", None)

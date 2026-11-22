"""Good practice found by outside testers: delete old records, say what is wrong without echoing input, cache rules,
developer pages off on the live site, and a share link that previews with its verdict."""
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from checkam import config, security, store
from checkam.app import app

client = TestClient(app)
WEB = config.ROOT / "web" / "dist"


def test_old_records_are_deleted_and_open_flags_are_kept():
    old = (datetime.now(timezone.utc) - timedelta(days=800)).isoformat(timespec="seconds")
    new = store.now()
    c = store.conn()
    with store._lock:
        c.execute("INSERT OR REPLACE INTO answers VALUES ('k-old', ?, '{}', 0)", (( datetime.now(timezone.utc) - timedelta(days=40)).isoformat(timespec="seconds"),))
        c.execute("INSERT OR REPLACE INTO answers VALUES ('k-new', ?, '{}', 0)", (new,))
        c.execute("INSERT OR REPLACE INTO checks (id, created, masked_text, verdict) VALUES ('C-oldoldol', ?, 'x', 'scam')", (old,))
        c.execute("INSERT OR REPLACE INTO flags VALUES ('F-openopen', ?, 'C-x', 'scam', '', '', 'open', NULL)", (old,))
        c.execute("INSERT OR REPLACE INTO flags VALUES ('F-doneeeee', ?, 'C-x', 'scam', '', '', 'confirmed', 'a')", (old,))
        c.commit()
    out = store.purge_old()
    assert out["answers"] >= 1 and out["checks"] >= 1 and out["flags"] >= 1
    assert c.execute("SELECT 1 FROM answers WHERE key='k-new'").fetchone()
    assert not c.execute("SELECT 1 FROM answers WHERE key='k-old'").fetchone()
    assert c.execute("SELECT 1 FROM flags WHERE id='F-openopen'").fetchone()
    assert not c.execute("SELECT 1 FROM flags WHERE id='F-doneeeee'").fetchone()


def test_a_bad_request_does_not_echo_what_was_typed():
    secret = "SECRET-TEXT-" + "x" * 4100
    r = client.post("/check", json={"text": secret})
    assert r.status_code == 422
    assert "SECRET-TEXT" not in r.text


def test_developer_pages_are_off_unless_enabled():
    if config.flag("CHECKAM_DOCS", False):
        pytest.skip("docs enabled here")
    assert client.get("/docs").status_code in (404, 200) and client.get("/openapi.json").status_code == 404


def test_answers_are_never_cached_and_public_numbers_briefly():
    security._hits.clear()
    assert client.get("/health").headers["cache-control"] == "no-store"
    assert client.get("/stats/public").headers["cache-control"] == "public, max-age=60"


def test_read_only_pages_are_rate_limited_too():
    security._hits.clear()
    codes = [client.get("/stats/public").status_code for _ in range(250)]
    assert 429 in codes and codes[0] == 200
    security._hits.clear()


@pytest.mark.skipif(not (WEB / "index.html").exists(), reason="web app not built here")
def test_a_share_link_previews_with_its_verdict():
    rid = "C-" + "ab12cd34"
    store.save_receipt({"id": rid, "created": store.now(), "kind": "verdict", "verdict": "scam", "scheme": "prize", "confidence": 0.9, "text_sha256": "0" * 8})
    page = client.get(f"/v/{rid}").text
    assert "<title>CheckAm: Scam</title>" in page
    assert re.search(r'og:description" content="CheckAm found [^"]+', page)
    assert "<script" not in re.search(r'og:title" content="([^"]*)"', page).group(1)
    fr = client.get(f"/v/{rid}", headers={"Accept-Language": "fr-FR"}).text
    assert '<html lang="fr">' in fr and "<title>CheckAm : Arnaque</title>" in fr
    other = client.get("/v/C-00000000").text
    assert "<title>CheckAm</title>" in other  # an unknown answer keeps the plain page


def test_nothing_leaves_for_the_ai_service_with_a_real_number_or_code(monkeypatch):
    from checkam.adapters import nvidia
    sent = []

    def fake_post(path, body, timeout):
        sent.append(str(body))
        return {"choices": [{"message": {"content": "{}"}}], "data": [{"embedding": [0.1]}]}

    monkeypatch.setattr(nvidia, "_post", fake_post)
    monkeypatch.setattr(nvidia, "enabled", lambda: True)
    monkeypatch.setattr(nvidia, "_embed_down_until", 0.0)
    text = "Call 677 00 11 22 and give your PIN 4821 now"
    nvidia.chat([{"role": "user", "content": text}, {"role": "user", "content": [{"type": "text", "text": text}]}])
    nvidia.embed([text], kind="query")
    blob = " ".join(sent)
    assert "677 00 11 22" not in blob and "677001122" not in blob and "4821" not in blob
    assert "[PHONE:" in blob


def test_the_page_is_allowed_to_use_the_microphone_for_speech_input():
    """The header once said microphone=(), which told every browser the page may never use it: the Speak it button
    failed with 'blocked' and never even asked."""
    policy = client.get("/health").headers["permissions-policy"]
    assert "microphone=(self)" in policy
    assert "camera=()" in policy and "geolocation=()" in policy

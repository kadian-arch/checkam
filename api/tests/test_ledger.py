"""Published alerts are signed and chained: edits, forgeries and deletions are all detected."""
from checkam import ledger, store


def publish(title):
    return store.publish_alert({"campaign_id": "cmp_x", "title": title, "body_en": "Never send money to 6XX.", "body_fr": "N'envoyez jamais d'argent.",
                                "numbers": ["654-jwmukg"], "published_by": "analyst@example.org", "run_id": "r1", "contract_id": "c1"})


def test_published_alert_verifies():
    a = publish("Fake refund calls")
    assert ledger.verify({k: a[k] for k in store.PUBLIC_ALERT_FIELDS})["valid"]


def test_edited_alert_is_caught():
    a = {k: v for k, v in publish("Fake MTN promo").items() if k in store.PUBLIC_ALERT_FIELDS}
    a["body_en"] = "Send money to 677 00 00 00, it is safe."
    assert not ledger.verify(a)["valid"]


def test_forged_signature_is_caught():
    a = {k: v for k, v in publish("Fake job").items() if k in store.PUBLIC_ALERT_FIELDS}
    a["signature"] = a["signature"][:-4] + "AAAA"
    assert not ledger.verify(a)["valid"]


def test_chain_detects_a_deleted_alert():
    for t in ("one", "two", "three"):
        publish(t)
    chain = store.alerts(1000, oldest_first=True)
    assert ledger.verify_chain(chain)["valid"]
    del chain[1]
    assert not ledger.verify_chain(chain)["valid"]


def test_public_feed_hides_who_published():
    publish("privacy")
    assert all("published_by" not in a for a in store.alerts())


def test_a_checkam_answer_can_be_verified_and_a_faked_one_cannot():
    from fastapi.testclient import TestClient
    from checkam import agents, ledger, store
    from checkam.app import app
    msg = "Your MTN account is blocked. Send the code you received to 677 00 11 22 to unlock it"
    card = agents.run_check(msg)
    rid = card["receipt"]["id"]
    assert card["receipt"]["url"].endswith(f"/v/{rid}")
    c = TestClient(app)
    got = c.get(f"/receipts/{rid}").json()
    assert got["valid"] and got["receipt"]["verdict"] == card["verdict"]
    assert "text" not in got["receipt"] and "677" not in str(got)  # the message itself is never shown
    assert c.post(f"/receipts/{rid}/match", json={"text": msg.upper()}).json()["same_message"]
    assert not c.post(f"/receipts/{rid}/match", json={"text": "a different message"}).json()["same_message"]
    forged = {**store.get_receipt(rid), "verdict": "looks_genuine"}  # someone edits the verdict
    assert not ledger.verify_receipt(forged)["valid"]
    assert c.get("/receipts/C-00000000").status_code == 404
    assert "MODEL_API_KEY" not in c.get("/receipts/..%2f..%2f.env").text


def test_an_unsigned_alert_never_counts_and_never_hides_the_signed_chain():
    from checkam import ledger
    a1 = ledger.seal({"id": "A1", "created": "2026-10-25", "title": "t", "body_en": "b", "numbers": [], "campaign_id": "c"}, None)
    planted = {"id": "X", "created": "2026-10-25", "title": "fake", "body_en": "pay here", "numbers": []}  # slipped in by hand
    r = ledger.verify_chain([planted, a1])
    assert r["valid"] and r["length"] == 1 and r["unsigned"] == ["X"]

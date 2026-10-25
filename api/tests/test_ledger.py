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

import os

import pytest

from checkam import pgcompat


def test_insert_or_replace_becomes_an_upsert_on_the_primary_key():
    sql, params = pgcompat.translate("INSERT OR REPLACE INTO settings VALUES (?,?)", ("k", "v"))
    assert sql == 'INSERT INTO settings ("key", "value") VALUES (%s,%s) ON CONFLICT ("key") DO UPDATE SET "value" = EXCLUDED."value"'
    assert params == ("k", "v")


def test_named_parameters_and_listed_columns_are_kept():
    sql, params = pgcompat.translate(
        "INSERT OR REPLACE INTO checks (id, created, masked_text) VALUES (:id,:created,:masked_text)", {"id": "C-1", "created": "x", "masked_text": "y"})
    assert "VALUES (%(id)s,%(created)s,%(masked_text)s)" in sql and 'ON CONFLICT ("id") DO UPDATE SET "created" = EXCLUDED."created"' in sql
    assert params["id"] == "C-1"


def test_a_keyword_column_is_quoted_and_a_table_without_other_columns_does_nothing_on_conflict():
    sql, _ = pgcompat.translate("INSERT OR REPLACE INTO alert_hidden VALUES (?,?,?,?)", ("a", "r", "t", "who"))
    assert '"by"' in sql and "DO UPDATE SET" in sql


def test_percent_signs_are_escaped_only_when_parameters_are_used():
    sql, params = pgcompat.translate("SELECT 1 FROM checks WHERE masked_text LIKE '%x%' AND id = ?", ("C-1",))
    assert "'%%x%%'" in sql and sql.endswith("id = %s") and params == ("C-1",)
    sql, params = pgcompat.translate("UPDATE checks SET operator = 'x' WHERE masked_text LIKE '%orange%'", ())
    assert "'%orange%'" in sql and params is None


def test_double_colon_casts_are_not_mistaken_for_named_parameters():
    sql, _ = pgcompat.translate("SELECT :a::text", {"a": 1})
    assert sql == "SELECT %(a)s::text"


def test_rows_can_be_read_by_name_and_by_position():
    r = pgcompat.Row(a=1, b="x")
    assert r["a"] == 1 and r[1] == "x" and dict(r) == {"a": 1, "b": "x"}


URL = os.environ.get("CHECKAM_TEST_PG_URL", "")


@pytest.mark.skipif(not URL, reason="set CHECKAM_TEST_PG_URL to a PostgreSQL address to run the store against PostgreSQL")
def test_the_store_works_against_a_real_postgresql_database(monkeypatch):
    from checkam import config, store
    monkeypatch.setattr(config, "DATABASE_URL", URL)
    monkeypatch.setattr(store, "_conn", None)
    c = store.conn()
    for t in ("checks", "receipts", "answers", "flags", "alerts", "settings", "monthly_stats", "alert_i18n", "alert_hidden", "admin_2fa", "admin_audit", "analysts"):
        c.execute(f"DELETE FROM {t}")
    store.save_check({"id": "C-aaaaaaaa", "created": store.now(), "masked_text": "send back to [PHONE]", "verdict": "scam", "confidence": 0.9, "language": "en",
                      "numbers": ["x"], "links": [], "scam_types": [], "campaign_id": None, "run_id": "r", "channel": "text", "operator": "mtn", "amount_fcfa": 5000, "scheme": "reversal"})
    store.save_check({"id": "C-aaaaaaaa", "created": store.now(), "masked_text": "again", "verdict": "scam", "confidence": 0.9, "language": "en",
                      "numbers": [], "links": [], "scam_types": [], "campaign_id": None, "run_id": "r", "channel": "text", "operator": "mtn", "amount_fcfa": 5000, "scheme": "reversal"})
    assert store.get_check("C-aaaaaaaa")["masked_text"] == "again"            # the second save replaced the first
    assert store.analytics()["kept_fcfa"] == 5000 and store.radar()["flagged"] == 1
    store.add_analyst("a@b.cm", "pw-long-enough", "A", "Org")
    assert store.verify_analyst("a@b.cm", "pw-long-enough")["name"] == "A"
    flag = store.add_flag("C-aaaaaaaa", "looks_genuine", "wrong")
    assert store.open_flags()[0]["id"] == flag["id"]
    alert = store.publish_alert({"published_by": "a@b.cm", "campaign_id": None, "title": "t", "body_en": "b", "body_fr": "c", "numbers": [], "run_id": "r", "contract_id": "k"})
    assert store.alerts(5)[0]["id"] == alert["id"]
    store.add_monthly([{"created": "2026-11-01", "scheme": "x", "verdict": "scam"}] * 2)
    assert store.check_stats()["total"] >= 3
    store.set_setting("alert_show_days", "30")
    assert store.settings()["alert_show_days"] == 30
    store.cache_put("k1", {"verdict": "scam"})
    assert store.cache_get("k1")["cached"] == 1 and store.counts()["checks"] == 1

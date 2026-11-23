from checkam import telegram


def test_card_renders_in_the_message_language_and_escapes_html():
    card = {"verdict": "scam", "confidence": 0.93, "language": "fr", "headline": "Arnaque <b>connue</b>",
            "why": [{"text": "Le numéro 677 est signalé 4 fois"}], "do_now": ["Composez *126#"], "dont": ["Ne donnez jamais votre code"]}
    out = telegram.render(card, "en")
    assert out.startswith("<b>🔴 ARNAQUE</b>") and "&lt;b&gt;connue&lt;/b&gt;" in out and "Pourquoi" in out


def test_chat_is_rate_limited_and_start_needs_no_check(monkeypatch):
    sent, ran = [], []
    monkeypatch.setattr(telegram, "_send", lambda chat, text: sent.append(text))
    monkeypatch.setattr(telegram, "_check", lambda *a: ran.append(a))
    monkeypatch.setattr(telegram.threading, "Thread", lambda target, args, daemon: type("T", (), {"start": lambda self: target(*args)})())
    telegram.handle({"message": {"chat": {"id": 991}, "from": {"language_code": "en"}, "text": "/start"}})
    assert ran == [] and "Forward me" in sent[-1]
    for _ in range(12):
        telegram.handle({"message": {"chat": {"id": 991}, "from": {"language_code": "en"}, "text": "Send 5000 to 677000000"}})
    assert len(ran) == 8 and "Too many checks" in sent[-1]


def test_webhook_is_closed_without_the_secret():
    from fastapi.testclient import TestClient
    from checkam.app import app
    r = TestClient(app).post("/telegram/guess", json={"message": {"chat": {"id": 1}, "text": "hi"}})
    assert r.status_code == 404


def test_talk_is_answered_and_received_messages_are_checked():
    assert not telegram.wants_check({}, "How are you?")
    assert not telegram.wants_check({}, "Really?")
    assert telegram.wants_check({}, "Send 5000 to 677000000 now")
    assert telegram.wants_check({"forward_origin": {"type": "user"}}, "hello")  # forwarded: always checked
    assert telegram.wants_check({"photo": [{"file_id": "x"}]}, "")


def test_short_reply_after_who_sent_it_rechecks_with_that_sender(monkeypatch):
    ran = []
    monkeypatch.setattr(telegram, "_send", lambda *a, **k: None)
    monkeypatch.setattr(telegram, "_check", lambda *a: ran.append(a))
    monkeypatch.setattr(telegram.threading, "Thread", lambda target, args, daemon: type("T", (), {"start": lambda self: target(*args)})())
    telegram._pending[77] = (telegram.time.monotonic(), "You have received 30 000 FCFA, transaction 123", "")
    telegram.handle({"message": {"chat": {"id": 77}, "from": {"language_code": "en"}, "text": "MobileMoney"}})
    assert ran and ran[-1][2].startswith("You have received") and ran[-1][4] == "MobileMoney"
    # a longer answer is what the person adds, checked together with the message
    telegram._pending[77] = (telegram.time.monotonic(), "You have received 30 000 FCFA, transaction 123", "")
    telegram.handle({"message": {"chat": {"id": 77}, "from": {"language_code": "en"}, "text": "Then a man called asking me to send it back to him"}})
    assert "send it back" in ran[-1][2] and ran[-1][2].startswith("You have received") and ran[-1][4] == ""


def test_the_bot_speaks_plainly_like_the_website():
    for lang in ("en", "fr"):
        def words(x):  # what a person reads: the values, never the internal keys
            return " ".join(words(v) for v in x.values()) if isinstance(x, dict) else str(x)
        blob = words(telegram.TEXT[lang]).lower()
        assert "agent" not in blob and "critic" not in blob and "critique" not in blob


def test_the_answer_offers_what_you_already_did_and_whether_it_was_right():
    card = {"verdict": "scam", "check_id": "C-1a2b3c4d", "language": "en", "headline": "x", "receipt": {"url": "https://checkam.me/v/C-1a2b3c4d"}}
    data = [b.get("callback_data") for row in telegram.buttons(card, "en") for b in row if b.get("callback_data")]
    assert "a:money:C-1a2b3c4d" in data and "a:code:C-1a2b3c4d" in data and "f:wrong:C-1a2b3c4d" in data
    genuine = telegram.buttons({**card, "verdict": "looks_genuine"}, "en")
    assert not any((b.get("callback_data") or "").startswith("a:") for row in genuine for b in row)


def test_pressing_i_paid_answers_with_the_steps_for_that_situation(monkeypatch):
    from checkam import store
    store.save_check({"id": "C-ca11ba01", "created": store.now(), "masked_text": "x", "verdict": "scam", "confidence": 0.9, "language": "en", "numbers": [], "links": [],
                      "scam_types": [], "campaign_id": None, "run_id": "r", "channel": "text", "operator": "mtn", "amount_fcfa": None, "scheme": "prize"})
    sent, called = [], []
    monkeypatch.setattr(telegram, "_send", lambda chat, text, *a, **k: sent.append(text))
    monkeypatch.setattr(telegram, "_call", lambda method, **kw: called.append((method, kw)) or {})
    telegram.handle({"callback_query": {"id": "cb1", "from": {"language_code": "en"}, "message": {"chat": {"id": 4242}}, "data": "a:money:C-ca11ba01"}})
    assert sent and "sent money" in sent[-1] and "within the hour" in sent[-1] and "650 52 87 87" in sent[-1]
    assert ("answerCallbackQuery", {"callback_query_id": "cb1"}) in called


def test_pressing_wrong_sends_the_answer_to_the_review_queue_and_junk_is_ignored(monkeypatch):
    from checkam import store
    store.save_check({"id": "C-ca11ba02", "created": store.now(), "masked_text": "x", "verdict": "scam", "confidence": 0.9, "language": "fr", "numbers": [], "links": [],
                      "scam_types": [], "campaign_id": None, "run_id": "r", "channel": "text", "operator": "other", "amount_fcfa": None, "scheme": None})
    monkeypatch.setattr(telegram, "_send", lambda *a, **k: None)
    monkeypatch.setattr(telegram, "_call", lambda *a, **k: {})
    telegram.handle({"callback_query": {"id": "cb2", "from": {"language_code": "fr"}, "message": {"chat": {"id": 4243}}, "data": "f:wrong:C-ca11ba02"}})
    assert any(f["check_id"] == "C-ca11ba02" for f in store.open_flags(200))
    telegram.handle({"callback_query": {"id": "cb3", "from": {}, "message": {"chat": {"id": 4244}}, "data": "a:money:not-an-id"}})  # no crash
    telegram.handle({"callback_query": {"id": "cb4", "from": {}, "message": {"chat": {"id": 4245}}, "data": "a:money:C-00000000"}})  # unknown check

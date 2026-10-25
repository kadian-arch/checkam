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
    telegram._pending[77] = (telegram.time.monotonic(), "You have received 30 000 FCFA, transaction 123")
    telegram.handle({"message": {"chat": {"id": 77}, "from": {"language_code": "en"}, "text": "MobileMoney"}})
    assert ran and ran[-1][2].startswith("You have received") and ran[-1][4] == "MobileMoney"

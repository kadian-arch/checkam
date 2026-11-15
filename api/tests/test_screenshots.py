import base64

from checkam import agents, telegram
from checkam.trace import Trace

PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 32


def shot(tag: str) -> tuple[str, str]:
    return base64.b64encode(tag.encode()).decode(), "image/png"


def fake_reader(monkeypatch):
    # stands in for the vision model: "reads" back the tag each fake screenshot carries
    monkeypatch.setattr(agents.nvidia, "read_image", lambda b64, mime, trace=None: base64.b64decode(b64).decode())


def test_several_screenshots_are_read_in_order_as_one_conversation(monkeypatch):
    fake_reader(monkeypatch)
    facts = agents.intake("", Trace(echo=False), images=[shot("Hello, I sent you 50000 by mistake"), shot("Send it back to 677123456 now")])
    text = facts["text"]
    assert text.index("by mistake") < text.index("Send it back")


def test_one_screenshot_still_works_the_old_way(monkeypatch):
    fake_reader(monkeypatch)
    assert "by mistake" in agents.intake("", Trace(echo=False), image=shot("I sent you money by mistake"))["text"]


def test_no_more_than_the_limit_is_read(monkeypatch):
    read = []
    monkeypatch.setattr(agents.nvidia, "read_image", lambda b64, mime, trace=None: read.append(b64) or "x")
    agents.intake("", Trace(echo=False), images=[shot(str(i)) for i in range(agents.MAX_SHOTS + 3)])
    assert len(read) == agents.MAX_SHOTS


def test_api_takes_several_images_and_refuses_too_many(monkeypatch):
    from fastapi.testclient import TestClient
    from checkam.app import app
    got = {}
    monkeypatch.setattr(agents, "run_check", lambda text, **k: got.update(k) or {"ok": True})
    c = TestClient(app)
    two = c.post("/check/image", files=[("image", ("a.png", PNG, "image/png")), ("image", ("b.png", PNG, "image/png"))])
    assert two.status_code == 200 and len(got["images"]) == 2
    one = c.post("/check/image", files={"image": ("a.png", PNG, "image/png")})
    assert one.status_code == 200 and len(got["images"]) == 1
    many = c.post("/check/image", files=[("image", (f"{i}.png", PNG, "image/png")) for i in range(agents.MAX_SHOTS + 1)])
    assert many.status_code == 413


def test_a_telegram_album_is_one_check_with_every_photo_in_order(monkeypatch):
    ran = []
    monkeypatch.setattr(telegram, "_send", lambda *a, **k: None)
    monkeypatch.setattr(telegram, "_check", lambda *a: ran.append(a))
    monkeypatch.setattr(telegram.threading, "Timer", lambda wait, fn, args: type("T", (), {"start": lambda self: None})())
    base = {"chat": {"id": 4242}, "from": {"language_code": "en"}, "media_group_id": "g1"}
    # Telegram may deliver the photos out of order
    telegram.handle({"message": {**base, "message_id": 12, "photo": [{"file_id": "second"}]}})
    telegram.handle({"message": {**base, "message_id": 11, "photo": [{"file_id": "first"}], "caption": "is this real?"}})
    assert ran == []  # still gathering
    telegram._album_done((4242, "g1"), "en")
    assert ran == [(4242, "en", "is this real?", ["first", "second"])]

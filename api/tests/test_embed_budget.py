"""One slow embedding call must never hold up a person's check: on the live site it once took 92 seconds."""
import time

from checkam.adapters import nvidia


def test_a_failed_query_embedding_is_skipped_for_a_minute(monkeypatch):
    calls = []

    def fake_post(path, body, timeout):
        calls.append(timeout)
        raise TimeoutError("slow")

    monkeypatch.setattr(nvidia, "_post", fake_post)
    monkeypatch.setattr(nvidia, "enabled", lambda: True)
    monkeypatch.setattr(nvidia, "_embed_down_until", 0.0)
    assert nvidia.embed(["a message"], kind="query") is None
    assert calls == [8]  # the person's own message gets a short budget
    assert nvidia.embed(["another"], kind="query") is None
    assert calls == [8]  # and the second check does not wait at all
    assert nvidia._embed_down_until > time.monotonic()


def test_corpus_embeddings_keep_the_long_budget(monkeypatch):
    seen = []
    monkeypatch.setattr(nvidia, "_post", lambda path, body, timeout: seen.append(timeout) or {"data": [{"embedding": [0.1]}]})
    monkeypatch.setattr(nvidia, "enabled", lambda: True)
    monkeypatch.setattr(nvidia, "_embed_down_until", 0.0)
    assert nvidia.embed(["a"]) == [[0.1]]
    assert seen == [90]

from checkam import kv, security, store


class Fake:
    def __init__(self):
        self.d, self.ttl = {}, {}

    def get(self, k): return self.d.get(k)
    def set(self, k, v, ex=None): self.d[k] = str(v); self.ttl[k] = ex
    def incr(self, k): self.d[k] = str(int(self.d.get(k, 0)) + 1); return int(self.d[k])
    def expire(self, k, s): self.ttl[k] = s
    def scan_iter(self, match=None, count=0): return [k for k in list(self.d) if k.startswith(match.rstrip("*"))]
    def delete(self, k): self.d.pop(k, None)


class Broken(Fake):
    def get(self, k): raise ConnectionError("down")
    def set(self, *a, **k): raise ConnectionError("down")
    def incr(self, k): raise ConnectionError("down")


def use(monkeypatch, fake):
    monkeypatch.setattr(kv, "_client", fake)
    monkeypatch.setattr(kv, "_down_until", 0.0)


def test_without_redis_nothing_changes(monkeypatch):
    monkeypatch.setattr(kv, "_client", None)
    monkeypatch.setattr(kv, "_make", lambda: None)
    assert not kv.enabled() and kv.get("x") is None and kv.incr("x", 5) is None
    ok, _ = security.allowed("10.9.9.9", "default")
    assert ok


def test_repeat_answers_are_shared_through_redis(monkeypatch):
    fake = Fake()
    use(monkeypatch, fake)
    key = store.cache_key("send 5000 to 677000001", "", "en")
    store.cache_put(key, {"verdict": "scam", "headline": "x"})
    assert "ans:" + key in fake.d
    first, second = store.cache_get(key), store.cache_get(key)
    assert first["verdict"] == "scam" and first["cached"] == 1 and second["cached"] == 2
    store.cache_clear()
    assert not any(k.startswith("ans:") for k in fake.d)


def test_rate_limits_are_counted_in_redis(monkeypatch):
    fake = Fake()
    use(monkeypatch, fake)
    group = next(g for g in security.LIMITS if len(security.LIMITS[g]) >= 1)
    n, window = security.LIMITS[group][0]
    results = [security.allowed("10.7.7.7", group)[0] for _ in range(n + 2)]
    assert results[:n] == [True] * n and results[n] is False
    assert any(k.startswith(f"rl:{group}:10.7.7.7") for k in fake.d)


def test_a_broken_redis_falls_back_to_local_state_and_stops_asking(monkeypatch):
    use(monkeypatch, Broken())
    key = store.cache_key("another text 6770000", "", "en")
    store.cache_put(key, {"verdict": "scam"})          # local database still stores it
    assert store.cache_get(key)["verdict"] == "scam"   # and serves it
    assert security.allowed("10.8.8.8", "default")[0]
    assert not kv.enabled()                            # backed off for 30 seconds

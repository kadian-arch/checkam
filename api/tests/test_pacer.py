import time

from checkam.adapters.nvidia import Pacer


def test_calls_wait_their_turn_instead_of_bursting():
    p = Pacer("k", rpm=600)  # one call every 0.1 s
    t0 = time.monotonic()
    for _ in range(4):
        assert p.wait(time.monotonic() + 10)
    assert time.monotonic() - t0 >= 0.29


def test_a_refusal_slows_the_pace_and_a_full_budget_gives_up_early():
    p = Pacer("k", rpm=60)
    p.refused(retry_after=0.2)
    assert p.gap == 2.0
    assert p.wait(time.monotonic() + 10)
    assert not p.wait(time.monotonic() + 1)  # next turn is 2 s away, past the budget


def test_a_refused_key_is_benched_and_the_retry_goes_to_another_key_at_once():
    import httpx
    from checkam.adapters import nvidia
    used = []

    class Fake:
        def post(self, url, json, timeout, headers):
            key = headers["Authorization"].split()[-1]
            used.append(key)
            req = httpx.Request("POST", url)
            if key == "busy":
                return httpx.Response(429, request=req)
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]}, request=req)

    old_p, old_c = nvidia._pacers, nvidia._client
    nvidia._pacers, nvidia._client = [Pacer("busy", rpm=600), Pacer("free", rpm=600)], Fake()
    try:
        nvidia._pacers[1].next = time.monotonic() + 0.05  # the busy key looks free first
        t0 = time.monotonic()
        assert nvidia._post("/chat/completions", {}, timeout=10)["choices"]
        assert used[:2] == ["busy", "free"] and time.monotonic() - t0 < 1.5
        assert nvidia._pacers[0].next > time.monotonic() + 3  # benched for its cooldown
    finally:
        nvidia._pacers, nvidia._client = old_p, old_c

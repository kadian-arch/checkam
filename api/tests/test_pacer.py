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
    p.refused()
    assert p.gap == 2.0
    assert p.wait(time.monotonic() + 10)
    assert not p.wait(time.monotonic() + 1)  # next turn is 2 s away, past the budget

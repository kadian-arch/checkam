"""The advice changes with what the person has already done, and names only official channels."""
import pytest

from checkam import advice


@pytest.mark.parametrize("acted", ["money", "code", "clicked", "documents", "installed"])
@pytest.mark.parametrize("lang", ["en", "fr"])
def test_every_situation_has_steps_in_both_languages(acted, lang):
    steps = advice.after_action(acted, [], lang)
    assert steps and all(advice.vetted(s) or "*126#" in s for s in steps)


def test_nothing_done_adds_nothing():
    assert advice.after_action("nothing", ["mtn"], "en") == []


def test_money_sent_puts_the_operators_own_line_in():
    steps = advice.after_action("money", ["mtn"], "en")
    assert any("650 52 87 87" in s for s in steps)
    assert not any("650 52 87 87" in s for s in advice.after_action("money", ["orange"], "en"))


@pytest.mark.parametrize("line", ["Call 677123456 and they will help", "Dial *555# now", "Go to www.recover-funds.com", "You will get your money back, guaranteed"])
def test_a_model_written_step_with_an_invented_number_site_or_promise_is_dropped(line):
    assert not advice.vetted(line)


def test_a_plain_model_step_is_kept():
    assert advice.vetted("Tell a family member today so you are not alone with this.")

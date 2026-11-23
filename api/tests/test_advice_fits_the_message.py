"""Advice follows what a message DOES, whatever name the scam has. Found by a tester who sent scams outside the 18 named kinds
to the live site: a land sale got "pay on delivery", a wallet-draining airdrop never said "never share your seed phrase",
and an ordinary friend message was told "do not call the number"."""
import pytest

from checkam import advice, agents

AIRDROP = ("Congrats! You are eligible for the $CAMCOIN airdrop. Connect your wallet at camcoin-airdrop-claim.xyz and "
           "enter your seed phrase to verify ownership.")
BOX = ("Hello dear. I am a retired customs officer. I found a sealed box registered in your name at the airport. "
       "Buy two 5000 FCFA Orange recharge cards and read me the numbers. Keep our contact secret.")
LAND = "Bonsoir, je vends un terrain de 500m2 a Buea Molyko. Versez 500 000 FCFA d'avance par Mobile Money pour bloquer le terrain."
DOOR = "A man says he is the ENEO meter inspector at your door and wants 15000 FCFA cash to avoid disconnection."
BOSS = "Mr Kum it is the director, I am in a meeting. Transfer 450000 FCFA urgently for a supplier. Do not tell anyone in accounts."
SEED = "Man of God Prophet Elijah says: sow a seed of 10000 FCFA on MoMo today and God will deliver you from your debts this week."
FIBRE = "CAMTEL fibre installation: pay 25000 FCFA installation fee to 677 00 11 22 to be connected this week."
LEASE = "MTN wants to rent your land for a tower. Pay 50000 FCFA lease registration first by MoMo."


def card(text, verdict="scam", scheme=None, asks=(), lang="en"):
    do, dont = advice.steps(verdict, scheme, {"brands": ["mtn"], "asks": list(asks), "links": [], "text": text}, lang)
    return " ".join(do), " ".join(dont)


@pytest.mark.parametrize("text,needle", [
    (AIRDROP, "seed phrase"), (BOX, "recharge"), (BOX, "secret"), (LAND, "land title"), (DOOR, "ID"),
    (BOSS, "second person"), (SEED, "blessing"), (FIBRE, "installation"), (LEASE, "rent your land"),
])
def test_what_the_message_does_decides_the_advice(text, needle):
    do, dont = card(text, scheme="advance_fee")
    assert needle.lower() in (do + " " + dont).lower(), (needle, do, dont)


def test_the_french_card_says_the_same_things_in_french():
    do, dont = card(AIRDROP.replace("enter your seed phrase", "tapez votre phrase secrete"), lang="fr")
    assert "phrase secrète" in dont


@pytest.mark.parametrize("text,scheme", [(LAND, "seller"), (BOX, "seller"), (SEED, "charity"), (AIRDROP, "investment"), (BOSS, "family")])
def test_a_kind_the_message_does_not_show_gets_none_of_its_advice(text, scheme):
    do, dont = card(text, scheme=scheme)
    blob = (do + " " + dont).lower()
    assert "on delivery" not in blob
    assert "organisation you can visit" not in blob and "real investments never promise" not in blob
    assert "call your relative" not in blob


def test_with_no_supported_kind_the_card_gives_the_step_true_for_every_scam():
    do, _ = card("Something nobody has seen before asks you to act today", scheme="seller")
    assert "do not act on it yet" in do.lower()


def test_the_operators_balance_line_is_only_for_money_that_may_have_moved():
    for text, scheme in ((LAND, "seller"), (SEED, "charity"), (AIRDROP, "investment")):
        assert "*126#" not in card(text, scheme=scheme)[0]
    rev = "Je vous ai envoye 25 000 FCFA par erreur sur votre compte Mobile Money, renvoyez-les"
    assert "*126#" in card(rev, scheme="reversal", asks=["send_money"], lang="fr")[0]


def test_a_message_that_asks_for_a_secret_is_asking_for_the_one_thing_nobody_gives():
    assert agents.SECRET_ASK.search(AIRDROP) and agents.SECRET_ASK.search(BOX)
    assert not agents.SECRET_ASK.search("Your recharge of 500 U was successful. Balance 1,200 U.")
    assert not agents.SECRET_ASK.search("Buy a recharge card at any MTN shop and keep your receipt.")


@pytest.mark.parametrize("text", [AIRDROP, BOX])
def test_asking_for_a_seed_phrase_or_a_card_number_is_a_scam_not_a_soft_warning(text):
    assert agents.run_check(text, sender="6 70 00 00 00", persist=False, echo=False)["verdict"] == "scam"


def test_an_ordinary_friend_message_is_not_told_to_ignore_the_friend():
    text = "Hey Kum, are you free this Saturday afternoon? I will be around Molyko, let us meet at the usual place near the junction around 3pm. Call me when you reach."
    k = agents.run_check(text, sender="+237677000123", persist=False, echo=False)
    blob = " ".join(k["do_now"] + k["dont"]).lower()
    assert k["verdict"] not in ("scam", "suspicious") or "do not call" not in blob
    assert k["verdict"] != "scam"

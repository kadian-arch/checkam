"""Every scam type in the Stop Arnaque 237 taxonomy has a plain name and advice of its own, in both languages."""
import json
from pathlib import Path

import pytest

from checkam import advice

# taxonomy code -> the scheme the person is told about
TAXONOMY = {
    "wrong_number_reversal": "reversal", "deposit_withdrawal_trap": "reversal", "fake_prize_promo": "prize",
    "account_blocked": "credential", "fake_agent_support": "credential", "credential_request": "credential", "sim_swap": "credential",
    "family_emergency": "family", "hacked_account_money": "family", "fake_job": "job", "fake_scholarship_visa": "visa_scholarship",
    "fake_concours_admission": "exam", "investment_ponzi_crypto": "investment", "loan_scam": "loan", "fake_seller_delivery": "seller",
    "official_impersonation": "official", "romance": "romance", "threat_extortion": "extortion", "fake_social_profile": "fake_page",
    "fake_document": "fake_page", "phishing_link": "phishing", "advance_fee": "advance_fee",
}

MESSAGES = [
    ("Concours ENAM 2026: je peux pousser votre dossier, la liste d'admission sort demain", "exam"),
    ("My love, I am stuck at the airport. I want to marry you, please send 80000", "romance"),
    ("We have your intimate photos. Pay 100000 or we will publish them to your contacts", "extortion"),
    ("Ici le commissariat central. Vous avez une convocation, payez l'amende de 25000 par MoMo", "official"),
    ("Your inheritance of 4 500 000 is ready. Pay the clearance fee to release the funds", "advance_fee"),
    ("Your Facebook will be closed. Verify your account and sign in here: http://fb-secure.example", "phishing"),
    ("This is a fake page of the minister, a fake profile asking people to pay", "fake_page"),
]


@pytest.mark.parametrize("code,scheme", TAXONOMY.items())
def test_every_taxonomy_code_names_a_scheme(code, scheme):
    assert advice.scheme_of("", [], code) == scheme


@pytest.mark.parametrize("text,scheme", MESSAGES)
def test_the_newer_scam_types_are_named_from_the_message_itself(text, scheme):
    assert advice.scheme_of(text, [], "") == scheme


@pytest.mark.parametrize("scheme", sorted(advice.SCHEMES))
def test_every_scheme_has_a_label_and_a_warning_in_both_languages(scheme):
    for lang in ("en", "fr"):
        assert advice.label(scheme, lang)
        do, dont = advice.steps("scam", scheme, {"brands": [], "asks": [], "links": []}, lang)
        assert do and dont and len(do) <= 3 and len(dont) <= 3
    en = advice.steps("scam", scheme, {"brands": [], "asks": [], "links": []}, "en")
    fr = advice.steps("scam", scheme, {"brands": [], "asks": [], "links": []}, "fr")
    assert en != fr


def test_the_web_app_can_name_every_scheme():
    i18n = Path(__file__).resolve().parents[2] / "web" / "src" / "i18n"
    for lang in ("en", "fr"):
        known = json.loads((i18n / f"{lang}.json").read_text(encoding="utf-8"))["schemes"]
        assert set(advice.SCHEMES) <= set(known), f"{lang}.json is missing {set(advice.SCHEMES) - set(known)}"


def test_wider_names_do_not_change_what_counts_as_an_announcement():
    assert advice.announcement("Recrutement massif: 300 postes, payez les frais de dossier")
    assert advice.announcement("Concours ENAM: inscrivez-vous par ce lien WhatsApp")
    assert advice.announcement("Bourse d'études au Canada, visa garanti")
    assert not advice.announcement("Vous avez gagné un cadeau, félicitations")
    assert not advice.announcement("Mama I had an accident, send 20000 now")

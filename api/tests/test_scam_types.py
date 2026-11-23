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


def test_a_prize_lottery_is_a_prize_and_only_the_visa_lottery_is_a_visa_offer():
    """A live test once called an Orange lottery message 'a fake visa or scholarship offer' and gave recruitment advice,
    because the bare word lottery sat in the visa list."""
    from checkam import advice
    for text in ("Bonjour, vous avez gagne 750000 FCFA a la loterie Orange. Envoyez votre code PIN pour recevoir le gain.",
                 "You won the MTN lottery jackpot of 500000 FCFA, send 5000 for fees",
                 "Tombola Camtel: felicitations, vous avez gagne un telephone"):
        assert advice.scheme_of(text, [], "") == "prize", text
    for text in ("DV lottery green card 2027: pay 50000 FCFA to register your file",
                 "Inscription a la loterie du visa americain, frais de dossier 30000 FCFA",
                 "Bourse d'etudes a l'etranger: payez les frais de dossier"):
        assert advice.scheme_of(text, [], "") == "visa_scholarship", text


# what each red-team scam really is, read by a person: the card's wording and advice follow this label
RED_TEAM_KINDS = {"job2": "job", "job4": "job", "romance1": "romance", "romance2": "romance", "romance3": "extortion", "romance4": "romance",
                  "relative3": "family", "exam3": "exam", "sim3": "credential", "float1": "reversal"}


def test_the_kind_of_scam_named_on_the_card_matches_what_the_scam_is():
    import json
    from pathlib import Path
    from checkam import advice
    rows = {c["kind"].removeprefix("redteam_"): c for c in json.loads((Path(__file__).resolve().parents[2] / "evals" / "redteam_scams.json").read_text(encoding="utf-8"))}
    wrong = {k: advice.scheme_of(rows[k]["text"], [], "") for k, want in RED_TEAM_KINDS.items() if advice.scheme_of(rows[k]["text"], [], "") != want}
    assert not wrong, wrong


def test_every_kind_of_scam_has_advice_a_model_guide_entry_and_a_name_in_both_languages():
    """A kind added in one place and missed in another shows up as a raw key on the radar or as no advice at all."""
    import json
    from pathlib import Path
    from checkam import advice
    keys = set(advice.SCHEMES)
    assert keys == set(advice.SCHEME_GUIDE) and keys <= set(advice.LINES)
    web = Path(__file__).resolve().parents[2] / "web" / "src" / "i18n"
    for lang in ("en", "fr"):
        names = json.loads((web / f"{lang}.json").read_text(encoding="utf-8"))["schemes"]
        assert keys <= set(names), (lang, keys - set(names))


def test_the_model_pick_decides_a_tie_and_the_words_still_outvote_a_wrong_pick():
    from checkam import advice
    tie = "Votre colis est bloque, payez les frais de stockage"
    assert advice.scheme_of(tie, [], "seller") == "seller"
    # a pick the text clearly contradicts does not win against three matching words of another kind
    text = "Shortlisted for the position, interview slot, pay the medical test and uniform"
    assert advice.scheme_of(text, [], "prize") == "job"
    assert advice.scheme_of("Hello", [], "seller") == "seller", "with nothing else to go on the pick stands"

"""Investment and referral platforms are recognised by what they describe, in any wording, not by one message."""
import json
from pathlib import Path

import pytest

from checkam import agents

PYRAMIDS = [
    "Nouvelle plateforme LIONCASH. Bonus d'inscription: 500. Depot minimum: 2000. Retrait minimum: 800. Frais 5%",
    "Join NOVAX now! Welcome bonus 1000F. Minimum deposit 3000F, minimum withdrawal 1000F. Earn 4% daily.",
    "Gagnez 3% par jour avec notre plateforme. Parrainage: Niveau 1: 30%\nNiveau 2: 5%\nNiveau 3: 2%",
    "Referral commission\nLevel 1: 25%\nLevel 2: 4%\nLevel 3: 1%\nSign-up bonus 700F",
]
HONEST = [
    "You have withdrawn 1000 XAF from your mobile money account. Fee was 0 XAF. New balance 7791 XAF.",
    "Good news! Instant referral payments are back. Earn 200F automatically for every successful referral. Reach 15 referrals and get an extra 5,000F bonus!",
    "Cash in of 500 XAF has been completed. Added commission: .",
    "Votre recharge est de 500.0 U. Solde: 550.0 U.",
    "You have received an advance of 50XAF from MMC to repay with Access Fee:1XAF  Fee:0.5% daily,Max Fee:18.5% Transact ID:[TXN_ID]. Your transaction is pending",
]


@pytest.mark.parametrize("text", PYRAMIDS)
def test_platforms_are_recognised_in_any_wording(text):
    assert agents.platform_scheme(text), agents.platform_signs(text)


@pytest.mark.parametrize("text", HONEST)
def test_ordinary_receipts_and_referral_promos_are_not_platforms(text):
    assert not agents.platform_scheme(text)


@pytest.mark.parametrize("text", PYRAMIDS)
def test_an_unknown_sender_platform_is_flagged(text):
    card = agents.run_check(text, sender="telegram account", persist=False, echo=False)
    assert card["verdict"] in ("scam", "suspicious")


def test_an_operators_own_loan_notice_is_not_a_pyramid():
    text = "You have received an advance of 1000XAF from MMC to repay with Access Fee:35XAF  Fee:0.5% daily,Max Fee:18.5% Transact ID:[TXN_ID]. Your transaction is pending, wait for final SMS"
    card = agents.run_check(text, sender="Mobile Money", persist=False, echo=False)
    assert card["verdict"] not in ("scam", "suspicious")

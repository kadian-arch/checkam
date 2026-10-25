from checkam import agents


def test_paying_now_for_a_bigger_return_is_caught_but_operator_bundles_are_not():
    assert agents.stake_and_return("Buy a machine for 5000frs, mine everyday for 1month and get 10500frs.")
    assert agents.stake_and_return("Investissez 10 000 FCFA et recevez 25 000 FCFA en 7 jours")
    assert not agents.stake_and_return("You have received 5000 FCFA from Paul. New balance 7000 FCFA")


def test_dates_no_calendar_has_mark_a_forged_receipt():
    assert agents.impossible_date("Transaction le 2026-02-30 a 10:13") == "2026-02-30"
    assert agents.impossible_date("31/04/2026") == "31/04/2026"
    assert agents.impossible_date("Date:25-09-2026 03:54") is None


def test_a_dial_code_that_pays_a_person_is_not_an_official_route():
    assert agents.USSD_TO_PERSON.search("Composez *126*1*1*677123456*5000# pour activer")
    assert not agents.USSD_TO_PERSON.search("Dial *126# to check your balance")


def test_fees_to_receive_a_gift_are_a_payment_demand():
    assert "send_money" in agents.demands_in("They want to give me a TV but I should send transport first")
    assert "send_money" in agents.demands_in("Payez les frais de livraison pour recevoir votre colis")


def test_payer_note_in_an_official_receipt_is_not_the_operator_asking():
    receipt = ("A transaction of 200 XAF by LEEDTECH LTD on your mobile money account successfully completed. "
               "Message from debit receiver: Pay SMS Notification Fees. Your new balance:2528 XAF.")
    assert agents.operator_demands(receipt, "official") == []
    fake = "Vous avez recu 25000 FCFA. Message de l'expediteur: SVP renvoyez l'argent au 677123456."
    assert "send_money" in agents.operator_demands(fake, "personal")
    assert "send_money" in agents.operator_demands(fake, "unknown")


def test_familiar_french_and_english_money_requests_are_demands():
    for msg in ["Bonjour cher ami ! S'il te plait envoie-moi urgemment 30.000 Fcfa.", "Fais-moi un transfert de 10 000 stp",
                "Prête-moi 5000 je te rembourse demain", "Bro lend me 20k till Friday"]:
        assert "send_money" in agents.demands_in(msg), msg
    assert "send_money" not in agents.demands_in("Ne m'envoie jamais d'argent sans m'appeler d'abord")


def test_a_debit_note_is_a_label_but_a_credit_note_can_be_the_scam():
    debit = ("A transaction of 200 XAF by LEEDTECH LTD on your mobile money account successfully completed. "
             "Message from debit receiver: Pay SMS Notification Fees. Your new balance:2528 XAF.")
    assert agents.operator_demands(debit, "unknown") == []
    credit = "Vous avez reçu 25000 FCFA de Paul. Message de l'expediteur: SVP renvoyez l'argent au 677123456."
    assert "send_money" in agents.operator_demands(credit, "unknown")


def test_model_demands_need_words_in_the_message():
    import re
    otp = "Your MTN Skills Academy OTP is: 4411. Do not share this OTP. imtncm-prod.mtn.auth0.com"
    assert not re.search(agents.FOOTPRINT["click_link"], otp)
    assert re.search(agents.FOOTPRINT["click_link"], "Cliquez ici pour réclamer votre prix")


def test_advice_fits_the_scheme_and_never_mixes_them_up():
    from checkam import advice
    visa = "CANADA VISA LOTTERY 2026. Host: Canada Government. Sponsored travel, work permit. Apply here https://istincy.com/CANADA-VISA-2026"
    s = advice.scheme_of(visa, [], "visa lottery scam")
    assert s == "visa_scholarship"
    do, dont = advice.steps("scam", s, {"brands": [], "asks": ["click_link"], "links": ["istincy.com"]}, "en")
    text = " ".join(do + dont)
    assert "canada.ca" in text and "fee" in text
    assert "PIN" not in text and "by mistake" not in text  # nothing about other schemes
    rev = "Je vous ai envoye 25 000 FCFA par erreur sur votre compte Mobile Money, renvoyez-les"
    do, dont = advice.steps("scam", advice.scheme_of(rev, [], ""), {"brands": ["mtn"], "asks": ["send_money"], "links": []}, "fr")
    assert any("*126#" in d for d in do) and any("erreur" in d for d in dont)


def test_official_route_accepts_codes_that_end_with_star_hash():
    assert agents.OFFICIAL_ROUTE.search("Get your MTN TV bundle now *280*16*#")


def test_a_link_that_does_not_belong_to_the_claimed_government_is_caught():
    from checkam.adapters import linkcheck
    who = linkcheck.claimed("CANADA VISA LOTTERY 2026. Host: Canada Government")
    assert who and not linkcheck.belongs("istincy.com", who[1])
    assert linkcheck.belongs("www.canada.ca", who[1]) and linkcheck.belongs("ircc.gc.ca", who[1])
    assert linkcheck.registrable("portal.minesup.gov.cm") == "minesup.gov.cm"


def test_the_message_itself_decides_the_scheme_over_similar_old_reports():
    from checkam import advice
    sos = "Hello my dear, I am stuck at the border and my phone is almost off. Please send me 20 000 by Orange Money, I will refund you tomorrow"
    assert advice.scheme_of(sos, ["wrong_number_reversal"], "fake border emergency") == "family"


def test_advice_points_to_the_institution_the_message_names():
    from checkam import advice
    from checkam.adapters import linkcheck
    msg = "Bourses du MINESUP 2026: payez 15 000 FCFA de frais de dossier pour valider votre place"
    who = linkcheck.claimed(msg, "fr")
    do, _ = advice.steps("scam", "visa_scholarship", {"brands": [], "asks": ["send_money"], "links": []}, "fr", "", who)
    assert "gov.cm" in do[0] and "canada" not in do[0].lower()

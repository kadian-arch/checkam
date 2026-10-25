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

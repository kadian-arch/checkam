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


def test_footprints_are_demand_verbs_not_nouns():
    import re
    fp = agents.FOOTPRINT["send_money"]
    assert not re.search(fp, "Good news! Instant referral payments are back. Earn 200F automatically for every referral")
    assert not re.search(fp, "Fee was 0 XAF, loyalty fee was 0. Your new balance: 2528 XAF")
    assert re.search(fp, "Payez 5000 pour activer") and re.search(fp, "please send me the money")


def test_a_code_does_not_vouch_for_free_money_from_an_unverified_sender():
    card = agents.run_check("MTN Cameroon offre 10 000 FCFA à toute personne souscrivant au code #237#", persist=False)
    assert card["verdict"] != "looks_genuine"


def test_a_registered_senders_long_standing_site_is_its_own_service(monkeypatch):
    from checkam.adapters import linkcheck
    from checkam.trace import Trace
    monkeypatch.setattr(linkcheck, "enabled", lambda: True)
    ages = {"mtnzik.cm": 2900, "mtn-bonus-2026.com": 9}
    monkeypatch.setattr(linkcheck, "age_days", lambda host, budget=5.0: ages.get(linkcheck.registrable(host)))
    msg = "Tape *192*2# pour telecharger PILE de Mauvais Djo sur mtnzik.cm Appelle le 8706 (gratuit)"
    tr = Trace(echo=False)
    case = agents.Case(tr.run_id, msg, agents.intake(msg, tr, sender="8706"))
    out = agents._tool_link_history(case, tr)
    assert all(f.direction != "scam" for f in out) and not agents.red_flags(case)
    # the same push from a personal number to a 9-day-old lookalike is a scam signal
    fake = "Telechargez votre bonus sur mtn-bonus-2026.com maintenant"
    case2 = agents.Case(tr.run_id, fake, agents.intake(fake, tr, sender="677123456"))
    assert any(f.direction == "scam" for f in agents._tool_link_history(case2, tr))


def test_scheme_words_match_whole_words_and_fake_receipts_are_reversal():
    from checkam import advice
    receipt = "MobileMoney Vous avez reçu 30200 XAF de JEAN P. sur votre compte mobile money. Votre nouveau solde est de 60809 FCFA."
    assert advice.scheme_of(receipt, [], "accidental transfer refund scam") == "reversal"
    assert advice.scheme_of("Mama I had an accident, send 20000 now", [], "") == "family"


def test_stems_still_match_every_ending():
    from checkam import advice
    assert advice.scheme_of("Recrutement massif: 300 postes, payez les frais de dossier", [], "") == "job"
    assert advice.scheme_of("Investissez 10 000 et doublez votre argent", [], "") == "investment"
    assert advice.scheme_of("Votre compte est bloqué, donnez votre code secret", [], "") == "credential"


def test_a_domain_seen_only_in_real_operator_messages_is_a_known_operator_link():
    from checkam.trace import Trace
    tr = Trace(echo=False)
    msg = "Tape *192*2# pour telecharger PILE de Mauvais Djo Plus de ZIKS sur mtnzik.cm Appelle le 8706"
    case = agents.Case(tr.run_id, msg, agents.intake(msg, tr, sender="8706"))
    out = agents._tool_link_history(case, tr)
    assert any(f.direction == "genuine" and "real operator message" in f.claim for f in out)
    assert not agents.red_flags(case)
    # a shortener seen in real messages proves nothing
    case2 = agents.Case(tr.run_id, "Open bit.ly/3abc to claim", agents.intake("Open bit.ly/3abc to claim", tr))
    assert agents._in_real_messages(case2, "bit.ly", tr) == 0


def test_testimonial_bait_counts_as_a_windfall_promise():
    bait = ("MobileMoney: You have received 750,000 FCFA from AFRICA DEVELOPMENT FOUNDATION FUNDS your mobile money account. "
            "Status caption: This is true promotion I apply and I receive")
    assert agents.PROMISE.search(bait)
    assert agents.PROMISE.search("C'est vrai, j'ai postulé hier et j'ai reçu 50 000")
    assert not agents.PROMISE.search("Vous avez reçu 5000 FCFA de Paul. Nouveau solde 7000 FCFA.")


def test_french_negation_before_the_verb_is_not_a_demand():
    assert agents.demands_in("Orange Money : pour votre sécurité, ne partagez jamais votre code secret.") == []
    assert agents.demands_in("N'envoyez pas d'argent à un inconnu") == []
    assert "pin" in agents.demands_in("Partagez votre code secret avec notre agent pour débloquer")


def test_a_quiet_personal_message_cannot_cost_money_but_the_mistake_opener_still_can():
    ok = agents.run_check("Bonjour tantine, j'ai déjà envoyé les 5 000 pour le marché ce matin. On se voit dimanche à l'église.",
                          sender="+237 677 55 66 77", persist=False)
    assert ok["verdict"] == "looks_genuine"
    opener = agents.run_check("Bonjour, je vous ai envoyé 5 000 par erreur, vérifiez votre solde svp", sender="+237 677 55 66 77", persist=False)
    assert opener["verdict"] != "looks_genuine"


def test_paying_through_the_operators_own_route_is_not_a_risky_demand():
    promo = {"asks": ["send_money"], "sender_kind": "official", "numbers": [], "body_numbers": 0, "links": [],
             "text": "Y'ello! Paye tes frais de scolarité avec MoMo Pay dans les établissements partenaires. Compose *126# ou utilise l'appli MoMo."}
    assert "send_money" not in agents.risky_asks(promo)
    # the same words from a personal number, or with a number to pay, stay risky
    assert "send_money" in agents.risky_asks({**promo, "sender_kind": "personal"})
    assert "send_money" in agents.risky_asks({**promo, "body_numbers": 1})


def test_an_earlier_genuine_check_of_a_number_is_not_evidence_against_it():
    from checkam import store
    from checkam.trace import Trace
    store.save_check({"id": "C-prev0001", "created": store.now(), "masked_text": "x", "verdict": "looks_genuine", "confidence": 0.75, "language": "fr",
                      "numbers": ["677-pknfzt"], "links": [], "scam_types": [], "campaign_id": None, "run_id": "r", "channel": "text"})
    tr = Trace(echo=False)
    m = "Bonjour tantine, on se voit dimanche"
    case = agents.Case(tr.run_id, m, agents.intake(m, tr, sender="+237 677 55 66 77"))
    assert all(f.direction != "scam" for f in agents._tool_number_history(case, tr))


def test_our_own_earlier_doubt_never_makes_a_message_that_asks_nothing_risky():
    from checkam import store
    from checkam.trace import Trace
    store.save_check({"id": "C-prev0002", "created": store.now(), "masked_text": "x", "verdict": "suspicious", "confidence": 0.6, "language": "fr",
                      "numbers": ["677-pknfzt"], "links": [], "scam_types": [], "campaign_id": None, "run_id": "r", "channel": "text"})
    tr = Trace(echo=False)
    quiet = "Bonjour tantine, on se voit dimanche"
    case = agents.Case(tr.run_id, quiet, agents.intake(quiet, tr, sender="+237 677 55 66 77"))
    assert all(f.direction != "scam" for f in agents._tool_number_history(case, tr))
    asks = "Envoie-moi 5000 vite au 677 55 66 77"
    case = agents.Case(tr.run_id, asks, agents.intake(asks, tr, sender="+237 677 55 66 77"))
    assert any(f.direction == "scam" for f in agents._tool_number_history(case, tr))


def test_a_credit_notice_with_no_sender_is_checked_against_the_balance_not_left_unsure():
    bare = "Vous avez recu 33700 XAF de JEAN P. (677 12 34 56) sur votre compte mobile money. Votre nouveau solde est de 68870 FCFA."
    assert agents.unverified_credit({"text": bare, "sender": ""})
    assert not agents.unverified_credit({"text": bare, "sender": "MobileMoney"})
    assert not agents.unverified_credit({"text": "A transaction of 200 XAF by LEEDTECH LTD. You have paid 200 XAF.", "sender": ""})
    card = agents.run_check(bare, persist=False)
    assert card["verdict"] in ("suspicious", "scam")
    assert any("126" in w["text"] for w in card["why"])
    assert agents.run_check(bare, sender="MobileMoney", persist=False)["verdict"] == "looks_genuine"


def test_a_cached_answer_belongs_to_the_rules_that_gave_it():
    from checkam import store
    k = store.cache_key("Vous avez gagné", "", "fr")
    old, store.RULES = store.RULES, "older-rules"
    try:
        assert store.cache_key("Vous avez gagné", "", "fr") != k
    finally:
        store.RULES = old


def test_model_french_without_accents_or_with_english_is_not_shown():
    assert agents.well_written("Il vient de MobileMoney, un nom qu'un téléphone personnel ne peut pas utiliser", "fr")
    assert not agents.well_written("Il vient de MobileMoney, un nom qu'un telephone personnel ne peut pas utiliser", "fr")
    assert not agents.well_written("ne demande ni argent, ni code, ni lien exterior", "fr")
    assert agents.well_written("It comes from MobileMoney and asks for nothing", "en")


def test_a_receipt_typed_from_a_personal_number_is_forged():
    r = "Vous avez reçu 30 000 FCFA de JEAN P. sur votre compte mobile money. Nouveau solde : 31 250 FCFA."
    assert agents.forged_receipt({"text": r, "sender_kind": "personal"})
    assert not agents.forged_receipt({"text": r, "sender_kind": "official"})
    assert not agents.forged_receipt({"text": "Tu as reçu les 5000 ? On se voit demain", "sender_kind": "personal"})
    assert agents.run_check(r, sender="+237 676 11 22 33", persist=False)["verdict"] == "scam"


def test_the_models_own_notes_reach_the_person_only_in_plain_words_and_their_language():
    assert agents.plain_note("Asks for a fee before paying out a prize", "en")
    assert not agents.plain_note('Sender shown = "MTN"', "en")
    assert not agents.plain_note("SMS claims receipt of 30200 XAF from JEAN P.", "fr")
    assert agents.plain_note("Demande des frais avant de verser un gain", "fr")


def test_a_victim_retelling_what_happened_is_judged_on_what_they_were_asked():
    told = agents.run_check("It was a withdrawal and I was supposed to input my code", persist=False)
    assert told["verdict"] in ("suspicious", "scam")
    credit = agents.run_check("It said I had received 35000frs on my account but the message came from a personal number", persist=False)
    assert credit["verdict"] in ("suspicious", "scam")


def test_a_job_or_scholarship_announcement_is_never_called_harmless():
    for ad in ["En rejoignant Nestlé, vous rejoignez la plus grande société alimentaire au monde. Type de contrat: Temps plein",
               "Volontaires ONU (VNU) 2024/2025. La candidature est en cours"]:
        assert agents.run_check(ad, persist=False)["verdict"] in ("suspicious", "scam"), ad


def test_a_fee_for_the_application_is_a_payment_demand_without_a_pay_verb():
    assert agents.FEE_FOR.search("Our interest is of 104 FCFA only, the 6,000 FCFA, it's for the application")
    assert agents.FEE_FOR.search("Les frais de dossier sont de 10 000 FCFA")
    assert not agents.FEE_FOR.search("Your new balance is 6,000 FCFA")


def test_a_plain_operator_notice_that_asks_nothing_is_not_left_unsure_but_a_threat_is_not_cleared():
    assert agents.run_check("Your Orange data bundle of 2GB has been activated. Valid 7 days.", persist=False)["verdict"] == "looks_genuine"
    assert agents.run_check("MTN: votre compte Mobile Money sera bloqué dans 24h. Un agent va vous appeler.", persist=False)["verdict"] != "looks_genuine"


def test_cash_for_nothing_is_a_promise_but_a_bundle_bonus_is_not():
    for m in ["Recevez 35 000 F CFA en espèces!", "MTN Cameroon offre 10 000 FCFA à toute personne souscrivant au code #237#",
              "Enter this link to receive a certain amount of money", "Transfert d'argent de 10 000 FCFA de JEAN à tous les Camerounais"]:
        assert agents.FREE_CASH.search(m), m
    for m in ["Pour 5000F, reçois en retour 25000F d'appels et 6Go d'Internet", "Make an airtime refill and receive a BONUS of up to 2500U",
              "You've received a MOMOKASH loan worth 5300.0FCFA from ORIS Finance"]:
        assert not agents.FREE_CASH.search(m), m


def test_a_credit_notice_cut_before_the_amount_is_still_checked_against_the_balance():
    assert agents.run_check("You have just received...", persist=False)["verdict"] in ("suspicious", "scam")


def test_a_french_rewrite_that_drops_letters_or_a_note_without_words_is_not_shown():
    ours = "N'importe qui peut taper un message « vous avez reçu de l'argent »"
    assert not agents.accents_kept(ours, "N'importe qui peut taper un message « vous avez reu de l'argent »", "fr")
    assert agents.accents_kept(ours, "Tout le monde peut écrire « vous avez reçu de l'argent »", "fr")
    assert not agents.plain_note("+237 6 54 **** ***", "fr")


def test_an_english_note_is_never_shown_as_french():
    assert not agents.well_written("Follow-up message asks to return 25000 XAF claiming hospital error", "fr")
    assert agents.well_written("Arnaque : argent « envoyé par erreur »", "fr")
    assert agents.well_written("Le message demande de renvoyer 25 000 FCFA", "fr")


def test_checking_the_same_message_again_is_not_new_evidence():
    from checkam import store
    from checkam.trace import Trace
    m = "Envoie-moi 5000 vite au 699 12 34 98 svp"
    tr = Trace(echo=False)
    f = agents.intake(m, tr)
    code = f["numbers"][0]["code"]
    for i in range(3):
        store.save_check({"id": f"C-same{i:04d}", "created": store.now(), "masked_text": agents.privacy.mask(m), "verdict": "scam", "confidence": 0.9,
                          "language": "fr", "numbers": [code], "links": [], "scam_types": [], "campaign_id": None, "run_id": "r", "channel": "text"})
    case = agents.Case(tr.run_id, m, f)
    assert not any("check" in fd.claim.lower() for fd in agents._tool_number_history(case, tr))


def test_garbled_french_accents_are_caught_but_real_words_pass():
    assert agents.garbled("un message vous avez reù de l'argent")
    assert agents.garbled("Composez vous-mîme le *126#")
    for ok in ["Où est l'argent ?", "Une boîte de réception", "Le maître du jeu", "S'il vous plaît, vérifiez", "Ne renvoyez rien, même pas 500 F"]:
        assert not agents.garbled(ok), ok

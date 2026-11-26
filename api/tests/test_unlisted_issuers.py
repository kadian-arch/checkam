from checkam import agents


def card(text, sender=""):
    return agents.run_check(text, sender=sender, persist=False, echo=False)


def test_an_organisation_written_as_a_company_is_recognised_without_being_on_a_list():
    assert agents.named_issuer("Dangote Cameroon Ltd is recruiting 200 drivers") == "Dangote Cameroon Ltd"
    assert agents.named_issuer("Banque Atlantique Cameroun recrute") == "Banque Atlantique Cameroun"
    assert agents.named_issuer("I will see you at the market tomorrow") == ""


def test_a_notice_for_an_unlisted_company_with_nothing_to_check_is_not_cleared():
    c = card("Dangote Cameroon Ltd is recruiting drivers and mechanics in Douala. Interested candidates should apply.")
    assert c["verdict"] != "looks_genuine"
    assert any("no address, link or contact" in w["text"] for w in c["why"])


def test_ordinary_talk_that_mentions_a_company_is_left_alone():
    c = card("Mama I passed by Mama Ngum Foods Company this evening, they said the order is ready, I will carry it tomorrow", sender="Mama")
    assert c["verdict"] not in ("scam", "suspicious")

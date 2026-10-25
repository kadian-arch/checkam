from checkam import privacy


def test_real_number_becomes_a_code_and_never_stays_in_storage():
    out = privacy.extract("Send it back to 677 12 34 56 please")
    assert out["numbers"][0]["prefix"] == "677"
    assert out["numbers"][0]["code"].startswith("677-")
    masked = privacy.mask("Send it back to 677 12 34 56 please")
    assert "12 34 56" not in masked and "[PHONE:677-" in masked


def test_same_number_any_format_same_code():
    a = privacy.extract("+237 677123456")["numbers"][0]["code"]
    b = privacy.extract("677.12.34.56")["numbers"][0]["code"]
    assert a == b


def test_official_lines_and_domains_are_not_suspects():
    out = privacy.extract("WhatsApp MTN on 650528787 or visit link.mtn.cm/app")
    assert out["numbers"] == [] and out["official_numbers"] == ["650528787"]
    assert out["links"] == [] and out["official_links"] == ["link.mtn.cm"]


def test_amounts_are_not_phone_numbers():
    assert privacy.extract("Vous avez recu 250 000 000 FCFA")["numbers"] == []


def test_hidden_characters_are_counted_and_stripped():
    out = privacy.extract("Orange​ Mo​ney: send 5000")
    assert out["hidden_characters"] == 2 and "​" not in out["text"]


def test_dataset_tokens_are_read_as_codes():
    assert privacy.extract("call [PHONE:654-jwmukg] now")["numbers"][0]["code"] == "654-jwmukg"


def test_pin_requests_are_flagged():
    assert privacy.extract("Confirm your PIN to receive the money")["asks_for_secret"]


def test_a_clean_channel_file_adds_to_the_official_lists(tmp_path):
    f = tmp_path / "channels.json"
    f.write_text('{"mtn": {"sender_names": ["Yello Care"], "whatsapp": ["+237 651 00 00 00"], "short_codes": ["*126#"], '
                 '"websites": ["mtn.cm"], "sources": ["https://mtn.cm/help/contact-us/"]}}', encoding="utf-8")
    before = (set(privacy.OFFICIAL), set(privacy.SENDER_NAMES))
    try:
        assert privacy.load_channels(f) == []
        assert "651000000" in privacy.OFFICIAL and "yellocare" in privacy.SENDER_NAMES
    finally:
        privacy.OFFICIAL.clear(); privacy.OFFICIAL.update(before[0])
        privacy.SENDER_NAMES.clear(); privacy.SENDER_NAMES.update(before[1])


def test_an_unsafe_channel_file_is_refused_whole_and_never_crashes_the_app(tmp_path):
    f = tmp_path / "channels.json"
    f.write_text('{ "mtn": { "whatsapp": ["650528787"] "sources": [] }', encoding="utf-8")  # broken JSON
    assert privacy.load_channels(f) and privacy.load_channels(f)[0].startswith("not valid JSON")
    bad = {"mtn": {"whatsapp": ["650528787"], "websites": ["mtn.cm"], "short_codes": ["*126#"], "sources": ["https://mtn.cm"]},
           "orange": {"whatsapp": ["650528787"], "websites": ["orange.cm"], "short_codes": ["#150#, #123#"], "sources": ["https://orange.cm"]},
           "camtel": {"whatsapp": ["620105050"], "websites": ["mtn.cm"], "sources": []}}
    problems = " | ".join(privacy.channel_problems(bad))
    assert "also listed for mtn" in problems          # one number, two operators
    assert "one code per item" in problems            # "#150#, #123#" in one string
    assert "does not belong to camtel" in problems    # camtel pointing at mtn.cm
    assert "needs at least one source" in problems


def test_the_channel_file_in_the_repo_is_safe():
    # this runs in CI on every pull request: a wrong official number can never be merged
    if privacy.CHANNELS_FILE.exists():
        import json
        assert privacy.channel_problems(json.loads(privacy.CHANNELS_FILE.read_text(encoding="utf-8"))) == []

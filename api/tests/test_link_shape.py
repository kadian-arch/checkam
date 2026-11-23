from checkam.adapters import linkcheck


def kinds(host):
    return [s for s, _, _ in linkcheck.shape(host)]


def test_lookalike_of_a_known_name_is_strong_and_the_real_site_is_clean():
    assert "strong" in kinds("mtn-promo-cm.xyz") and "strong" in kinds("verify.orange-money.top")
    for real in ("mtn.cm", "www.mtn.cm", "momo.mtn.cm", "canada.ca", "orange.cm", "wa.me"):
        assert linkcheck.shape(real) == [], real


def test_bare_number_and_foreign_letter_addresses_are_strong():
    assert kinds("194.5.6.7") == ["strong"] and "strong" in kinds("xn--mtn-abc.com")


def test_cheap_endings_and_free_builders_are_only_weak_and_ordinary_words_are_not_brands():
    assert kinds("mypromo.blogspot.com") == ["weak"] and kinds("cheap-site.xyz") == ["weak"]
    assert linkcheck.shape("amount.com") == [] and linkcheck.shape("nonmtnorange.com") == []

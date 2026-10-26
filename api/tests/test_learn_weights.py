from checkam import learned


def test_the_learned_row_matches_its_names_and_reads_findings_and_facts():
    scam = learned.features([{"tool": "number_history", "direction": "scam", "weight": "strong", "status": "accepted"}], {"pin": True, "sender_kind": "personal"})
    real = learned.features([{"tool": "genuine_twin", "direction": "genuine", "weight": "strong", "status": "accepted"}], {"official_route": True, "sender_kind": "registered"})
    assert len(scam) == len(learned.NAMES) == len(real)
    assert scam[learned.NAMES.index("number_history:scam")] == 1.0 and scam[learned.NAMES.index("pin")] == 1.0
    rejected = learned.features([{"tool": "number_history", "direction": "scam", "weight": "strong", "status": "rejected"}], {})
    assert rejected[learned.NAMES.index("number_history:scam")] == 0  # what the Critic rejected never counts


def test_weights_for_another_row_shape_are_never_applied(tmp_path, monkeypatch):
    f = tmp_path / "w.json"
    f.write_text('{"names": ["old"], "weights": [1], "bias": 0, "threshold": 0.5}')
    monkeypatch.setattr(learned, "FILE", f)
    learned._model.cache_clear()
    assert learned.probability([], {}) is None
    learned._model.cache_clear()

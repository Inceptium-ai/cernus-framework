"""Baseline data: integrity of the trimmed NIST SP 800-53B catalogs."""

from cernus_core.baselines import baseline_families, load_baseline
from cernus_core.catalogs import load_crosswalk

# Crosswalk controls that are NOT in the 800-53B Moderate baseline: they are
# FedRAMP-added enhancements, evaluated by Cernus but outside the documented
# baseline (FedRAMP delta content is a declared non-goal for now).
BEYOND_BASELINE = {"IA-5(7)", "SA-11(1)", "SA-11(2)", "SR-4"}


def test_baselines_load_and_nest():
    low = load_baseline("low")
    moderate = load_baseline("moderate")
    assert 140 <= len(low) <= 170
    assert 270 <= len(moderate) <= 330
    mod_ids = {c["id"] for c in moderate}
    assert {c["id"] for c in low} <= mod_ids  # Low ⊆ Moderate
    assert len(baseline_families("moderate")) >= 17


def test_controls_have_statements_and_shape():
    for c in load_baseline("moderate"):
        assert c["id"] and c["title"] and c["family"]
        assert isinstance(c["statement"], str)
    ra5 = next(c for c in load_baseline("moderate") if c["id"] == "RA-5")
    assert "vulnerabilit" in ra5["statement"].lower()


def test_crosswalk_overlays_baseline():
    mod_ids = {c["id"] for c in load_baseline("moderate")}
    cw_ids = {c["id"] for c in load_crosswalk("nist-800-53r5")["controls"]}
    assert cw_ids - mod_ids == BEYOND_BASELINE
    assert len(cw_ids & mod_ids) >= 10


def test_unknown_level_raises():
    import pytest

    with pytest.raises(KeyError):
        load_baseline("extreme")

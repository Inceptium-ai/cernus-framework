from cernus_core.catalogs import controls, load_crosswalk


def test_crosswalk_loads_and_is_well_formed():
    cw = load_crosswalk()
    assert cw["catalog"] == "nist-800-53r5"
    ids = [c["id"] for c in controls()]
    assert len(ids) == len(set(ids)) and "RA-5" in ids and "SI-2" in ids
    for c in controls():
        assert c["rule"] and c["statement"] and c["family"] == c["id"].split("-")[0]

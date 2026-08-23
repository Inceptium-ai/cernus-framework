from cernus_core.catalogs import available_catalogs, controls, load_crosswalk

KNOWN_RULES = {
    "scan_fresh",
    "rescan_present",
    "sla_met",
    "inventory_with_sbom",
    "change_controlled",
    "no_open_category",
    "gates_passed",
    "poam_current",
}


def test_nist_crosswalk_loads_and_is_well_formed():
    cw = load_crosswalk()
    assert cw["catalog"] == "nist-800-53r5"
    ids = [c["id"] for c in controls()]
    assert len(ids) == len(set(ids)) and "RA-5" in ids and "SI-2" in ids
    for c in controls():
        assert c["family"] == c["id"].split("-")[0]


def test_all_catalogs_are_well_formed():
    packs = available_catalogs()
    assert {p["catalog"] for p in packs} >= {
        "nist-800-53r5",
        "cis-v8",
        "soc2-tsc",
        "pci-dss-4",
        "iso-27001",
    }
    for pack in packs:
        cs = controls(pack["catalog"])
        ids = [c["id"] for c in cs]
        assert len(ids) == len(set(ids)), pack["catalog"]
        for c in cs:
            assert c["rule"] in KNOWN_RULES, (pack["catalog"], c["id"], c["rule"])
            assert c["statement"] and c["title"] and c["family"]

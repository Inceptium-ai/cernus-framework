"""Process definitions: shape and internal consistency."""

from cernus_core.processes import available_processes, load_process

REQUIRED_KEYS = {
    "process",
    "title",
    "description",
    "baseline",
    "required_catalogs",
    "phases",
    "artifacts",
}


def test_available_processes():
    procs = available_processes()
    ids = {p["process"] for p in procs}
    assert {"fedramp-low-ato", "fedramp-moderate-ato"} <= ids
    for p in procs:
        assert REQUIRED_KEYS <= set(p)
        for phase in p["phases"]:
            assert phase["id"] and phase["title"]
            for step in phase["steps"]:
                assert step["id"] and step["title"] and step["check"]
        kinds = {a["kind"] for a in p["artifacts"]}
        assert kinds <= {"generated", "exported"}


def test_process_baseline_resolves():
    from cernus_core.baselines import load_baseline

    for p in available_processes():
        assert load_baseline(p["baseline"])  # every named baseline exists


def test_load_single():
    p = load_process("fedramp-moderate-ato")
    assert p["baseline"] == "moderate"
    assert any(a["id"] == "ssp" for a in p["artifacts"])

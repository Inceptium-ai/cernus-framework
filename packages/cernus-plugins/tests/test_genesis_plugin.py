def test_two_projects_same_service_name_get_distinct_systems():
    """A catalog app instantiated next to its source shares the service name;
    each Genesis project must still be its own Cernus system."""
    from cernus_plugins.genesis import GenesisConnector

    manifest = {"service": {"name": "resume-builder"}}
    dep_a = {"project_id": "proj_aaaa", "service": "resume-builder"}
    dep_b = {"project_id": "proj_bbbb", "service": "resume-builder"}
    a = GenesisConnector().build(manifest, None, dep_a)
    b = GenesisConnector().build(manifest, None, dep_b)
    assert a.systems[0].id != b.systems[0].id
    assert a.systems[0].genesis_project_id == "proj_aaaa"
    assert b.systems[0].genesis_project_id == "proj_bbbb"
    # No project id (CLI ingest of a bare workspace): service name still keys.
    c = GenesisConnector().build(manifest, None, {})
    d = GenesisConnector().build(manifest, None, {})
    assert c.systems[0].id == d.systems[0].id

# SIEM-E2E — SIEM federation end-to-end conservation

*Implementation: `tests/lab_siem_federation/test_siem_federation_e2e.py`*

Conservation test: an event fanned out to Splunk (CIM) must be retrievable via the swarm's SPL pivot — a write↔read contract break surfaces here, not in production.

`tests/lab_siem_federation/test_siem_federation_e2e.py:L189-L195`

```python
    def test_fanned_out_event_is_retrievable_via_swarm_pivot(self, siem_url):
        doc, _ = cim_fanout(_nettap_event())
        STORE.index("nexus_network", "cim", doc)                 # the fanout write
        tool = sq.SiemQueryTool(siem_config=_cfg(siem_url, "spl", ["nexus_network"]))
        out = tool._run("scope the dst across the fleet", "b",
                        sq.build_spl(DST, ["nexus_network"], 6, 200))   # the swarm read
        assert "returned 1 row" in out and DST in out, "conservation broken: fanned-out event not retrieved"
```

Same conservation guarantee on the Elastic (ECS) path via ES|QL.

`tests/lab_siem_federation/test_siem_federation_e2e.py:L222-L227`

```python
    def test_fanned_out_event_retrievable_via_esql(self, siem_url):
        doc, _ = ecs_fanout(_nettap_event())
        STORE.index("nexus-network", "ecs", doc)
        tool = sq.SiemQueryTool(siem_config=_cfg(siem_url, "esql", ["nexus-network"]))
        out = tool._run("scope dst", "b", sq.build_esql(DST, ["nexus-network"], 6, 200))
        assert DST in out, "ECS conservation broken: fanned-out event not retrieved via ES|QL"
```

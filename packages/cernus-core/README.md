# cernus-core

The open core of [Cernus](https://github.com/Inceptium-ai/cernus-framework):
runtime security, continuous compliance, and ATO evidence for deployed
applications.

`cernus-core` has no server, no database, and no network calls of its own. It gives you:

- **Contracts** (`contracts/*.schema.json`) — versioned JSON Schemas for
  `Finding`, `Asset`, `System`, `Deployment`, `PolicySet`, `Decision`,
  `ControlResult`, `EvidenceRecord`, and the `IngestBatch` envelope. Any tool
  can produce or consume Cernus objects; the schemas ship inside the wheel.
- **Model** (`cernus_core.model`) — dataclasses for those objects, with stable
  fingerprints for deduplication.
- **Plugin SDK** (`cernus_core.plugins`) — `Connector` (turn a tool's output
  into an `IngestBatch`), `Scanner` (invoke a tool you already have),
  `Exporter` (write OSCAL/SARIF). Plugins register via entry points; built-ins
  win on name collision; a broken plugin is reported, never fatal.
- **Policy engine** (`cernus_core.policy`) — deterministic, priority-ordered,
  first-match triage rules with a recorded reason per decision, and an explicit
  *unmatched* outcome that becomes the human-review queue.

Most people want the CLI: `pip install cernus-cli`.

## License

Apache-2.0.

# Cernus Framework

**Runtime security, continuous compliance, and ATO evidence for deployed
applications — built on the scanners you already run.**

*Cernus — from the Latin* cernere, *to discern: to sort what matters from what doesn't.*

Cernus connects your infrastructure and scanners to one normalized runtime
security model. It wraps existing open-source tools as plugins (Trivy, Syft,
Semgrep, Gitleaks, Dependency-Track, Cartography…), speaks the open standards
(SARIF, CycloneDX, OSCAL), and adds the part nobody ships: deterministic,
versioned triage policy with a recorded reason for every decision, and an
append-only evidence ledger.

```bash
pip install cernus-cli
cernus doctor                          # which scanners are installed
cernus scan image python:3.11-slim     # syft SBOM + trivy vulns → one batch
cernus ingest ./my-genesis-workspace   # Genesis manifest + gate evidence + deploy record
cernus triage .cernus/python-3-11-slim.batch.json --policy policy.yaml
cernus export .cernus/python-3-11-slim.batch.json --format oscal-poam -o poam.json
```

## Packages

| Package | What it is |
|---|---|
| `cernus-core` | JSON Schema contracts, canonical model, plugin SDK, policy engine. No I/O. |
| `cernus-plugins` | First-party connectors/scanners/exporters: genesis, trivy, syft, cyclonedx, sarif, oscal. |
| `cernus-cli` | The `cernus` command. |

All Apache-2.0. The commercial Cernus control plane (posture, continuous
control monitoring, POA&M workflow, governed remediation) runs the same open
core and emits the same artifacts.

## The model

```
System ─┬─ Deployment ─┬─ Asset ─── Finding ─── Decision
        │   (manifest,  │  (image,    (vuln,      (rule | model | human,
        │    evidence)  │   service)   sast,…)     reason, autonomy)
        │               └─ Sbom
        └─ ControlResult ─── EvidenceRecord (append-only, hashed)
```

See [docs/architecture.md](docs/architecture.md) and
[docs/integrations.md](docs/integrations.md).

## Writing a plugin

```python
from cernus_core.plugins import Connector, register_connector

@register_connector
class NessusConnector(Connector):
    name = "nessus"
    def detect(self, path, document=None): ...
    def ingest(self, path, document=None, **context): ...
```

Register through an entry point in your own distribution — no fork:

```toml
[project.entry-points."cernus.connectors"]
nessus = "my_plugin.nessus:NessusConnector"
```

## License

Apache-2.0 · Part of the Inceptium family with
[Genesis](https://github.com/Inceptium-ai/genesis-framework) and
[Tabella](https://github.com/Inceptium-ai/tabella).

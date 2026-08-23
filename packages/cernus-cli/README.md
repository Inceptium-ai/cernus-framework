# cernus-cli

```bash
pip install cernus-cli
cernus doctor                                   # which scanners and plugins are available
cernus scan image python:3.11-slim              # syft SBOM + trivy vulns -> .cernus/batch.json
cernus ingest trivy-report.json                 # normalize any supported tool output
cernus ingest ./my-genesis-workspace            # Genesis manifest + evidence + deployment
cernus triage .cernus/batch.json --policy policy.yaml
cernus export .cernus/batch.json --format oscal-poam -o poam.json
cernus push .cernus/batch.json --server http://localhost:8200
```

Everything the CLI writes validates against the contracts in `cernus-core`.

# cernus-plugins

First-party plugins for [Cernus](https://github.com/Inceptium-ai/cernus-framework).
Each one wraps a tool you already run; none re-implements a scanner.

| Plugin | Kind | What it does |
|---|---|---|
| `genesis` | connector | Genesis `EvidencePackage` + `DeliveryManifest` → System, Deployment, Findings |
| `trivy` | connector + scanner | `trivy image/sbom --format json` → Findings with CVE/CVSS/purl; runs trivy |
| `syft` | scanner | `syft <image> -o cyclonedx-json` → SBOM |
| `cyclonedx` | connector | CycloneDX SBOM → Sbom + component Assets |
| `sarif` | connector + exporter | SARIF 2.1.0 in (semgrep, CodeQL, …) and out |
| `oscal` | exporter | Findings → OSCAL 1.1 POA&M (minimal, schema-shaped) |

Plugins register through entry points (`cernus.connectors`, `cernus.scanners`,
`cernus.exporters`). Write your own the same way — see `cernus_core.plugins`.

# Integrations — integrate first, build second

Cernus composes existing open-source tools and builds only what none of them
do. Three tiers:

## Tier 1 — run as-is (plugin)

Mature, one job, stable CLI/API. Wrapped, never forked.

| Tool | Role | Plugin | Status |
|---|---|---|---|
| Trivy | image / fs / SBOM vulnerability + secret + misconfig scan | `trivy` connector + scanner | ✅ 0.1 |
| Syft | SBOM generation (CycloneDX) | `syft` scanner, `cyclonedx` connector | ✅ 0.1 |
| Genesis (genesis-gates) | build-time gates, manifest, evidence | `genesis` connector | ✅ 0.1 |
| Semgrep / CodeQL / Bandit | SAST via SARIF | `sarif` connector | ✅ 0.1 |
| Gitleaks | secret scan (via Genesis gate or SARIF) | `sarif` connector | ✅ 0.1 |
| Grype | alternative vuln matcher over SBOMs | `grype` connector | Phase 1 |
| Dependency-Track | SBOM store + continuous CVE matching + VEX | `deptrack` plugin (optional) | Phase 1 |
| Cartography | cloud / k8s asset graph | `cartography` collector | later |
| OpenSCAP | STIG / CIS host checks | `openscap` connector | later |
| Steampipe | cloud config queries | later | later |

## Tier 2 — adopt the format, use the library

The standard is the value; the reference tool is a library or validator.

| Standard | Use | Notes |
|---|---|---|
| OSCAL 1.1 | POA&M, assessment results, (later) SSP evidence | `oscal` exporter; `compliance-trestle` as optional validator |
| SARIF 2.1.0 | scanner in / out | `sarif` connector + exporter |
| CycloneDX 1.5+ / VEX | SBOM storage, exploitability statements | stored verbatim |
| OCSF | finding vocabulary reference | informs field names; not a wire format yet |
| genesis-gates contracts | `DeliveryManifest`, `EvidencePackage` | embedded verbatim in `Deployment` |

## Tier 3 — build

No OSS exists, or the closest OSS is close-but-wrong.

- Canonical model, fingerprints, asset reconciliation (`cernus-core`)
- Deterministic policy engine + (Phase 3) AI rule proposal with approval
- Continuous control evaluation, evidence freshness (Phase 2)
- POA&M projection from findings × controls × SLA × evidence (Phase 2)
- Append-only evidence ledger + verified closure (server)
- Autonomy levels + Genesis executor adapter (Phase 4)
- Posture UI

## Deliberately not embedded

- **DefectDojo / Faraday** — engagement-centric data model, heavy monoliths,
  no deployment/boundary/control relationships. A DefectDojo *importer*
  connector is planned so existing shops can feed Cernus.
- **GovReady-Q / OpenRMF** — document-centric; OSCAL interop covers the need.
- **Lula** — OSCAL-native control validation; planned as a *validation
  provider* plugin in Phase 2, not the core engine.
- **OPA / Rego** — fine evaluator, but the value is the rule library +
  learning loop + approval. Revisit at Phase 3.
- **Any SIEM** — Cernus consumes security-relevant events; it never stores or
  searches logs.

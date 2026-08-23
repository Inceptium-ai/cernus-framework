# Cernus architecture

Cernus is the Day-2 layer of the Inceptium family. Genesis proves a change was
safe to ship at T₀ (delivery gates → `EvidencePackage`). Cernus owns T₀+1 day
onward: new CVEs against the same SBOM, posture of the running system, control
evidence aging out, the POA&M a regulated customer must produce, and the
governed path to fixing what it finds.

## Three layers

```
┌─ Observe (open source) ────────────────────────────────────────────────┐
│ Connectors + scanners wrap tools you already run and normalize their   │
│ output into the canonical model. trivy · syft · sarif · genesis · …    │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   ▼  IngestBatch (validated)
┌─ Understand (open engine, commercial service) ─────────────────────────┐
│ Dedup by fingerprint · asset reconciliation · deterministic policy     │
│ (PolicySet → Decision with reason) · control evaluation · posture      │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   ▼  Decisions · ControlResults · EvidenceRecords
┌─ Act (commercial) ─────────────────────────────────────────────────────┐
│ Autonomy lanes (deterministic / AI-assisted / human) · Genesis executor │
│ adapter · verified closure (rescan → fixed + evidence) · POA&M / OSCAL │
└────────────────────────────────────────────────────────────────────────┘
```

## Canonical model

```
System ─┬─ Deployment ─┬─ Asset ─── Finding ─── Decision
        │   (manifest,  │  (image,    (vuln,      (rule | model | human,
        │    evidence)  │   service)   sast,…)     reason, autonomy)
        │               └─ Sbom
        └─ ControlResult ─── EvidenceRecord (append-only, hashed)
```

- **System** — the unit of ownership and authorization (a Genesis project; an
  ATO boundary member).
- **Deployment** — one act of putting a system into an environment; carries
  the Genesis `DeliveryManifest` and `EvidencePackage` verbatim so Day-2
  findings can be compared to what was proven at deploy time.
- **Asset** — something that carries findings. Identity is deterministic
  (`Asset.id_for(kind, facet)`); for images the facet is the normalized
  reference (`python:3.11-slim`) so trivy, syft, and the deploy record
  reconcile to one asset; the digest rides along as an identifier.
- **Finding** — superset of the genesis-gates finding. `fingerprint` is a
  sha256 over (tool, vuln/rule id, purl or location, asset) — stable across
  rescans, title rewording, and severity changes.
- **Decision** — exactly one per finding per policy evaluation. Actor is
  `rule`, `model`, or `human`; always carries a reason. `unmatched` is the
  review queue.
- **EvidenceRecord** — immutable, hashed. Scans, gate runs, SBOMs, decisions,
  deploys, rescans, approvals, exceptions, control evaluations.

Contracts live in `packages/cernus-core/contracts/*.schema.json` (Draft
2020-12, `additionalProperties: false`, additive-only within `cernus.ai/v0`).

## Verified closure

Ingest is idempotent on fingerprints. When a tool rescans an asset and a
previously-open finding is absent from the new report, the server marks it
`fixed` and writes a `rescan` evidence record pointing at the finding. A
finding that reappears is reopened. This is step one of the closure chain
(change → gates → deploy → rescan → evidence); steps two and three land with
the Genesis executor adapter.

## The Genesis seam

Genesis writes `<workspace>/.genesis-work/manifest.yaml` and stores the
`EvidencePackage` in its database. The `genesis` connector accepts either, or a
workspace directory that also contains `deployment.json` (project id,
environment, preview url, image refs + digests) written by the Genesis
post-deploy hook. From those it builds the System, the Deployment, one asset
per deployed image, and one finding per gate finding — so the first thing
Cernus knows about an app is exactly what Genesis proved about it.

## Policy engine

Lineage: Auto-Triage's criteria library → versioned configuration → rule.
Criteria are predicates over dotted paths into the finding joined with its
asset and system; rules AND criteria and name an action; a PolicySet is a
versioned, approvable, priority-ordered bundle; first match wins. Phase 3 adds
the learning loop: unmatched findings go to a model with a rubric, the model
proposes a rule, a human approves it, and the rule joins the library — so the
system becomes more deterministic and cheaper over time.

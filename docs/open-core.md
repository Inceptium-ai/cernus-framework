# Open core

Cernus follows the Genesis model: the private monorepo
(`Inceptium-ai/Cernus`) is the source of truth; the public repo
(`Inceptium-ai/cernus-framework`) is a verified snapshot assembled from an
explicit allowlist by `scripts/oss_sync.py`. Nothing is public unless it is
listed there.

## The razor

**Open source gets data into one shape and out in open formats. Enterprise
decides, acts, and proves.**

| Open (Apache-2.0) | Commercial |
|---|---|
| Contracts / JSON Schemas | Policy service with AI rule proposal + approval workflow |
| Canonical model, fingerprinting, dedup | Deployment topology graph, exposure paths, authorization boundaries |
| Plugin SDK + first-party connectors/scanners/exporters | Continuous control evaluation, evidence freshness, per-system posture |
| Deterministic policy engine (evaluate a PolicySet) | FedRAMP ConMon, POA&M workflow, deviations, ATO readiness |
| OSCAL / SARIF export | Governed remediation: autonomy levels, Genesis executor adapter, verified closure |
| `cernus` CLI | Evidence ledger service, multi-tenant, RBAC, SSO, dashboards |

## The iron rule

The dependency arrow points commercial → open only. `cernus-core`,
`cernus-plugins`, and `cernus-cli` never import `cernus_server`.
`packages/cernus-core/tests/test_oss_boundary.py` fails the whole suite on a
reverse import, and `oss_sync.py verify` greps the assembled tree again.

## Sync stages

1. **assemble** — copy `ALLOW` paths into `build/oss`, applying `RENAMES`
   (`oss/README.md` → `README.md`, `oss/workflows` → `.github/workflows`).
2. **verify** — gitleaks over the assembled tree; boundary grep; `uv sync` and
   the full OSS test suite + ruff run *inside* the extracted tree with its own
   workspace root, proving the public packages are self-contained.
3. **publish** — rsync into a checkout of the public repo and commit with a
   `Cernus-Monorepo-Rev: <sha>` trailer. Push is always manual.

## Compatibility surface

The JSON Schemas in `packages/cernus-core/contracts/` are the contract.
Additive-only within a major (`cernus.ai/v0`): new optional fields are fine;
renames, removals, and enum narrowing are not.

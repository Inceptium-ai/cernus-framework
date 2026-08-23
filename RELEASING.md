# Releasing Cernus

All four packages — `cernus-core`, `cernus-plugins`, `cernus-cli`, and the
`cernus` meta-package — version and release **in lockstep**: one `v*` tag on
this repository (`Inceptium-ai/cernus-framework`) publishes them all at the
same version.

Releases run from this public snapshot repo, not the monorepo: the tag must be
pushed here, after an `oss_sync` publish has landed the code.

## Setup status: ✅ complete (v0.1.0, 2026-08-23)

All four projects exist on PyPI with **trusted publishing** configured
(GitHub OIDC — no stored tokens): each project's publisher is
`Inceptium-ai/cernus-framework` · workflow `release.yml` · environment `pypi`,
and the `pypi` environment exists on the GitHub repo. Every release from here
on is fully automated by the tag push below.

<details>
<summary>How the first release was bootstrapped (for the record)</summary>

PyPI requires every **pending** publisher (for a not-yet-existing project) to
have a *unique* configuration, so four identical entries can't be
pre-registered from one repo (learned on the Tabella release). The first
release was uploaded with a one-time account-scoped API token (`uv build` per
package + `uv publish`), revoked immediately after; per-project trusted
publishers were added once the projects existed.

</details>

## Cutting a release

1. In the **monorepo**: bump `version` in all four `packages/*/pyproject.toml`
   (same value) and the three `__version__` strings
   (`cernus_core/__init__.py`, `cernus_plugins/__init__.py`,
   `cernus_cli/__init__.py`, `cernus/__init__.py`); update `CHANGELOG.md`.
2. `make oss-build`, commit, and publish the snapshot
   (`make oss-publish DIR=../cernus-framework`), push it.
3. Tag **this repo** and push the tag:

   ```bash
   git tag v0.1.0
   git push origin main --tags
   ```

4. The `Release` workflow lints, tests, builds all four packages, and publishes
   via trusted publishing. Verify at `https://pypi.org/project/cernus-cli/`.

## Verifying locally before tagging

```bash
uv run ruff check packages && uv run pytest -q
rm -rf dist && for p in cernus-core cernus-plugins cernus-cli cernus; do uv build --package "$p"; done
uv run python -m zipfile -l dist/cernus_core-*.whl | grep -c "contracts/"   # schemas travel with the wheel
```

## Naming

The bare name `cernus` is ours (meta-package that depends on `cernus-cli`).
The install entry point we document is `pip install cernus-cli`; the console
command is `cernus` either way.

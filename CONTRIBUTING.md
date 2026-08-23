# Contributing

Thanks for helping. Cernus is developed in a private monorepo and published
here as a verified snapshot; pull requests are welcome and will be applied
upstream with attribution.

- `uv sync` · `uv run pytest -q` · `uv run ruff check packages`
- Contracts in `packages/cernus-core/contracts` are the source of truth.
  Schema changes are additive-only within a major version.
- New tool support belongs in a plugin (`cernus.connectors` /
  `cernus.scanners` / `cernus.exporters` entry points). Wrap the tool; don't
  re-implement it.
- Fixtures must be real tool output, trimmed, with no secrets.

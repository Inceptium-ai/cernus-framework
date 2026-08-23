# Agent instructions — Cernus Framework (public snapshot)

- Three packages: `cernus-core` (contracts, model, plugin SDK, policy engine),
  `cernus-plugins` (first-party plugins), `cernus-cli`.
- `uv sync` then `uv run pytest -q` and `uv run ruff check packages`.
- Contracts (`packages/cernus-core/contracts/*.schema.json`) are the SSOT;
  additive-only within `cernus.ai/v0`.
- Wrap tools as plugins; never re-implement a scanner.
- This tree is a published snapshot — upstream changes land via the monorepo.

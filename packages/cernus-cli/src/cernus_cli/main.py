"""`cernus` — the command line for the open core.

Commands are thin: each one is a few lines over ``cernus_core`` so the same
behaviour is reachable from the server and from tests.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import cernus_plugins  # noqa: F401  — registers first-party plugins
import yaml
from cernus_core import __version__, validate
from cernus_core.ingest import ingest_path, normalize
from cernus_core.model import IngestBatch, Severity, Source
from cernus_core.plugins import (
    CONNECTOR_REGISTRY,
    EXPORTER_REGISTRY,
    SCANNER_REGISTRY,
    exporter_for_format,
    get_scanner,
    load_plugins,
    plugin_errors,
)
from cernus_core.policy import PolicySet

from . import batchio

OUT_DIR = Path(".cernus")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 2
    try:
        return int(args.func(args) or 0)
    except (LookupError, ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cernus", description="Runtime security and continuous assurance."
    )
    p.add_argument("--version", action="version", version=f"cernus {__version__}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("doctor", help="Show available scanners, plugins, and contract location")
    s.set_defaults(func=cmd_doctor)

    s = sub.add_parser("plugins", help="List registered connectors, scanners, exporters")
    s.set_defaults(func=cmd_plugins)

    s = sub.add_parser("ingest", help="Normalize a tool output file/dir into an IngestBatch")
    s.add_argument("path", type=Path)
    s.add_argument("--connector", default="auto")
    s.add_argument(
        "-o", "--output", type=Path, default=None, help="default: .cernus/<name>.batch.json"
    )
    s.add_argument("--system-id")
    s.add_argument("--deployment-id")
    s.add_argument("--asset-id")
    s.add_argument(
        "--environment",
        choices=["production", "staging", "development", "test", "ephemeral", "unknown"],
    )
    s.add_argument("--raw", action="store_true", help="keep tool-native records in the output")
    s.set_defaults(func=cmd_ingest)

    s = sub.add_parser(
        "scan", help="Run installed scanners against a target and normalize the result"
    )
    s.add_argument("kind", choices=["image", "fs", "sbom"])
    s.add_argument("target")
    s.add_argument("--scanners", default="syft,trivy", help="comma list; default syft,trivy")
    s.add_argument("-o", "--output", type=Path, default=None)
    s.add_argument("--workdir", type=Path, default=OUT_DIR / "scans")
    s.add_argument("--system-id")
    s.add_argument("--deployment-id")
    s.add_argument("--environment", default=None)
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("validate", help="Validate a Cernus JSON document against its contract")
    s.add_argument("path", type=Path)
    s.set_defaults(func=cmd_validate)

    s = sub.add_parser("triage", help="Evaluate a PolicySet against a batch; write Decisions")
    s.add_argument("batch", type=Path)
    s.add_argument("--policy", type=Path, required=True, help="PolicySet YAML/JSON")
    s.add_argument("-o", "--output", type=Path, default=None)
    s.set_defaults(func=cmd_triage)

    s = sub.add_parser("export", help="Export a batch in an external format")
    s.add_argument("batch", type=Path)
    s.add_argument("--format", required=True, help="sarif | oscal-poam")
    s.add_argument("-o", "--output", type=Path, required=True)
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("merge", help="Merge several batches into one (dedups findings)")
    s.add_argument("batches", nargs="+", type=Path)
    s.add_argument("-o", "--output", type=Path, required=True)
    s.set_defaults(func=cmd_merge)

    s = sub.add_parser("push", help="POST a batch to a Cernus server")
    s.add_argument("batch", type=Path)
    s.add_argument("--server", required=True)
    s.add_argument("--token", default=None)
    s.set_defaults(func=cmd_push)
    return p


# ── commands ────────────────────────────────────────────────────────────────


def cmd_doctor(args: argparse.Namespace) -> int:
    from cernus_core.contracts import contracts_dir

    load_plugins()
    print(f"cernus {__version__}")
    print(f"contracts: {contracts_dir()}")
    print("scanners:")
    for name, cls in sorted(SCANNER_REGISTRY.items()):
        sc = cls()
        state = (
            f"ok ({sc.version() or 'version unknown'})"
            if sc.available()
            else f"missing `{cls.binary}`"
        )
        print(f"  {name:<12} {state}")
    print(f"connectors: {', '.join(sorted(CONNECTOR_REGISTRY)) or '(none)'}")
    formats = sorted(f for c in EXPORTER_REGISTRY.values() for f in c.formats)
    print(f"exporters:  {', '.join(formats) or '(none)'}")
    _print_plugin_errors()
    return 0


def cmd_plugins(args: argparse.Namespace) -> int:
    load_plugins()
    for label, reg in (
        ("connectors", CONNECTOR_REGISTRY),
        ("scanners", SCANNER_REGISTRY),
        ("exporters", EXPORTER_REGISTRY),
    ):
        print(f"{label}:")
        for name, cls in sorted(reg.items()):
            print(f"  {name:<12} {cls.description}")
    _print_plugin_errors()
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    ctx = {
        k: v
        for k, v in vars(args).items()
        if k in {"system_id", "deployment_id", "asset_id", "environment"} and v
    }
    batch = ingest_path(args.path, connector=args.connector, **ctx)
    out = args.output or OUT_DIR / f"{args.path.stem}.batch.json"
    batchio.write(batch, out, include_raw=args.raw)
    _report(batch, out)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    load_plugins()
    merged = IngestBatch(source=Source(tool="cernus", version=__version__, connector="scan"))
    ctx = {
        k: v
        for k, v in vars(args).items()
        if k in {"system_id", "deployment_id", "environment"} and v
    }
    asset_id: str | None = None
    ran = 0
    for name in [s.strip() for s in args.scanners.split(",") if s.strip()]:
        scanner = get_scanner(name)
        if args.kind not in scanner.targets:
            continue
        if not scanner.available():
            print(f"skip {name}: `{scanner.binary}` not installed", file=sys.stderr)
            continue
        print(f"running {name} {args.kind} {args.target} …", file=sys.stderr)
        result = scanner.scan(args.kind, args.target, args.workdir)
        if result.returncode != 0 or result.output_path is None:
            print(
                f"{name} failed (exit {result.returncode}): {result.stderr.strip()[-500:]}",
                file=sys.stderr,
            )
            continue
        part = ingest_path(
            result.output_path,
            connector=result.connector or "auto",
            **ctx,
            **({"asset_id": asset_id} if asset_id else {}),
        )
        if asset_id is None and part.assets:
            asset_id = part.assets[0].id  # later scanners attach to the same asset
        merged.extend(part)
        ran += 1
    if ran == 0:
        print("no scanner ran", file=sys.stderr)
        return 1
    normalize(merged)
    out = args.output or OUT_DIR / f"{_slug(args.target)}.batch.json"
    batchio.write(merged, out)
    _report(merged, out)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    doc = _load_any(args.path)
    errors = validate(doc)
    if errors:
        print(f"✗ {args.path}: {len(errors)} error(s)")
        for e in errors[:50]:
            print(f"  {e}")
        return 1
    print(f"✓ {args.path}: valid {doc.get('kind')}")
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    batch = batchio.read(args.batch)
    policy = PolicySet.from_dict(_load_any(args.policy))
    assets = {a.id: a for a in batch.assets}
    systems = {s.id: s for s in batch.systems}
    decisions = policy.evaluate_all(batch.findings, assets, systems)
    out = args.output or args.batch.with_suffix(".decisions.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps([d.to_dict() for d in decisions], indent=2))
    by_action: dict[str, int] = {}
    for d in decisions:
        by_action[d.action] = by_action.get(d.action, 0) + 1
    print(
        f"policy {policy.name} v{policy.version} ({policy.status}) "
        f"over {len(decisions)} findings → {out}"
    )
    for k, v in sorted(by_action.items(), key=lambda kv: -kv[1]):
        print(f"  {k:<14}{v}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    batch = batchio.read(args.batch)
    exporter = exporter_for_format(args.format)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    written = exporter.export(args.format, batch, args.output)
    print(f"wrote {args.format} → {written}")
    return 0


def cmd_merge(args: argparse.Namespace) -> int:
    merged = IngestBatch(source=Source(tool="cernus", version=__version__, connector="merge"))
    for p in args.batches:
        merged.extend(batchio.read(p))
    normalize(merged)
    batchio.write(merged, args.output)
    _report(merged, args.output)
    return 0


def cmd_push(args: argparse.Namespace) -> int:
    import urllib.error
    import urllib.request

    body = args.batch.read_bytes()
    req = urllib.request.Request(
        args.server.rstrip("/") + "/api/ingest",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            **({"Authorization": f"Bearer {args.token}"} if args.token else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - user-supplied server
            print(resp.read().decode())
    except urllib.error.URLError as exc:
        print(f"push failed: {exc}", file=sys.stderr)
        return 1
    return 0


# ── helpers ─────────────────────────────────────────────────────────────────


def _report(batch: IngestBatch, out: Path) -> None:
    s = batch.summary()
    sev = " ".join(f"{k[0].upper()}:{v}" for k, v in s["by_severity"].items() if v)
    print(
        f"{s['systems']} systems, {s['deployments']} deployments, {s['assets']} assets, "
        f"{s['findings']} findings [{sev or '-'}], {s['sboms']} sboms, "
        f"{s['evidence']} evidence → {out}"
    )
    _print_plugin_errors()


def _print_plugin_errors() -> None:
    if plugin_errors:
        print(f"{len(plugin_errors)} plugin problem(s):", file=sys.stderr)
        for e in plugin_errors:
            print(f"  {e}", file=sys.stderr)


def _load_any(path: Path) -> dict[str, Any]:
    text = path.read_text()
    return yaml.safe_load(text) if path.suffix in {".yaml", ".yml"} else json.loads(text)


def _slug(s: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in s).strip("-")[:80]


__all__ = ["main", "Severity"]

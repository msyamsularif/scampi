"""Slash command and operator CLI.

Read-only by default: everything here reports state or moderates the report
database. Checks always run through the model and the tools, so the
deterministic core stays in one place. The CLI is the operator's moderation
and curation surface (spec: CLI-only for v1).
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

from ..about import __version__
from ..checks import eval as eval_mod
from ..checks import patterns as patterns_mod
from ..config import settings as settings_mod
from ..store import reports, store
from . import runtime

_STATUS_HELP = "Perintah: /scampi status (kesehatan layanan) atau /scampi help."


# --------------------------------------------------------------------------- #
# Slash command (works in CLI and gateway sessions)
# --------------------------------------------------------------------------- #

def handle(raw_args: str) -> str:
    args = (raw_args or "").strip().lower()
    if args in ("", "status"):
        return status_text()
    if args == "help":
        return _STATUS_HELP
    return f"Perintah tidak dikenal. {_STATUS_HELP}"


def status_text() -> str:
    config = settings_mod.load()
    source = runtime.settings_source()

    with store.connection() as conn:
        checks = conn.execute("SELECT COUNT(*) AS n FROM checks").fetchone()["n"]
        report_count = conn.execute("SELECT COUNT(*) AS n FROM reports").fetchone()["n"]
        confirmed = conn.execute(
            "SELECT COUNT(*) AS n FROM reports WHERE status='confirmed'"
        ).fetchone()["n"]

    pattern_count = len(patterns_mod.load_patterns())
    safe_browsing = bool(os.environ.get("SAFE_BROWSING_API_KEY", "").strip())
    urlhaus = bool(os.environ.get("URLHAUS_AUTH_KEY", "").strip())

    lines = [
        "🦐 Scampi — status",
        f"Versi plugin        : {__version__}",
        f"Pola penipuan aktif : {pattern_count}",
        f"Mengecek            : {'aktif' if config['network_enabled'] else 'dimatikan (offline)'}",
        f"Google Safe Browsing: {'aktif' if safe_browsing else 'nonaktif (key belum diisi)'}",
        f"URLhaus             : {'aktif' if urlhaus else 'nonaktif (key belum diisi)'}",
        f"Pengecekan tercatat  : {checks}",
        f"Laporan komunitas   : {report_count} ({confirmed} terkonfirmasi)",
        f"Retensi bukti       : {config['retention_days']} hari",
        f"Batas cek/jam       : {config['rate_limit_checks_per_hour']}",
        f"Sumber pengaturan   : {source['source']} ({source['path']})",
    ]
    warning = source.get("warning")
    if warning:
        lines.append(f"⚠️  {warning}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI: hermes scampi <subcommand>
# --------------------------------------------------------------------------- #

def setup_cli(subparser: argparse.ArgumentParser) -> None:
    sub = subparser.add_subparsers(dest="scampi_command")

    sub.add_parser("status", help="Show plugin health and data counts")

    patterns_cmd = sub.add_parser("patterns", help="Scam-pattern database utilities")
    patterns_sub = patterns_cmd.add_subparsers(dest="patterns_command")
    patterns_sub.add_parser("list", help="List loaded patterns")
    patterns_sub.add_parser("validate", help="Validate every pattern file")

    reports_cmd = sub.add_parser("reports", help="Community report moderation")
    reports_sub = reports_cmd.add_subparsers(dest="reports_command")
    list_cmd = reports_sub.add_parser("list", help="List recent reports")
    list_cmd.add_argument("--status", default=None)
    list_cmd.add_argument("--limit", type=int, default=20)
    for name, help_text in (
        ("show", "Show one report"),
        ("confirm", "Moderate: mark a report confirmed"),
        ("reject", "Moderate: mark a report rejected"),
        ("dispute", "Moderate: mark a report disputed"),
    ):
        item = reports_sub.add_parser(name, help=help_text)
        item.add_argument("report_id", type=int)

    retention = sub.add_parser("retention", help="Retention maintenance")
    retention_sub = retention.add_subparsers(dest="retention_command")
    purge = retention_sub.add_parser("purge", help="Delete artifacts older than the retention window")
    purge.add_argument("--days", type=int, default=None)

    eval_cmd = sub.add_parser("eval", help="Offline evaluation harness")
    eval_sub = eval_cmd.add_subparsers(dest="eval_command")
    run_cmd = eval_sub.add_parser("run", help="Run the labeled corpus")
    run_cmd.add_argument("--dataset", required=True, help="Path to a JSONL corpus")
    run_cmd.add_argument("--limit", type=int, default=None)
    run_cmd.add_argument("--network", action="store_true", help="Allow provider calls during evaluation")

    subparser.set_defaults(func=handle_cli)


def handle_cli(args: Any) -> int:
    command = getattr(args, "scampi_command", None)
    if command == "status":
        print(status_text())
        return 0
    if command == "patterns":
        return _patterns_cli(getattr(args, "patterns_command", None))
    if command == "reports":
        return _reports_cli(args)
    if command == "retention":
        return _retention_cli(args)
    if command == "eval":
        return _eval_cli(args)
    print("Penggunaan: hermes scampi {status|patterns|reports|retention|eval}")
    return 1


# --------------------------------------------------------------------------- #
# Subcommand implementations
# --------------------------------------------------------------------------- #

def _patterns_cli(subcommand: str | None) -> int:
    if subcommand == "validate":
        return _patterns_validate()
    patterns = patterns_mod.load_patterns()
    if not patterns:
        print("Tidak ada pola yang termuat.")
        return 1
    for pattern in patterns:
        reviewed = f"review: {pattern.last_reviewed_at}" if pattern.last_reviewed_at else "review: -"
        print(f"{pattern.id:32s} {pattern.strength:6s} {pattern.name}  ({reviewed})")
    print(f"\n{len(patterns)} pola termuat.")
    return 0


def _patterns_validate() -> int:
    directory = patterns_mod.DEFAULT_DIR
    if not directory.is_dir():
        print(f"Direktori pola tidak ditemukan: {directory}")
        return 1

    try:
        import yaml  # type: ignore
    except ImportError:  # pragma: no cover
        print("PyYAML tidak tersedia; tidak bisa memvalidasi pola.")
        return 1

    ok = 0
    problems = 0
    for path in sorted(directory.glob("*.yaml")):
        try:
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except Exception as exc:
            print(f"✗ {path.name}: tidak bisa dibaca ({exc.__class__.__name__})")
            problems += 1
            continue
        errors = patterns_mod.validate(data)
        if errors:
            print(f"✗ {path.name}: {'; '.join(errors)}")
            problems += 1
        else:
            ok += 1

    print(f"\n{ok} pola valid, {problems} bermasalah.")
    return 0 if problems == 0 else 1


def _reports_cli(args: Any) -> int:
    subcommand = getattr(args, "reports_command", None)
    if subcommand == "list":
        with store.connection() as conn:
            rows = reports.list_reports(conn, status=args.status, limit=args.limit)
        if not rows:
            print("Tidak ada laporan.")
            return 0
        for row in rows:
            print(
                f"#{row['id']:<5} {row['entity_type']:8s} {row['masked_value']:>12s} "
                f"{row['bank']:6s} {row['status']:11s} {row['created_at']}"
            )
        return 0

    report_id = getattr(args, "report_id", None)
    if report_id is None:
        print("Penggunaan: hermes scampi reports {list|show|confirm|reject|dispute}")
        return 1

    if subcommand == "show":
        with store.connection() as conn:
            report = reports.get_report(conn, report_id)
        if report is None:
            print(f"Laporan #{report_id} tidak ditemukan.")
            return 1
        print(f"#{report['id']} [{report['status']}] {report['entity_type']} "
              f"bank={report['bank'] or '-'} pattern={report['pattern_id'] or '-'}")
        print(f"  dibuat   : {report['created_at']} (update: {report['updated_at']})")
        if report["note"]:
            print(f"  catatan  : {report['note']}")
        for evidence in report["evidence"]:
            print(f"  bukti    : {evidence['ref']} ({evidence['created_at']})")
        return 0

    if subcommand in ("confirm", "reject", "dispute"):
        with store.connection() as conn:
            updated = reports.set_status(conn, report_id, subcommand)
        if not updated:
            print(f"Laporan #{report_id} tidak ditemukan.")
            return 1
        print(f"Laporan #{report_id} → {subcommand}.")
        return 0

    print("Penggunaan: hermes scampi reports {list|show|confirm|reject|dispute}")
    return 1


def _retention_cli(args: Any) -> int:
    if getattr(args, "retention_command", None) != "purge":
        print("Penggunaan: hermes scampi retention purge [--days N]")
        return 1
    config = settings_mod.load()
    days = args.days if args.days is not None else config["retention_days"]
    with store.connection() as conn:
        counts = store.purge(conn, days, evidence_dir=runtime.evidence_dir())
    summary = ", ".join(f"{key}: {value}" for key, value in counts.items() if value)
    print(f"Purge retensi ({days} hari) selesai. {summary or 'Tidak ada yang perlu dihapus.'}")
    return 0


def _eval_cli(args: Any) -> int:
    if getattr(args, "eval_command", None) != "run":
        print("Penggunaan: hermes scampi eval run --dataset <path.jsonl> [--limit N] [--network]")
        return 1
    dataset = Path(args.dataset).expanduser()
    if not dataset.is_file():
        print(f"Dataset tidak ditemukan: {dataset}")
        return 1
    metrics = eval_mod.run(dataset, limit=args.limit, network=bool(args.network))
    print(eval_mod.format_report(metrics))
    return 0

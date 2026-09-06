"""Command-line entrypoint for reproducible MalWeave workflows."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
from pathlib import Path
import sys

from dotenv import load_dotenv

from malweave.config import CONFIGS_DIR, PROJECT_ROOT
from malweave.data.dataset_config import DatasetConfigError, load_rands_dataset_config
from malweave.data.rands import RandsDataError, inspect_rands, write_rands_manifest
from malweave.data.rands_pilot import (
    RandsPilotError,
    build_rands_pilot,
    load_rands_pilot_config,
    pilot_console_summary,
    write_rands_pilot_outputs,
)

DEFAULT_RANDS_CONFIG = CONFIGS_DIR / "datasets" / "rands-raw-2026.yaml"
DEFAULT_RANDS_PILOT_CONFIG = CONFIGS_DIR / "experiments" / "lmlm-rands-pilot.yaml"
DOTENV_PATH = PROJECT_ROOT / ".env"


def _load_project_environment(path: Path | None = None) -> None:
    """Load machine-local settings without overriding the caller's environment."""
    load_dotenv(dotenv_path=path or DOTENV_PATH, override=False)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="malweave", description="MalWeave research tooling.")
    commands = parser.add_subparsers(dest="command", required=True)
    data = commands.add_parser("data", help="Inspect and prepare research datasets.")
    data_commands = data.add_subparsers(dest="data_command", required=True)

    inspect = data_commands.add_parser("inspect", help="Audit a local dataset without mutation.")
    inspect.add_argument("--dataset", choices=("rands",), required=True)
    inspect.add_argument("--config", type=Path, default=DEFAULT_RANDS_CONFIG)
    inspect.add_argument("--root", type=Path, default=None)
    inspect.add_argument(
        "--verify-hashes",
        choices=("none", "sample", "all"),
        default="none",
        help="Hash no files, one deterministic file per shard, or the full corpus.",
    )
    inspect.add_argument(
        "--summary",
        type=Path,
        default=None,
        help="Optional aggregate JSON output; safe summaries contain no sample hashes.",
    )
    inspect.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="Optional local CSV inventory containing sample hashes; never commit it.",
    )

    pilot = data_commands.add_parser(
        "pilot", help="Build and fully verify a deterministic local RanDS pilot manifest."
    )
    pilot.add_argument("--dataset", choices=("rands",), required=True)
    pilot.add_argument("--config", type=Path, default=DEFAULT_RANDS_CONFIG)
    pilot.add_argument("--experiment", type=Path, default=DEFAULT_RANDS_PILOT_CONFIG)
    pilot.add_argument("--root", type=Path, default=None)
    pilot.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Local pilot CSV containing sample hashes; must remain uncommitted.",
    )
    pilot.add_argument(
        "--summary",
        type=Path,
        required=True,
        help="Aggregate local JSON evidence; safe because it contains no sample hashes.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit status."""
    parser = _parser()
    args = parser.parse_args(argv)
    _load_project_environment()

    try:
        if args.command == "data" and args.data_command == "inspect":
            config = load_rands_dataset_config(args.config)
            root = config.resolve_root(args.root)
            summary, metadata, present_shas = inspect_rands(
                config, root, hash_mode=args.verify_hashes
            )
            rendered = json.dumps(summary, indent=2, sort_keys=True)
            print(rendered)

            if args.summary is not None:
                args.summary.parent.mkdir(parents=True, exist_ok=True)
                args.summary.write_text(rendered + "\n", encoding="utf-8")
            if args.manifest is not None:
                write_rands_manifest(args.manifest, config, metadata, present_shas)
            return 0 if summary["contract"]["passed"] else 1
        if args.command == "data" and args.data_command == "pilot":
            dataset_config = load_rands_dataset_config(args.config)
            pilot_config = load_rands_pilot_config(args.experiment)
            root = dataset_config.resolve_root(args.root)
            build = build_rands_pilot(dataset_config, pilot_config, root)
            write_rands_pilot_outputs(build, args.manifest, args.summary)
            print(json.dumps(pilot_console_summary(build.summary), indent=2, sort_keys=True))
            return 0 if build.passed else 1
    except (DatasetConfigError, RandsDataError, RandsPilotError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    parser.error("Unsupported command.")
    return 2

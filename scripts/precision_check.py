#!/usr/bin/env python3
"""Measure detection precision against real artifacts.

The harness the brief calls for at M2, in its first useful form. Point it at a
real-world artifact you believe is clean and it reports what the rule pack
fires on. Every hit is a candidate false positive to be explained or fixed.

    uv run python scripts/precision_check.py var/runs/samples/MoVaPuCo_4.3.zip

Rules are deliberately recall-first, but that is not a licence for a rule that
matches every 40-character base64 window. The line: a rule may be noisy in a
way a human can dismiss quickly; it may not bury the report.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from core.rules import load_rule_pack, scan_file  # noqa: E402
from core.unpack import ExtractionBudget, Extractor  # noqa: E402

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"


def main() -> int:
    parser = argparse.ArgumentParser(description="Detection precision check")
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--rule", help="show every hit for one rule")
    parser.add_argument("--context", type=int, default=0, help="context chars to print")
    parser.add_argument("--top-files", type=int, default=8)
    args = parser.parse_args()

    if not args.artifact.is_file():
        raise SystemExit(f"{args.artifact} not found")

    pack = load_rule_pack(REPO_ROOT / "detections")
    workdir = Path(tempfile.mkdtemp(prefix="precision-"))

    try:
        size = args.artifact.stat().st_size
        extraction = Extractor(ExtractionBudget.for_input(size)).extract_tree(
            args.artifact, workdir, root_name=args.artifact.name
        )

        targets: list[tuple[str, Path]] = [(args.artifact.name, args.artifact)]
        targets += [(n.path_in_tree, workdir / n.relative_path) for n in extraction.nodes]

        by_rule: Counter[str] = Counter()
        by_file: Counter[str] = Counter()
        samples: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
        scanned = 0

        for path_in_tree, path in targets:
            if not path.is_file():
                continue
            scanned += 1
            for match in scan_file(str(path), pack):
                by_rule[match.rule_id] += 1
                by_file[path_in_tree] += 1
                if len(samples[match.rule_id]) < 400:
                    samples[match.rule_id].append((match.masked, match.context, path_in_tree))

        total = sum(by_rule.values())
        print(f"\n{BOLD}{args.artifact.name}{RESET}  {size:,} bytes")
        print(f"{scanned} files scanned ({len(extraction.nodes)} extracted)")
        print(f"{BOLD}{total:,} raw matches{RESET}\n")

        if args.rule:
            for masked, context, where in samples.get(args.rule, []):
                print(f"  {masked}")
                print(f"    {DIM}{where}{RESET}")
                if args.context:
                    flat = " ".join(context.split())[: args.context]
                    print(f"    {DIM}{flat}{RESET}")
            return 0

        print(f"{BOLD}by rule{RESET}")
        for rule_id, count in by_rule.most_common():
            share = 100 * count / total if total else 0
            bar = "#" * int(share / 2)
            print(f"  {count:>6}  {share:>5.1f}%  {rule_id:<34} {DIM}{bar}{RESET}")

        print(f"\n{BOLD}by file{RESET}")
        for where, count in by_file.most_common(args.top_files):
            print(f"  {count:>6}  {where[-88:]}")

        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())

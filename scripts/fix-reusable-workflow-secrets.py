#!/usr/bin/env python3
"""Remove unsafe `secrets: inherit` from reusable-workflow callers.

The OWASP workflow uses github.token when SECURITY_REPO_TOKEN is not supplied,
so callers scanning public repositories normally do not need to forward any
repository secrets.

Exit codes:
    0: Files are compliant, or files were corrected successfully
    1: Unsafe declarations remain or a file could not be corrected
    2: Invalid invocation or missing repository root
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DEFAULT_FILES = (
    ".github/workflows/reusable-security.yml",
    "examples/caller-api.yml",
    "examples/caller-cloud-native.yml",
    "examples/caller-desktop.yml",
    "examples/caller-web.yml",
)

SECRETS_INHERIT_PATTERN = re.compile(
    r"^(?P<indent>[ \t]*)secrets:[ \t]*inherit[ \t]*(?:#.*)?$",
    flags=re.MULTILINE,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Remove unsafe 'secrets: inherit' declarations from known "
            "GitHub Actions reusable-workflow callers."
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Repository root. Defaults to the current directory.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Only check files. Do not modify them.",
    )
    parser.add_argument(
        "files",
        nargs="*",
        help=(
            "Optional repository-relative files. If omitted, the known "
            "workflow and example files are checked."
        ),
    )
    return parser.parse_args()


def remove_secrets_inherit(text: str) -> tuple[str, int]:
    corrected, replacements = SECRETS_INHERIT_PATTERN.subn("", text)

    # Avoid leaving more than two consecutive blank lines.
    corrected = re.sub(r"\n{3,}", "\n\n", corrected)

    # Preserve the conventional final newline.
    corrected = corrected.rstrip() + "\n"

    return corrected, replacements


def find_remaining_occurrences(root: Path) -> list[tuple[Path, int, str]]:
    findings: list[tuple[Path, int, str]] = []

    search_roots = [
        root / ".github",
        root / "examples",
    ]

    for search_root in search_roots:
        if not search_root.exists():
            continue

        for path in sorted(search_root.rglob("*")):
            if not path.is_file() or path.suffix not in {".yml", ".yaml"}:
                continue

            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError as exc:
                print(f"Unable to read {path}: {exc}", file=sys.stderr)
                continue

            for line_number, line in enumerate(lines, start=1):
                if re.match(
                    r"^[ \t]*secrets:[ \t]*inherit(?:[ \t]*#.*)?$",
                    line,
                ):
                    findings.append((path, line_number, line.strip()))

    return findings


def main() -> int:
    args = parse_args()
    root = args.root.resolve()

    if not root.is_dir():
        print(f"Repository root does not exist: {root}", file=sys.stderr)
        return 2

    relative_files = tuple(args.files) if args.files else DEFAULT_FILES
    changed_files: list[Path] = []
    missing_files: list[Path] = []
    unsafe_files: list[Path] = []

    for relative_name in relative_files:
        path = root / relative_name

        if not path.is_file():
            missing_files.append(path)
            print(f"SKIP: File not found: {path}")
            continue

        try:
            original = path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"ERROR: Unable to read {path}: {exc}", file=sys.stderr)
            return 1

        corrected, replacements = remove_secrets_inherit(original)

        if replacements == 0:
            print(f"OK: No secrets inheritance found in {relative_name}")
            continue

        unsafe_files.append(path)

        if args.check:
            print(
                f"UNSAFE: {relative_name} contains "
                f"{replacements} 'secrets: inherit' declaration(s)"
            )
            continue

        try:
            path.write_text(corrected, encoding="utf-8")
        except OSError as exc:
            print(f"ERROR: Unable to update {path}: {exc}", file=sys.stderr)
            return 1

        changed_files.append(path)
        print(
            f"FIXED: Removed {replacements} unsafe declaration(s) "
            f"from {relative_name}"
        )

    if args.check and unsafe_files:
        print()
        print(
            f"Check failed: {len(unsafe_files)} file(s) use "
            "'secrets: inherit'."
        )
        return 1

    remaining = find_remaining_occurrences(root)

    if remaining:
        print()
        print("ERROR: Unsafe secrets inheritance remains:")
        for path, line_number, text in remaining:
            relative = path.relative_to(root)
            print(f"  {relative}:{line_number}: {text}")
        return 1

    print()
    if changed_files:
        print(f"Successfully corrected {len(changed_files)} file(s).")
    else:
        print("No unsafe secrets inheritance remains.")

    if missing_files:
        print(
            f"Note: {len(missing_files)} expected file(s) were not present."
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
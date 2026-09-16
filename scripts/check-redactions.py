#!/usr/bin/env python3
"""Refuse to publish anything containing a never-publish value.

Every file this project generates passes through here before it is committed or published. The rules are in
scripts/lib/redact.py (structural patterns) and config/redactions.txt (the real values, git-ignored).

  scripts/check-redactions.py site/index.html data/snapshot-2026-09-16.json
  scripts/check-redactions.py --staged          # what the pre-commit hook runs
  scripts/check-redactions.py --self-test       # prove the checker still catches every configured value
  cat something | scripts/check-redactions.py -

Exit status: 0 clean, 1 something must not be published, 2 the checker itself could not run.
Findings name the rule and the line, never the value.
Reads local files only; makes no network requests.
"""
import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from redact import (EXAMPLE_FILE, LITERALS_FILE, PATTERNS, Finding,  # noqa: E402
                    RedactionError, load_literals, scan_file, scan_text)


def staged_files() -> list[Path]:
    result = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise RedactionError("git diff --cached failed; is this a git repository?")
    return [Path(name) for name in result.stdout.split("\n") if name.strip() and Path(name).is_file()]


def report(findings: list[Finding]) -> None:
    print(f"check-redactions: {len(findings)} value(s) that must not be published:\n", file=sys.stderr)
    for finding in sorted(findings, key=lambda f: (f.path, f.line, f.rule)):
        print(f"  {finding.path}:{finding.line}: {finding.rule} ({finding.hint})", file=sys.stderr)
    print("\nNothing is printed in full on purpose. Open the line to see what it is.", file=sys.stderr)


def self_test() -> int:
    """Plant every configured value in a file and assert the checker finds it. A guard nobody tests is decoration."""
    try:
        literals = load_literals()
    except RedactionError as exc:
        print(f"check-redactions: {exc}", file=sys.stderr)
        return 2

    samples: list[tuple[str, str]] = [(name, value) for name, value in literals]
    # One sample per structural pattern, assembled from fragments so this file does not itself contain the shapes the
    # checker refuses. The rules have no exemption for the checker's own source, and adding one would be the first
    # crack in the guard — so the fixtures work around the rule instead of the rule working around the fixtures.
    joined = "".join
    samples += [("gcp-project-id", joined(("example-project-", "123456"))),
                ("private-ipv4", joined(("10.", "0.0.1"))),
                ("loopback-ipv4", joined(("127.", "0.0.1"))),
                ("link-local-ipv4", joined(("169.", "254.169.254"))),
                ("cgnat-ipv4", joined(("100.", "64.0.1")))]

    failures = []
    with tempfile.TemporaryDirectory() as workdir:
        for index, (name, value) in enumerate(samples):
            planted = Path(workdir) / f"planted-{index}.txt"
            planted.write_text(f"harmless line\nthe value is {value} here\nanother harmless line\n", encoding="utf-8")
            found = scan_file(planted, literals)
            if not found:
                failures.append(f"MISSED  {name}: planted value was not caught")
            elif not any(f.line == 2 for f in found):
                failures.append(f"WRONG LINE  {name}: reported {[f.line for f in found]}, expected 2")
            for finding in found:
                if value in finding.hint:
                    failures.append(f"LEAKED  {name}: the finding printed the value it is protecting")

        clean = Path(workdir) / "clean.txt"
        clean.write_text("203.0.113.9 is a documentation address and 8.8.8.8 is public DNS.\n", encoding="utf-8")
        if scan_file(clean, literals):
            failures.append("FALSE POSITIVE  a file with only public addresses was refused")

    checked = f"{len(literals)} literal(s) from {LITERALS_FILE.name} + {len(PATTERNS)} structural pattern(s)"
    if failures:
        print(f"check-redactions: self-test FAILED ({checked})", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(f"check-redactions: self-test passed — {checked}; every planted value caught, "
          f"no value printed, public addresses allowed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*", help="files to check; '-' reads standard input")
    parser.add_argument("--staged", action="store_true", help="check the files staged for commit")
    parser.add_argument("--self-test", action="store_true", help="prove the checker catches every configured value")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.paths and not args.staged:
        parser.print_help(sys.stderr)
        return 2

    try:
        literals = load_literals()
        targets = staged_files() if args.staged else []
    except RedactionError as exc:
        print(f"check-redactions: {exc}", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    for name in args.paths:
        if name == "-":
            findings += scan_text(sys.stdin.read(), "<stdin>", literals)
            continue
        path = Path(name)
        if not path.is_file():
            print(f"check-redactions: {path} is not a file", file=sys.stderr)
            return 2
        targets.append(path)
    for path in targets:
        findings += scan_file(path, literals)

    if findings:
        report(findings)
        return 1
    count = len(targets) + (1 if "-" in args.paths else 0)
    print(f"check-redactions: {count} file(s) clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())

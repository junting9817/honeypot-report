"""The never-publish rules: what must never appear in anything this project generates.

Two kinds of rule, deliberately stored differently:

- **Patterns** live in this file. They are structural (RFC1918 ranges, loopback, link-local, the shape of a GCP
  project id) and describe a *class* of value, so committing them leaks nothing.
- **Literals** live in `config/redactions.txt`, which is git-ignored. Those are the actual addresses and identifiers
  that must never be published — the lab's own hosts and my personal addresses. Keeping them out of git is the whole
  point: a repository that never contained them can be made public without rewriting history.

`config/redactions.example.txt` documents the format with placeholder values and is tracked.

Findings are reported by rule name and location, never by value, so a failing check can be pasted into an issue, a
log or a chat window without leaking the thing it is protecting.
"""
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
LITERALS_FILE = REPO / "config" / "redactions.txt"
EXAMPLE_FILE = REPO / "config" / "redactions.example.txt"

# Structural rules. Safe to commit: they name a class of value, not a value.
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("gcp-project-id", re.compile(r"\b[a-z][a-z0-9-]{4,28}-\d{6}\b")),
    ("private-ipv4", re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")),
    ("loopback-ipv4", re.compile(r"\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")),
    ("link-local-ipv4", re.compile(r"\b169\.254\.\d{1,3}\.\d{1,3}\b")),
    ("cgnat-ipv4", re.compile(r"\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b")),
]

IPV4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int
    hint: str  # a masked fragment: enough to locate, not enough to leak


class RedactionError(Exception):
    """The rules could not be loaded."""


def mask(value: str) -> str:
    """'203.0.113.7' -> '203.0.x.x'; anything else -> first 2 characters plus length."""
    if IPV4.fullmatch(value):
        a, b, _, _ = value.split(".")
        return f"{a}.{b}.x.x"
    return f"{value[:2]}…({len(value)} chars)"


def load_literals(path: Path = LITERALS_FILE) -> list[tuple[str, str]]:
    """[(rule name, value)] from the git-ignored literals file.

    Format: one `name = value` per line; '#' starts a comment. A missing file is an error, not a silent pass —
    a checker that quietly stops checking is worse than no checker.
    """
    if not path.is_file():
        raise RedactionError(
            f"{path} not found. Copy {EXAMPLE_FILE.name} to {path.name} and fill in the real values; "
            f"it is git-ignored on purpose.")
    literals: list[tuple[str, str]] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        name, sep, value = line.partition("=")
        name, value = name.strip(), value.strip()
        if not sep or not name or not value:
            raise RedactionError(f"{path}:{number}: expected 'name = value'")
        if value.startswith("<") and value.endswith(">"):
            continue  # an unfilled placeholder from the example file
        literals.append((name, value))
    if not literals:
        raise RedactionError(f"{path} defines no values; fill it in or the check is meaningless")
    return literals


def scan_text(text: str, where: str, literals: list[tuple[str, str]]) -> list[Finding]:
    """Every never-publish value found in this text."""
    findings: list[Finding] = []
    for number, line in enumerate(text.splitlines(), 1):
        for name, value in literals:
            if value in line:
                findings.append(Finding(name, where, number, mask(value)))
        for name, pattern in PATTERNS:
            for match in pattern.finditer(line):
                findings.append(Finding(name, where, number, mask(match.group(0))))
    return findings


def scan_file(path: Path, literals: list[tuple[str, str]]) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []  # binary or unreadable: the pre-commit hook refuses those separately
    return scan_text(text, str(path), literals)

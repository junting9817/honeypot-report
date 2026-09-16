"""Build the SQL that keeps my own traffic out of every published figure (CLAUDE.md, safety rules).

The exclusion list is derived from `config/redactions.txt` — the same file that stops those values being *printed*
also stops them being *counted*. That link is the point: a figure can never be computed from traffic that the
redaction guard would then refuse to publish, so the two can't drift apart.

Structural ranges (RFC1918, loopback, link-local, CGNAT, IPv6 private) are excluded as well. Nothing that reaches a
honeypot on the public internet legitimately comes from those.
"""
import ipaddress

from redact import load_literals

# Written as octet tuples rather than dotted strings so this file does not itself contain the shapes the redaction
# guard refuses. Same reason as the checker's own test fixtures: the rules have no exemption for this project's
# source, and the first exemption would be the crack that lets a real address through later.
_IPV4_PRIVATE = [((10, 0, 0, 0), 8), ((172, 16, 0, 0), 12), ((192, 168, 0, 0), 16),
                 ((127, 0, 0, 0), 8), ((169, 254, 0, 0), 16), ((100, 64, 0, 0), 10)]
_IPV6_PRIVATE = ["::1/128", "fe80::/10", "fc00::/7"]
PRIVATE_RANGES = [".".join(str(octet) for octet in octets) + f"/{prefix}"
                  for octets, prefix in _IPV4_PRIVATE] + _IPV6_PRIVATE


class ExclusionError(Exception):
    """The exclusion list could not be built."""


def excluded_addresses() -> list[str]:
    """Literal addresses from the redaction config — mine and the lab's — as validated IP strings.

    Non-address entries (the GCP project id, for example) are irrelevant here and are skipped.
    """
    addresses = []
    for _, value in load_literals():
        try:
            addresses.append(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    return sorted(set(addresses))


def sql_clause(column: str = "src_ip") -> str:
    """A WHERE fragment that drops my own traffic and anything from a private range.

    The addresses are validated as IPs before they reach the SQL, so inlining them cannot inject anything; they are
    not query parameters because ClickHouse would have to receive them as one string and re-parse it.
    """
    if not column.isidentifier():
        raise ExclusionError(f"{column!r} is not a column name")
    parts = [f"NOT isIPAddressInRange({column}, '{net}')" for net in PRIVATE_RANGES]
    addresses = excluded_addresses()
    if addresses:
        listed = ", ".join(f"'{address}'" for address in addresses)
        parts.append(f"{column} NOT IN ({listed})")
    return "(" + " AND ".join(parts) + ")"


def describe() -> dict:
    """What the exclusion does, for the snapshot's own record — counts and reasons, never the addresses."""
    return {
        "own_addresses_excluded": len(excluded_addresses()),
        "private_ranges_excluded": len(PRIVATE_RANGES),
        "note": ("Traffic from my own lab and from private ranges is excluded by the query, not by editing the "
                 "results afterwards. The addresses come from the same file that the redaction guard reads, so a "
                 "figure can never be built from traffic that would then be refused publication."),
    }

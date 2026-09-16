#!/usr/bin/env python3
"""Turn a window of honeypot data into one versioned JSON file (docs/method.md, Phase 2).

Everything the published page will ever say comes from a snapshot: the page is generated from the file, never from a
live query, so what was published can always be reproduced and diffed.

  scripts/snapshot.py                            # the whole recorded window, to data/snapshot-<end date>.json
  scripts/snapshot.py --since 2026-09-15 --until 2026-09-16
  scripts/snapshot.py --out - --quiet            # print the JSON instead of writing it

Determinism: given the same window over the same rows, the output is byte-identical — keys sorted, no wall-clock
value anywhere in the file. That is what makes `--check-determinism` meaningful and a re-run show no diff.

My own traffic is excluded by the query (scripts/lib/exclusions.py), and the finished file is passed through the
redaction guard before it is written. Reads the lab's database read-only; makes no network requests.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts" / "lib"))
import exclusions  # noqa: E402
from chquery import QueryError, query  # noqa: E402
from redact import RedactionError, load_literals, sanitise, scan_text  # noqa: E402

TABLE = "nsm.cowrie_events"
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?)?$")


def valid_time(value: str) -> str:
    if not TIMESTAMP_RE.match(value):
        raise argparse.ArgumentTypeError(f"{value!r} is not YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
    return value


def build(top: int) -> dict:
    """Every figure the page can use, from one window. Each key names the question it answers."""
    keep = exclusions.sql_clause()
    window = "timestamp >= {since:String} AND timestamp <= {until:String}"
    scope = f"WHERE {window} AND {keep}"

    def rows(sql: str) -> list[dict]:
        return query(sql, {"since": build.since, "until": build.until})

    def one(sql: str) -> dict:
        found = rows(sql)
        return found[0] if found else {}

    snapshot: dict = {}

    snapshot["totals"] = one(f"""
        SELECT count() AS events, uniqExact(session) AS sessions, uniqExact(src_ip) AS source_addresses,
               uniqExactIf(src_country_code, src_country_code != '') AS countries,
               uniqExactIf(src_asn, src_asn != 0) AS asns,
               min(timestamp) AS first_event, max(timestamp) AS last_event
        FROM {TABLE} {scope}""")

    # Transparency, not decoration: how much was dropped, and never which addresses.
    snapshot["excluded"] = {
        **one(f"""
            SELECT count() AS events, uniqExact(session) AS sessions, uniqExact(src_ip) AS source_addresses
            FROM {TABLE} WHERE {window} AND NOT {keep}"""),
        **exclusions.describe(),
    }

    # ASN enrichment is incomplete. Publishing "top ASNs" without saying so would misreport two thirds of the traffic.
    snapshot["enrichment"] = one(f"""
        SELECT countIf(src_asn != 0) AS events_with_asn, countIf(src_asn = 0) AS events_without_asn,
               uniqExactIf(src_ip, src_asn != 0) AS addresses_with_asn,
               uniqExactIf(src_ip, src_asn = 0) AS addresses_without_asn,
               countIf(src_country_code != '') AS events_with_country
        FROM {TABLE} {scope}""")

    snapshot["by_day"] = rows(f"""
        SELECT toDate(timestamp) AS day, count() AS events, uniqExact(session) AS sessions,
               uniqExact(src_ip) AS source_addresses
        FROM {TABLE} {scope} GROUP BY day ORDER BY day""")

    snapshot["by_hour_utc"] = rows(f"""
        SELECT toHour(timestamp) AS hour, count() AS events, uniqExact(session) AS sessions
        FROM {TABLE} {scope} GROUP BY hour ORDER BY hour""")

    snapshot["top_addresses"] = rows(f"""
        SELECT src_ip AS address, any(src_country_code) AS country_code, any(src_country) AS country,
               max(src_asn) AS asn, anyIf(src_as_org, src_as_org != '') AS as_org,
               uniqExact(session) AS sessions, count() AS events,
               countIf(eventid = 'cowrie.command.input') AS commands,
               uniqExactIf(username, eventid LIKE 'cowrie.login%') AS usernames_tried,
               min(timestamp) AS first_seen, max(timestamp) AS last_seen
        FROM {TABLE} {scope}
        GROUP BY address ORDER BY events DESC, address ASC LIMIT {top}""")

    snapshot["countries"] = rows(f"""
        SELECT src_country_code AS country_code, any(src_country) AS country,
               uniqExact(src_ip) AS source_addresses, uniqExact(session) AS sessions, count() AS events
        FROM {TABLE} {scope} AND src_country_code != ''
        GROUP BY country_code ORDER BY sessions DESC, country_code ASC LIMIT {top}""")

    snapshot["networks"] = rows(f"""
        SELECT src_asn AS asn, anyIf(src_as_org, src_as_org != '') AS as_org,
               uniqExact(src_ip) AS source_addresses, uniqExact(session) AS sessions, count() AS events
        FROM {TABLE} {scope} AND src_asn != 0
        GROUP BY asn ORDER BY sessions DESC, asn ASC LIMIT {top}""")

    snapshot["logins"] = one(f"""
        SELECT countIf(eventid = 'cowrie.login.success') AS accepted,
               countIf(eventid = 'cowrie.login.failed') AS refused,
               uniqExactIf(username, eventid LIKE 'cowrie.login%') AS distinct_usernames,
               uniqExactIf(password, eventid LIKE 'cowrie.login%') AS distinct_passwords
        FROM {TABLE} {scope}""")

    snapshot["credentials"] = rows(f"""
        SELECT username, password, count() AS attempts, uniqExact(src_ip) AS source_addresses
        FROM {TABLE} {scope} AND eventid LIKE 'cowrie.login%'
        GROUP BY username, password ORDER BY attempts DESC, username ASC, password ASC LIMIT {top}""")

    snapshot["usernames"] = rows(f"""
        SELECT username, count() AS attempts, uniqExact(src_ip) AS source_addresses
        FROM {TABLE} {scope} AND eventid LIKE 'cowrie.login%'
        GROUP BY username ORDER BY attempts DESC, username ASC LIMIT {top}""")

    snapshot["passwords"] = rows(f"""
        SELECT password, count() AS attempts, uniqExact(src_ip) AS source_addresses
        FROM {TABLE} {scope} AND eventid LIKE 'cowrie.login%'
        GROUP BY password ORDER BY attempts DESC, password ASC LIMIT {top}""")

    snapshot["commands"] = rows(f"""
        SELECT input AS command, count() AS times, uniqExact(src_ip) AS source_addresses,
               uniqExact(session) AS sessions
        FROM {TABLE} {scope} AND eventid = 'cowrie.command.input' AND input != ''
        GROUP BY command ORDER BY times DESC, command ASC LIMIT {top}""")

    snapshot["clients"] = rows(f"""
        SELECT client_version AS client, any(hassh) AS hassh, uniqExact(src_ip) AS source_addresses,
               uniqExact(session) AS sessions
        FROM {TABLE} {scope} AND client_version != ''
        GROUP BY client ORDER BY sessions DESC, client ASC LIMIT {top}""")

    # Hashes and the name the attacker used. Never the bytes, never a re-fetch of the URL (H4).
    snapshot["file_events"] = rows(f"""
        SELECT timestamp, eventid AS event, src_ip AS address, any(src_country_code) AS country_code,
               shasum AS sha256, url,
               extract(message, 'file "([^"]+)"') AS filename
        FROM {TABLE} {scope} AND eventid LIKE 'cowrie.session.file%'
        GROUP BY timestamp, event, address, sha256, url, filename
        ORDER BY timestamp, sha256""")

    snapshot["session_seconds"] = one(f"""
        SELECT round(quantileExact(0.5)(duration_ms) / 1000, 3) AS median,
               round(quantileExact(0.9)(duration_ms) / 1000, 3) AS p90,
               round(max(duration_ms) / 1000, 3) AS longest,
               countIf(duration_ms = 0) AS instant
        FROM {TABLE} {scope} AND eventid = 'cowrie.session.closed'""")

    return snapshot


def resolve_window(since: str | None, until: str | None) -> tuple[str, str]:
    """Default the window to the data's own bounds, so the file records a window and never a wall-clock time."""
    bounds = query(f"SELECT min(timestamp) AS first, max(timestamp) AS last FROM {TABLE}")
    if not bounds or not bounds[0].get("first"):
        raise QueryError(f"{TABLE} is empty")
    return since or str(bounds[0]["first"]), until or str(bounds[0]["last"])


def clean(value, literals, counts: dict[str, int]):
    """Sanitise every string in the snapshot, tallying what was rewritten.

    Applied to the whole structure rather than to a chosen list of fields: a new query added later is covered without
    anyone remembering to add it here, and the tally makes each rewrite visible in the file itself.
    """
    if isinstance(value, str):
        text, found = sanitise(value, literals)
        for rule, number in found.items():
            counts[rule] = counts.get(rule, 0) + number
        return text
    if isinstance(value, dict):
        return {key: clean(item, literals, counts) for key, item in value.items()}
    if isinstance(value, list):
        return [clean(item, literals, counts) for item in value]
    return value


def render(snapshot: dict) -> str:
    return json.dumps(snapshot, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--since", type=valid_time, help="window start (default: the first recorded event)")
    parser.add_argument("--until", type=valid_time, help="window end (default: the last recorded event)")
    parser.add_argument("--top", type=int, default=20, help="rows per ranking (default 20)")
    parser.add_argument("--out", help="output path, or '-' for standard output "
                                      "(default: data/snapshot-<end date>.json)")
    parser.add_argument("--check-determinism", action="store_true",
                        help="build the snapshot twice and confirm the bytes are identical")
    parser.add_argument("--quiet", action="store_true", help="no summary on stderr")
    args = parser.parse_args()

    if args.top < 1 or args.top > 500:
        print("snapshot: --top must be between 1 and 500", file=sys.stderr)
        return 2

    try:
        build.since, build.until = resolve_window(args.since, args.until)
        snapshot = {"meta": {
            "source": TABLE,
            "window_start": build.since,
            "window_end": build.until,
            "top_n": args.top,
            "schema_version": 1,
        }}
        literals = load_literals()
        rewritten: dict[str, int] = {}
        snapshot.update(clean(build(args.top), literals, rewritten))
        # Recorded in the file: an attacker string that mentioned one of my hosts was rewritten, never dropped.
        snapshot["meta"]["sanitised_values"] = dict(sorted(rewritten.items()))
        text = render(snapshot)
        if args.check_determinism:
            again = render({**snapshot, **clean(build(args.top), literals, {})})
            if again != text:
                print("snapshot: NOT deterministic — two builds of the same window differ", file=sys.stderr)
                return 1
            print("snapshot: deterministic — two builds of the same window produced identical bytes",
                  file=sys.stderr)
    except (QueryError, RedactionError, exclusions.ExclusionError) as exc:
        print(f"snapshot: {exc}", file=sys.stderr)
        return 2

    # The guard runs before the file exists on disk, not after it has been written and possibly committed.
    findings = scan_text(text, "<snapshot>", literals)
    if findings:
        print(f"snapshot: refusing to write — {len(findings)} never-publish value(s) in the result:", file=sys.stderr)
        for finding in findings:
            print(f"  line {finding.line}: {finding.rule} ({finding.hint})", file=sys.stderr)
        return 1

    if args.out == "-":
        sys.stdout.write(text)
    else:
        path = Path(args.out) if args.out else REPO / "data" / f"snapshot-{build.until[:10]}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        if not args.quiet:
            print(f"snapshot: wrote {path.relative_to(REPO) if path.is_relative_to(REPO) else path} "
                  f"({len(text)} bytes)", file=sys.stderr)

    if not args.quiet:
        totals, excluded = snapshot["totals"], snapshot["excluded"]
        enrich = snapshot["enrichment"]
        print(f"  window   {build.since} → {build.until}", file=sys.stderr)
        print(f"  kept     {totals['events']} events · {totals['sessions']} sessions · "
              f"{totals['source_addresses']} addresses · {totals['countries']} countries", file=sys.stderr)
        print(f"  excluded {excluded['events']} events from {excluded['source_addresses']} of my own addresses "
              f"and private ranges", file=sys.stderr)
        share = 100 * enrich["events_without_asn"] / max(totals["events"], 1)
        print(f"  ASN      missing on {enrich['events_without_asn']} events ({share:.0f}%) from "
              f"{enrich['addresses_without_asn']} addresses — stated in the file, not hidden", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

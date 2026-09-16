#!/usr/bin/env python3
"""Find the operators behind the addresses (docs/method.md, Phase 3).

A list of top attacking addresses is not a finding: one operator runs many hosts, and the same host can be rented by
several. This turns a window of honeypot data into the structure underneath it — which sessions share an SSH client
fingerprint, which credential lists are shared between operators, which commands belong to exactly one of them — and
reconciles every derived figure against the snapshot it was built from.

  scripts/analyse.py                                  # newest snapshot in data/
  scripts/analyse.py --snapshot data/snapshot-2026-09-16.json
  scripts/analyse.py --out - --quiet

Clustering unit is the **session**: every session carries at most one hassh, so sessions partition exactly and the
totals must add up. Addresses do not partition — 13 of them presented more than one client fingerprint — so the
report says how many appear in several clusters rather than pretending each one has a single owner.

Reads the lab's database read-only. The only outbound request is a VirusTotal hash lookup, and only when a key is
configured (CLAUDE.md H5).
"""
import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts" / "lib"))
import exclusions  # noqa: E402
import virustotal  # noqa: E402
from chquery import QueryError, query  # noqa: E402
from redact import RedactionError, load_literals, sanitise, scan_text  # noqa: E402

TABLE = "nsm.cowrie_events"

# When SSH was first reachable from the internet. Not derivable from this data — the sensor's own test traffic starts
# earlier — so it is recorded here with its source and marked as an external fact wherever it is used.
SENSOR_LIVE_UTC = "2026-09-14 06:34:00"
SENSOR_LIVE_SOURCE = "~/JC deployment record: honeypot opened to the internet (Phase 5 Stage B), validated 06:34 UTC"


def clean(value, literals, counts: dict[str, int]):
    """Sanitise every string, tallying rewrites — same contract as snapshot.py."""
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


def analyse(since: str, until: str, top: int) -> dict:
    keep = exclusions.sql_clause()
    window = "timestamp >= {since:String} AND timestamp <= {until:String}"
    scope = f"WHERE {window} AND {keep}"

    # Cowrie records the client fingerprint on the key-exchange event only; every other event in the same session
    # carries an empty `hassh`. Grouping those events by the column directly matches nothing and quietly returns
    # empty results, so the fingerprint is resolved per session first and joined back onto every event.
    fingerprinted = f"""
        FROM {TABLE} AS e
        INNER JOIN (
            SELECT session, anyIf(hassh, hassh != '') AS hassh
            FROM {TABLE} {scope}
            GROUP BY session HAVING hassh != ''
        ) AS s ON e.session = s.session
        WHERE e.{window} AND {exclusions.sql_clause('e.src_ip')}"""

    def rows(sql: str) -> list[dict]:
        return query(sql, {"since": since, "until": until})

    def one(sql: str) -> dict:
        found = rows(sql)
        return found[0] if found else {}

    result: dict = {}

    # ---------------------------------------------------------------- exposure
    # The moment SSH became reachable is passed as a query parameter, not spliced into the SQL.
    exposure = query(f"""
        SELECT min(timestamp) AS first_attacker_event,
               round(date_diff('second', parseDateTime64BestEffort({{live:String}}), min(timestamp)) / 60, 1)
                   AS minutes_to_first_attacker
        FROM {TABLE} {scope}""", {"since": since, "until": until, "live": SENSOR_LIVE_UTC})
    result["exposure"] = {
        "sensor_live_utc": SENSOR_LIVE_UTC,
        "sensor_live_source": SENSOR_LIVE_SOURCE,
        **(exposure[0] if exposure else {"first_attacker_event": "", "minutes_to_first_attacker": None}),
    }

    # ---------------------------------------------------------------- clusters
    # One row per SSH client fingerprint. A session has at most one hassh, so sessions partition exactly.
    clusters = rows(f"""
        SELECT s.hassh AS hassh,
               uniqExact(e.session) AS sessions, count() AS events,
               groupUniqArray(e.src_ip) AS addresses,
               uniqExact(e.src_ip) AS address_count,
               arraySort(groupUniqArrayIf(e.src_country_code, e.src_country_code != '')) AS countries,
               arraySort(groupUniqArrayIf(e.src_as_org, e.src_as_org != '')) AS networks,
               arraySort(groupUniqArrayIf(e.client_version, e.client_version != '')) AS clients,
               arraySort(groupUniqArrayIf(e.input, e.eventid = 'cowrie.command.input' AND e.input != '')) AS commands,
               uniqExactIf(concat(e.username, ':', e.password), e.eventid LIKE 'cowrie.login%') AS credential_pairs,
               min(e.timestamp) AS first_seen, max(e.timestamp) AS last_seen
        {fingerprinted}
        GROUP BY hassh ORDER BY sessions DESC, hassh ASC""")
    for cluster in clusters:
        cluster["addresses"] = sorted(cluster["addresses"])
        cluster["is_campaign"] = cluster["address_count"] > 1
        # Commands are the cluster's signature; keep them whole but bound the list.
        cluster["commands"] = cluster["commands"][:10]

    result["clusters"] = clusters[:top]
    result["clusters_not_listed"] = max(0, len(clusters) - top)

    # ---------------------------------------------------------------- no handshake
    # Most *addresses* never complete a key exchange: they connect, look, and leave.
    result["no_handshake"] = one(f"""
        SELECT uniqExact(session) AS sessions, uniqExact(src_ip) AS addresses_with_such_a_session,
               uniqExactIf(src_country_code, src_country_code != '') AS countries
        FROM {TABLE} {scope} AND session NOT IN (
            SELECT session FROM {TABLE} {scope} AND hassh != '')""")
    # The stricter figure: addresses that never completed a key exchange in any session. An address can do both, so
    # the two counts overlap and reporting only the looser one would overstate how many visitors never got that far.
    result["no_handshake"]["addresses_that_never_handshook"] = one(f"""
        SELECT countIf(fingerprints = 0) AS n FROM (
            SELECT src_ip, uniqExactIf(hassh, hassh != '') AS fingerprints
            FROM {TABLE} {scope} GROUP BY src_ip)""").get("n", 0)

    # ---------------------------------------------------------------- shape of the crowd
    result["shape"] = one(f"""
        SELECT uniqExactIf(src_ip, hassh != '') AS addresses_with_fingerprint,
               uniqExactIf(hassh, hassh != '') AS fingerprints,
               countIf(eventid = 'cowrie.command.input') AS commands_run
        FROM {TABLE} {scope}""")
    result["shape"]["addresses_in_several_clusters"] = one(f"""
        SELECT countIf(n > 1) AS n FROM (
            SELECT src_ip, uniqExactIf(hassh, hassh != '') AS n
            FROM {TABLE} {scope} GROUP BY src_ip)""").get("n", 0)

    # ---------------------------------------------------------------- credential reuse
    # A password used by several fingerprints is a shared dictionary; one used by a single fingerprint is that
    # operator's own list. The split says how much of this traffic is commodity tooling.
    result["credential_reuse"] = one(f"""
        SELECT countIf(clusters > 1) AS shared_passwords, countIf(clusters = 1) AS exclusive_passwords
        FROM (
            SELECT e.password AS password, uniqExact(s.hassh) AS clusters
            {fingerprinted} AND e.eventid LIKE 'cowrie.login%' AND e.password != ''
            GROUP BY password)""")
    result["most_shared_passwords"] = rows(f"""
        SELECT e.password AS password, uniqExact(s.hassh) AS used_by_clusters,
               uniqExact(e.src_ip) AS source_addresses, count() AS attempts
        {fingerprinted} AND e.eventid LIKE 'cowrie.login%' AND e.password != ''
        GROUP BY password HAVING used_by_clusters > 1
        ORDER BY used_by_clusters DESC, attempts DESC, password ASC LIMIT {top}""")

    # ---------------------------------------------------------------- command signatures
    # A command run by exactly one fingerprint identifies that operator; one run by many is generic reconnaissance.
    result["command_signatures"] = rows(f"""
        SELECT e.input AS command, uniqExact(s.hassh) AS used_by_clusters,
               uniqExact(e.src_ip) AS source_addresses, count() AS times,
               arraySort(groupUniqArray(s.hassh)) AS clusters
        {fingerprinted} AND e.eventid = 'cowrie.command.input' AND e.input != ''
        GROUP BY command ORDER BY times DESC, command ASC LIMIT {top}""")
    for signature in result["command_signatures"]:
        signature["exclusive_to_one_cluster"] = signature["used_by_clusters"] == 1

    return result


def reconcile(analysis: dict, snapshot: dict) -> list[str]:
    """Every derived figure must add up against the snapshot, or the analysis is wrong. Returns the mismatches."""
    problems = []
    totals = snapshot.get("totals", {})
    listed = sum(c["sessions"] for c in analysis["clusters"])
    unlisted = analysis.get("_sessions_in_unlisted_clusters", 0)
    no_handshake = analysis["no_handshake"].get("sessions", 0)
    if listed + unlisted + no_handshake != totals.get("sessions"):
        problems.append(f"sessions: {listed} listed + {unlisted} unlisted + {no_handshake} without a handshake "
                        f"!= {totals.get('sessions')} in the snapshot")
    addresses = {address for cluster in analysis["clusters"] for address in cluster["addresses"]}
    if len(addresses) > totals.get("source_addresses", 0):
        problems.append(f"addresses: {len(addresses)} in clusters exceeds {totals.get('source_addresses')} total")
    if analysis["exposure"]["first_attacker_event"] != totals.get("first_event"):
        problems.append("first attacker event disagrees with the snapshot's first event")
    return problems


def newest_snapshot() -> Path:
    found = sorted((REPO / "data").glob("snapshot-*.json"))
    if not found:
        raise QueryError("no snapshot in data/ — run scripts/snapshot.py first")
    return found[-1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--snapshot", help="snapshot to analyse (default: the newest in data/)")
    parser.add_argument("--top", type=int, default=15, help="rows per ranking (default 15)")
    parser.add_argument("--out", help="output path, or '-' for standard output "
                                      "(default: data/analysis-<end date>.json)")
    parser.add_argument("--no-virustotal", action="store_true", help="skip the hash lookups even if a key is set")
    parser.add_argument("--quiet", action="store_true", help="no summary on stderr")
    args = parser.parse_args()

    if args.top < 1 or args.top > 200:
        print("analyse: --top must be between 1 and 200", file=sys.stderr)
        return 2

    try:
        snapshot_path = Path(args.snapshot) if args.snapshot else newest_snapshot()
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
        meta = snapshot.get("meta", {})
        since, until = meta.get("window_start"), meta.get("window_end")
        if not since or not until:
            raise QueryError(f"{snapshot_path} has no window in its meta block")

        analysis = analyse(since, until, args.top)

        # Sessions in clusters beyond --top still have to be counted for the reconciliation to mean anything.
        all_clusters = query(f"""
            SELECT uniqExact(session) AS sessions FROM {TABLE}
            WHERE timestamp >= {{since:String}} AND timestamp <= {{until:String}}
              AND {exclusions.sql_clause()} AND hassh != ''""", {"since": since, "until": until})
        in_clusters = all_clusters[0]["sessions"] if all_clusters else 0
        analysis["_sessions_in_unlisted_clusters"] = in_clusters - sum(c["sessions"] for c in analysis["clusters"])

        problems = reconcile(analysis, snapshot)
        analysis["clustering"] = {
            "unit": "session",
            "signal": "hassh — the SSH client's key-exchange fingerprint",
            "note": ("Sessions partition exactly: every session carries at most one hassh. Addresses do not — some "
                     "present more than one client build — so an address may appear in several clusters and the "
                     "count of addresses across clusters can exceed the number of addresses seen."),
            "reconciles": not problems,
            "problems": problems,
            "sessions_in_unlisted_clusters": analysis.pop("_sessions_in_unlisted_clusters"),
        }

        # ------------------------------------------------------------ VirusTotal (H5): hashes only, never a sample
        hashes = sorted({event["sha256"] for event in snapshot.get("file_events", []) if event.get("sha256")})
        key = None if args.no_virustotal else virustotal.api_key(REPO / ".env")
        if not hashes:
            analysis["virustotal"] = {"status": "nothing to look up", "hashes": []}
        elif not key:
            analysis["virustotal"] = {
                "status": "skipped", "hashes": hashes,
                "reason": "no VT_API_KEY in .env or the environment; re-run once a key is configured",
            }
        else:
            log = None if args.quiet else (lambda message: print(message, file=sys.stderr))
            analysis["virustotal"] = {
                "status": "looked up",
                "method": "GET /api/v3/files/<sha256> — a hash lookup; no sample is ever uploaded (H5)",
                "results": virustotal.lookup_all(hashes, key, REPO / "data" / "vt-cache.json", log),
            }

        literals = load_literals()
        rewritten: dict[str, int] = {}
        payload = {"meta": {
            "source_snapshot": snapshot_path.name,
            "window_start": since,
            "window_end": until,
            "top_n": args.top,
            "schema_version": 1,
        }}
        payload.update(clean(analysis, literals, rewritten))
        payload["meta"]["sanitised_values"] = dict(sorted(rewritten.items()))
        text = json.dumps(payload, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    except (QueryError, RedactionError, exclusions.ExclusionError, virustotal.VirusTotalError,
            OSError, json.JSONDecodeError) as exc:
        print(f"analyse: {exc}", file=sys.stderr)
        return 2

    findings = scan_text(text, "<analysis>", literals)
    if findings:
        print(f"analyse: refusing to write — {len(findings)} never-publish value(s):", file=sys.stderr)
        for finding in findings:
            print(f"  line {finding.line}: {finding.rule} ({finding.hint})", file=sys.stderr)
        return 1

    if args.out == "-":
        sys.stdout.write(text)
    else:
        path = Path(args.out) if args.out else REPO / "data" / f"analysis-{until[:10]}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        if not args.quiet:
            print(f"analyse: wrote {path.relative_to(REPO) if path.is_relative_to(REPO) else path} "
                  f"({len(text)} bytes)", file=sys.stderr)

    if not args.quiet:
        shape, exposure = payload["shape"], payload["exposure"]
        campaigns = [c for c in payload["clusters"] if c["is_campaign"]]
        print(f"  exposure  first attacker {exposure['minutes_to_first_attacker']} minutes after SSH went live",
              file=sys.stderr)
        print(f"  clusters  {shape['addresses_with_fingerprint']} addresses that completed a handshake collapse into "
              f"{shape['fingerprints']} client fingerprints", file=sys.stderr)
        print(f"  campaigns {len(campaigns)} of the top {len(payload['clusters'])} clusters span several addresses",
              file=sys.stderr)
        print(f"  quiet     {payload['no_handshake']['addresses_that_never_handshook']} addresses never completed a "
              f"key exchange at all ({payload['no_handshake']['addresses_with_such_a_session']} had at least one "
              f"session that did not)", file=sys.stderr)
        print(f"  reconcile {'OK' if payload['clustering']['reconciles'] else 'FAILED'}", file=sys.stderr)
        for problem in payload["clustering"]["problems"]:
            print(f"    {problem}", file=sys.stderr)
    return 0 if payload["clustering"]["reconciles"] else 1


if __name__ == "__main__":
    sys.exit(main())

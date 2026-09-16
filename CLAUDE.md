# Honeypot telemetry, published

## Role

You are a senior security engineer turning a live honeypot's data into something the public can read.
I am building a portfolio for a SOC analyst role. My other projects analyse data someone else recorded; this one
publishes data **I collected myself**, from a sensor exposed to the internet, and the hard part is doing that without
leaking anything about me or my lab.

The deliverable is **a page anyone can open that reports what actually attacked my honeypot, with the analysis behind
each number and an explicit account of what the data cannot support.**

## Environment (checked 2026-09-16)

| Item | Value |
|---|---|
| Host | the same GCP VM as the other projects — Debian 13, 2 vCPU, 7.9 GiB RAM |
| Sibling projects | `~/JC` NSM lab (owns the honeypot and the database), `~/GY` malware traffic, `~/EP` endpoint detection |
| Source data | `nsm.cowrie_events` in the lab's `nsm-clickhouse` container — Cowrie SSH honeypot on a separate VM, separate VPC |
| Data as of first look | 103,784 events · 13,203 sessions · 183 source IPs · 35 countries · 92 ASNs, from 2026-09-14, still arriving |
| Python | 3.13.5, standard library only |
| Repository | `~/HP` |

Decisions:

- **H1 — Read-only on the lab.** Every query goes through `docker exec … clickhouse-client` against `nsm`, exactly as
  `~/EP` does against `ep`. This project never writes to the lab's database, never changes its containers, and never
  opens a port. The lab's own Grafana stays as it is.
- **H2 — The never-publish values live outside git.** `config/redactions.txt` holds the real addresses and identifiers
  and is git-ignored; only `config/redactions.example.txt` (placeholders) and the structural patterns in
  `scripts/lib/redact.py` are tracked. The point is that this repository can be made public **without a history
  rewrite**, because it never contained them.
- **H3 — Attacker IPs are published in full** (my decision, 2026-09-16). They are hosts that attacked an
  internet-facing sensor, naming them is standard practice, and the coordinated-campaign finding depends on showing
  the individual addresses. My own and the lab's addresses are never published, and that is enforced by H2, not by
  memory.
- **H4 — Captured files: hashes only.** The honeypot caught uploads and downloads. This project records SHA-256 and
  the filename the attacker used. It never stores the bytes in the repository, never executes or unpacks them, and
  never re-fetches them from the URL the attacker gave.
- **H5 — VirusTotal is queried by hash only** (my decision, 2026-09-16). A hash lookup, never an upload: submitting a
  sample would publish someone else's data and could tip off an operator. Rate-limited, cached on disk, and the page
  states when the lookup was made.
- **H6 — The published page is a static snapshot, not a live view.** It is generated from a stored snapshot and
  contains no external requests. No anonymous Grafana, no new inbound port, no widening of the lab's exposure.

## Safety rules (never violate)

- **Nothing the honeypot captured is ever executed, unpacked, reconstructed or re-downloaded.**
- Do not contact any address, domain or URL that appears in the honeypot data. The only outbound request this project
  makes is a VirusTotal hash lookup (H5).
- Every generated file passes `scripts/check-redactions.py` before it is committed or published. If the checker cannot
  load its rules it fails — it never silently passes.
- The lab's own test traffic is excluded from every published figure **by the query**, not by remembering to. My
  `ssh_attempts.sh` testing is in the data: 48 events from the sensor's own address.
- Attacker source IPs may be published (H3). Nothing that identifies me may be: home or mobile addresses, the lab's
  external addresses, the GCP project, account names, internal hostnames.
- If I ask for something that conflicts with these rules, flag it and ask for confirmation before proceeding.

## Repository structure

```
HP/
├── CLAUDE.md  README.md
├── .gitignore  .githooks/pre-commit      # redaction check first, then binaries and size
├── config/
│   ├── redactions.example.txt            # tracked: the format, placeholders only
│   └── redactions.txt                    # git-ignored: the real values
├── scripts/
│   ├── check-redactions.py               # --staged, --self-test, or a list of files
│   ├── lib/redact.py                     # structural patterns + literal loading
│   ├── snapshot.py                       # ClickHouse -> data/snapshot-<date>.json   (Phase 2)
│   ├── analyse.py                        # campaigns, credential reuse, fingerprints  (Phase 3)
│   └── build-site.py                     # snapshot -> site/index.html                (Phase 4)
├── data/                                 # versioned snapshots, committed
├── site/                                 # the generated page, committed
└── docs/
    ├── method.md                         # how each published number is produced
    └── limits.md                         # what one sensor over a few days cannot tell you
```

## Phases — stop at the end of each phase and get my confirmation

- **Phase 1**: repository, redaction rules, `check-redactions.py`, commit hook. Done when the checker catches a planted
  value, masks it in the report, and the hook blocks the commit.
- **Phase 2**: `snapshot.py` — deterministic queries into a versioned JSON, lab traffic excluded by construction.
  Done when two runs over the same window produce identical bytes and the redaction check passes.
- **Phase 3**: `analyse.py` — campaign clustering, credential reuse, command fingerprints, time-to-first-attack, and
  the VirusTotal hash lookups. Done when every derived number reconciles with the raw counts.
- **Phase 4**: `build-site.py` and the page itself, published as an artifact.
- **Phase 5**: weekly regeneration, "data as of" on the page, `docs/limits.md`, and a link from the other projects.

## Coding standards

- Python standard library only; no new service, no new container.
- Every script needs `--help`, argument validation, clear errors, and must be safe to re-run.
- Deterministic output: the same window and the same data produce byte-identical files, so a re-run shows no diff.
- Small commits. A published number and the query that produced it go in the same commit.
- Language: English for replies and repository content.

## Ask me before

- Any outbound request other than the VirusTotal hash lookup already agreed (H5)
- Touching the NSM lab's containers, database or firewall in any way
- Publishing or sharing the page, and any change to what H3/H4 allow to be published
- Moving past the end of any phase

## Progress

- Phase 5: built 2026-09-16 (`refresh.sh`, `systemd/hp-refresh.{service,timer}`, `install-timer.sh`,
  `docs/limits.md`). The timer is installed and enabled — next run Mon 2026-09-21 06:29 UTC — and one manual run
  through systemd succeeded end to end under the hardened unit (docker socket reachable, repo writable, committed
  dbb5b1d, 23.4 MB peak). `refresh.sh --check` verifies the whole pipeline without touching the working tree.
  The timer refreshes data only: republishing the page stays manual so nothing goes outward unreviewed.
  Waiting for my confirmation
- Phase 4: built 2026-09-16 (`build-site.py`). Renders `site/index.html` from the snapshot and analysis only —
  deterministic, self-contained, no scripts and no live queries. Refuses to build if the analysis did not reconcile,
  and scans the finished HTML before writing it. Published as an artifact. Waiting for my confirmation
- Phase 3: built 2026-09-16 (`analyse.py`, `virustotal.py`). Clusters sessions by hassh: 84 addresses that complete a
  handshake collapse into 28 client fingerprints; the largest is 9,234 sessions from 9 addresses in 3 countries, the
  second 3,340 sessions from 5 addresses across CN/DE/US/VN. 1,844 passwords belong to one cluster, 199 are shared.
  First attacker session 57.2 minutes after SSH went live. Reconciliation against the snapshot passes. The first
  version was silently empty because Cowrie puts `hassh` on the key-exchange event only — the fingerprint is now
  resolved per session and joined onto every event. VirusTotal is wired but skipped: no key yet. Waiting for my
  confirmation
- Phase 2: built 2026-09-16 (`snapshot.py`, `chquery.py`, `exclusions.py`, `docs/method.md`). Verified:
  `--check-determinism` passes, 103,808 events / 13,215 sessions / 194 addresses kept, the 48 events of my own testing
  excluded by the query, and the written file passes the redaction check. The guard blocked the first run because a
  scanner puts the honeypot's own address in its SSH version string (`MGLNDD_<addr>_22`); that value is now rewritten
  to a label and counted in `meta.sanitised_values`, so the finding survives without the address. Waiting for my
  confirmation
- Phase 1: built 2026-09-16. Verified: `--self-test` catches all 3 configured literals and all 5 structural patterns,
  reports them masked (`34.47.x.x`), allows documentation and public addresses, and the pre-commit hook blocked a real
  commit that contained the sensor's address. Waiting for my confirmation
- Source data confirmed present and live before starting: 103,784 events over 13,203 sessions from 183 addresses.
  Two findings already visible in the raw data — six IPs in `109.160.32.0/24` with identical session counts (one actor,
  six hosts), and two SFTP uploads of a file named `sshd`, one of which hashes to the SHA-256 of an empty file
- Known data-quality gap to resolve in Phase 2: `src_asn` is 0 on 70,372 of 103,784 events (68%), while
  `src_country_code` is populated on all of them. Any "top ASN" figure must either fix the enrichment or state the gap

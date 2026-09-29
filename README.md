# What the internet does to an unguarded SSH server

An SSH honeypot has been running on a VM of mine since 14 September 2026. It accepts almost any password, records
everything the visitor types, and never lets them near a real machine. This repository turns what it catches into a
page anyone can read, and documents how each number was produced.

<img src="docs/page.png" alt="Port 22 Observatory" width="100%">

<sub>The published report, regenerated weekly from the live honeypot data. Regenerate with <code>scripts/build-site.py</code> then <code>docs/screenshot.sh --top 1500</code>.</sub>

It is the publishing half of my [network monitoring lab](../JC); the honeypot itself lives there, on its own VM in its
own VPC.

## Status

All five phases built. The report is generated from live data and refreshed weekly by a systemd timer; publishing the
page stays a deliberate act, so nothing goes outward unreviewed.

| | |
|---|---|
| Source | `nsm.cowrie_events` — Cowrie SSH honeypot, read-only |
| Window | 2026-09-14 05:57:05 → 2026-09-16 12:24:20 UTC |
| Collected | 103,859 events · 13,227 sessions · 197 addresses · 39 countries |
| The finding | those addresses are 28 SSH client fingerprints — one program runs from many hosts at once |
| Time to first attack | 57.2 minutes after the port opened |
| Output | `data/snapshot-<date>.json`, `data/analysis-<date>.json`, `site/index.html` — all committed |

```console
$ scripts/refresh.sh --check
refresh: the pipeline is healthy; nothing was written
```

## The problem this repository solves first

Publishing your own sensor's data means publishing from an environment that also contains your home address, your
phone's address, your cloud project and your lab's hosts. Redaction by remembering does not survive the twentieth
regeneration of a page.

So the first thing built here is the guard, not the report:

- The **real** never-publish values live in `config/redactions.txt`, which is git-ignored. This repository has never
  contained them, so it can be made public without rewriting history.
- The **shapes** that are always unpublishable — RFC1918, loopback, link-local, CGNAT, the form of a GCP project id —
  are patterns in `scripts/lib/redact.py`, which is safe to commit because it names classes, not values.
- Findings are reported by rule name and masked (`34.47.x.x`), so a failing check can be pasted anywhere.
- The commit hook runs the check **before** it looks at file types: a leaked address is the one mistake a later commit
  cannot undo.

```console
$ scripts/check-redactions.py --self-test
check-redactions: self-test passed — 3 literal(s) from redactions.txt + 5 structural pattern(s);
every planted value caught, no value printed, public addresses allowed

$ git commit -m "add today's figures"
check-redactions: 1 value(s) that must not be published:

  docs/leak-test.md:1: sensor-public-ip (34.47.x.x)

pre-commit: commit blocked by the redaction check.
```

## What the analysis found

The first thing I noticed in the raw data was six addresses in `109.160.32.0/24` with identical session counts — 1,437
each, to the event. The obvious reading was "one actor, six hosts in one subnet".

Clustering by SSH client fingerprint showed that reading was too small. The real group is **9 addresses spread across
Korea, Singapore and the United States**, and the `/24` itself splits across more than one client build — so neither
the subnet nor the country was the thing that held the group together. The tool was.

- **A second cluster runs from Germany, the United States, Vietnam and China at once**, which is why the page keeps a
  country ranking only to show why it misleads: that ranking splits one operator across four rows.
- **1,844 passwords were tried by exactly one fingerprint and only 199 by more than one.** The shared handful is the
  dictionary everyone has; the long tail is each program carrying its own list.
- **Two SFTP uploads of a file named `sshd`.** One has SHA-256 `e3b0c442…b855` — the hash of an empty file. The bot
  deployed its backdoor, uploaded nothing, and carried on as though it had worked.
- **110 addresses never completed a key exchange at all**: the majority of the addresses, and almost none of the
  traffic.

## How it is built

1. **Redaction guard** — `scripts/check-redactions.py`, with a self-test that plants every configured value.
2. **Snapshot** — `scripts/snapshot.py`: deterministic queries into a versioned JSON, my own traffic excluded by the
   query rather than by memory.
3. **Analysis** — `scripts/analyse.py`: clusters sessions by SSH client fingerprint, measures credential reuse between
   operators, and reconciles every derived figure against the snapshot before anything can be published.
4. **The page** — `scripts/build-site.py`: self-contained HTML rendered from those two files only.
5. **Freshness** — `scripts/refresh.sh` runs all four; a weekly systemd timer keeps the data current.
   [docs/limits.md](docs/limits.md) is the long form of what one sensor over a few days cannot say.

## Rules this project runs under

Nothing the honeypot captured is executed, unpacked or re-downloaded; captured files are recorded as hashes only.
No address from the data is ever contacted. The only outbound request is a VirusTotal hash lookup. The lab's database
is read-only here, and no port is opened. The full set is in [CLAUDE.md](CLAUDE.md).

# What the internet does to an unguarded SSH server

An SSH honeypot has been running on a VM of mine since 14 September 2026. It accepts almost any password, records
everything the visitor types, and never lets them near a real machine. This repository turns what it catches into a
page anyone can read, and documents how each number was produced.

It is the publishing half of my [network monitoring lab](../JC); the honeypot itself lives there, on its own VM in its
own VPC.

## Status

Phase 1 of 5. The redaction guard is built and tested; nothing is published yet.

| | |
|---|---|
| Source | `nsm.cowrie_events` — Cowrie SSH honeypot, read-only |
| Collected so far | 103,784 events · 13,203 sessions · 183 source addresses · 35 countries |
| Published | nothing yet — see Phases below |

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

## What is already visible in the raw data

Two things worth the write-up, found before any analysis code was written:

- **Six addresses in `109.160.32.0/24` with identical session counts** — 1,437 sessions each, to the event. That is one
  actor operating six hosts, not six attackers.
- **Two SFTP uploads of a file named `sshd`.** One of them has SHA-256 `e3b0c442…b855` — the hash of an empty file. The
  bot deployed its backdoor, uploaded nothing, and carried on.

## Phases

1. **Redaction guard** — built and tested.
2. **Snapshot** — deterministic queries into a versioned JSON; the lab's own test traffic excluded by the query, not by
   memory.
3. **Analysis** — campaign clustering, credential reuse between actors, command fingerprints, time to first attack,
   VirusTotal by hash.
4. **The page** — self-contained, generated from the snapshot.
5. **Freshness and limits** — weekly regeneration, and an honest account of what one sensor over a few days cannot say.

## Rules this project runs under

Nothing the honeypot captured is executed, unpacked or re-downloaded; captured files are recorded as hashes only.
No address from the data is ever contacted. The only outbound request is a VirusTotal hash lookup. The lab's database
is read-only here, and no port is opened. The full set is in [CLAUDE.md](CLAUDE.md).

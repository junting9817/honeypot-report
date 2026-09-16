# How a published number is produced

Everything the page says comes from one file: `data/snapshot-<end date>.json`. The page is generated from that
snapshot, never from a live query, so any figure that was ever published can be reproduced, diffed against the next
one, and checked against the query that made it.

## The chain

```
nsm.cowrie_events  →  scripts/snapshot.py  →  data/snapshot-<date>.json  →  the page
   (read-only)         exclude, query,          committed, diffable          (Phase 4)
                       sanitise, verify
```

## The window

A snapshot always records `window_start` and `window_end`, and every query is bounded by them. With no arguments the
window is the first and last event in the table, so the file describes itself rather than "now" — there is no
wall-clock value anywhere in it. That is what makes two runs comparable: the honeypot keeps collecting while a
snapshot is being built, and the pinned window is what keeps the arriving data out of it.

```console
$ scripts/snapshot.py --check-determinism
snapshot: deterministic — two builds of the same window produced identical bytes
```

## What is excluded, and why it is excluded by the query

My own traffic is dropped in the `WHERE` clause, not trimmed from the results afterwards:

- every literal address in `config/redactions.txt` — mine and the lab's
- every private, loopback, link-local and CGNAT range

The address list comes from the same file the redaction guard reads. That link is deliberate: a figure cannot be
computed from traffic that the guard would then refuse to publish, so the two cannot drift apart. The snapshot records
how much was dropped and never which addresses:

```json
"excluded": { "events": 48, "sessions": 10, "source_addresses": 1,
              "own_addresses_excluded": 2, "private_ranges_excluded": 9 }
```

Those 48 events are my own `ssh_attempts.sh` testing against the honeypot. They are real SSH sessions, and counting
them would have inflated every figure on the page.

## What is sanitised rather than dropped

Some of what the honeypot records contains one of my own addresses because **the attacker put it there**. The clearest
case in this data is a scanner that announces its target in the SSH version string:

```
MGLNDD_<redacted:honeypot-public-ip>_22
```

Dropping the row would hide a real finding; publishing it would leak the address. So the value is replaced with a
label naming what it was, and the count is written into the file:

```json
"meta": { "sanitised_values": { "honeypot-public-ip": 1 } }
```

Sanitising runs over the whole structure, not a chosen list of fields, so a query added later is covered without
anyone remembering to extend it.

## The order of the guards

1. Exclude my traffic in the query.
2. Sanitise attacker-supplied strings, counting every rewrite.
3. Scan the finished JSON **before it is written to disk**, and abort if anything remains.
4. The commit hook scans again, because a file can be edited by hand after it is generated.

Step 3 existing is why the first run of `snapshot.py` failed instead of producing a file that contained the
honeypot's address. The guard is meant to catch me, and it did.

## What each section of the snapshot answers

| Key | Question |
|---|---|
| `totals` | how much arrived, from how many addresses, countries and networks |
| `excluded` | how much of my own traffic was removed, and under what rules |
| `enrichment` | how complete the geolocation and ASN data actually is |
| `by_day`, `by_hour_utc` | when the traffic arrives |
| `top_addresses` | who sent the most, with country, network, sessions and commands |
| `countries`, `networks` | where it comes from, by geography and by operator |
| `logins` | how many credential attempts were accepted and refused, and how varied they were |
| `credentials`, `usernames`, `passwords` | what was guessed |
| `commands` | what was typed after a successful login |
| `clients` | what SSH client announced itself |
| `file_events` | what was uploaded or downloaded — SHA-256 and the attacker's filename only (H4) |
| `session_seconds` | how long a session lasted |

## Known data-quality gaps

- **ASN is missing on 68% of events** (70,372 of 103,808), from 7 addresses — six of them the `109.160.32.0/24`
  cluster. Country is populated on every event. The `networks` table therefore describes a third of the traffic, and
  the page has to say so rather than presenting it as the whole picture.
- **Geolocation disagrees with itself in places**: `47.80.13.176` is labelled `KR` while its network is registered to
  Alibaba's US entity, and the `109.160.32.0/24` block is labelled `US` on addresses that RIPE administers. Country
  here means "what the database says", not "where the operator is".

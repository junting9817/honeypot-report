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

## Finding the operators behind the addresses

A ranking of attacking addresses is not a finding. One operator runs many hosts, and the interesting question is which
of the 194 addresses belong together. `scripts/analyse.py` answers it with **hassh**, the fingerprint of the SSH
client's key-exchange offer: the same build of the same tool produces the same hassh wherever it runs.

**The clustering unit is the session, not the address.** Every session carries at most one hassh — verified, not
assumed — so sessions partition exactly and the totals must add up. Addresses do not partition: 13 of them presented
more than one client build, so an address can appear in several clusters. The file says so rather than pretending
each address has a single owner.

```console
$ scripts/analyse.py
  exposure  first attacker 57.2 minutes after SSH went live
  clusters  84 addresses that completed a handshake collapse into 28 client fingerprints
  campaigns 12 of the top 15 clusters span several addresses
  quiet     110 addresses never completed a key exchange at all (134 had at least one session that did not)
  reconcile OK
```

### The join that the data quietly requires

Cowrie records `hassh` on the key-exchange event **only**. Every other event in the same session — the logins, the
commands, the uploads — carries an empty string in that column. Grouping those events by `hassh` therefore matches
nothing and returns an empty result rather than an error: the first version of this analysis reported that no cluster
ran any command and that no password was shared by anyone, and both were silently wrong.

The fingerprint is now resolved per session and joined back onto every event:

```sql
FROM nsm.cowrie_events AS e
INNER JOIN (
    SELECT session, anyIf(hassh, hassh != '') AS hassh
    FROM nsm.cowrie_events <window and exclusions>
    GROUP BY session HAVING hassh != ''
) AS s ON e.session = s.session
```

### Reconciliation

Nothing derived is trusted on its own. `analyse.py` checks its own arithmetic against the snapshot it was built from —
sessions in listed clusters, plus sessions in clusters below the cut, plus sessions with no handshake, must equal the
snapshot's session count — and exits non-zero if they disagree. Reconciliation failures are recorded in the file as
well as printed, so a bad analysis cannot be published quietly.

### What the clustering shows

- The largest cluster is **9,234 sessions from 9 addresses in three countries**, all running one command.
- The second is **3,340 sessions from 5 addresses across four countries** — Germany, the US, Vietnam, China — which is
  what makes a "top attacking countries" chart misleading: that chart would split one operator four ways.
- **1,844 passwords were used by exactly one cluster and 199 by more than one.** The shared ones are the obvious
  dictionary — `admin`, `1234`, `12345`, `123456` — while the long tail belongs to a single operator each.
- Every one of the top commands is **exclusive to a single cluster**, which is what makes a command a usable signature
  rather than generic reconnaissance.

### What the analysis deliberately does not do

It does not name malware families. Strings such as `echo xsec` and `locate D877F783D5D3EF8C` are widely reported as
bot markers, but this project has not verified that mapping against a sample, so the clusters are identified by their
fingerprint and behaviour and left unnamed. Attribution that cannot be checked from this data does not belong on the
page.

## Time to first attack

`exposure` reports **57.2 minutes** between SSH becoming reachable from the internet and the first attacker session.
That figure depends on one fact the honeypot data cannot supply — when the port actually opened — so the moment is
recorded as a constant with its source (the lab's own deployment record, 2026-09-14 06:34 UTC) and is marked as an
external input wherever it is used. The sensor's own test traffic starts 94 minutes earlier, which is exactly why that
traffic is excluded before this figure is computed.

## VirusTotal

Hashes only, never a sample: `GET /api/v3/files/<sha256>`. Uploading a captured file would publish someone else's data
and could tell an operator that their tool landed in a honeypot. Results are cached in `data/vt-cache.json`, so a
re-run costs no requests and produces the same file, and the analysis records whether the lookup ran at all.

## Known data-quality gaps

- **ASN is missing on 68% of events** (70,372 of 103,808), from 7 addresses — six of them the `109.160.32.0/24`
  cluster. Country is populated on every event. The `networks` table therefore describes a third of the traffic, and
  the page has to say so rather than presenting it as the whole picture.
- **Geolocation disagrees with itself in places**: `47.80.13.176` is labelled `KR` while its network is registered to
  Alibaba's US entity, and the `109.160.32.0/24` block is labelled `US` on addresses that RIPE administers. Country
  here means "what the database says", not "where the operator is".

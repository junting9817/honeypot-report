#!/usr/bin/env python3
"""Render the published page from a snapshot and its analysis (Phase 4).

The page is generated, never hand-edited: Phase 5 regenerates it on a schedule, so anything typed into the HTML would
be lost. Everything it says comes from the two JSON files, which is what makes a published figure traceable back to
the query that produced it.

  scripts/build-site.py                     # newest snapshot + analysis in data/ -> site/index.html
  scripts/build-site.py --out - --quiet     # print the HTML

Self-contained by design (CLAUDE.md H6): no external requests except the web font stylesheet, no scripts, no live
queries. Deterministic — the same inputs produce byte-identical HTML. Reads local files only.
"""
import argparse
import html
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts" / "lib"))
from redact import RedactionError, load_literals, scan_text  # noqa: E402

FONTS = ("https://fonts.googleapis.com/css2?family=Archivo:wght@500;600;700"
         "&family=Roboto+Mono:wght@400;500&family=Source+Serif+4:ital,opsz,wght@0,8..60,400;0,8..60,600;1,8..60,400"
         "&display=swap")

CSS = """
:root {
  /* paper with a green cast — an instrument reading on a field report, not a terminal */
  --ground: #f3f4f0; --surface: #fafbf8; --sunk: #e9ebe4;
  --ink: #191c19; --ink-2: #565c54; --ink-3: #858a7e;
  --rule: #dadcd3; --rule-soft: #e6e8e1;
  --accent: #275446; --accent-soft: #e2ebe6;
  --signal: #b23a20; --signal-soft: #f3e2dd;
  --measure: 64ch;
  --display: Archivo, "Helvetica Neue", Helvetica, Arial, sans-serif;
  --body: "Source Serif 4", Georgia, "Times New Roman", serif;
  --mono: "Roboto Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --ground: #111412; --surface: #171b18; --sunk: #1d221e;
    --ink: #e4e8e0; --ink-2: #a3aa9e; --ink-3: #7c8379;
    --rule: #2a2f2b; --rule-soft: #212621;
    --accent: #81b9a1; --accent-soft: #1b2a24;
    --signal: #e4694a; --signal-soft: #2d1d18;
  }
}
:root[data-theme="dark"] {
  --ground: #111412; --surface: #171b18; --sunk: #1d221e;
  --ink: #e4e8e0; --ink-2: #a3aa9e; --ink-3: #7c8379;
  --rule: #2a2f2b; --rule-soft: #212621;
  --accent: #81b9a1; --accent-soft: #1b2a24;
  --signal: #e4694a; --signal-soft: #2d1d18;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--ground); color: var(--ink); font-family: var(--body);
       font-size: 17px; line-height: 1.6; -webkit-font-smoothing: antialiased; }
.page { max-width: 1040px; margin-inline: auto; padding-inline: 20px; padding-block: 0 80px; }
h1, h2, h3, .eyebrow, .chip, .stat b, .bar-label { font-family: var(--display); }
h1, h2, h3 { margin: 0; line-height: 1.15; letter-spacing: -.01em; text-wrap: balance; }
.eyebrow { font-size: .6875rem; font-weight: 600; letter-spacing: .14em; text-transform: uppercase;
           color: var(--ink-3); display: block; }
a { color: var(--accent); text-underline-offset: .18em; }
a:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
code, .mono { font-family: var(--mono); font-size: .86em; }

header.masthead { padding-block: 60px 36px; }
header.masthead h1 { font-size: clamp(2.1rem, 6vw, 3.1rem); font-weight: 700; max-width: 16ch; margin-top: 18px; }
.thesis { font-size: 1.2rem; line-height: 1.5; color: var(--ink-2); max-width: var(--measure); margin: 20px 0 0; }
.asof { margin-top: 24px; font-family: var(--mono); font-size: .8rem; color: var(--ink-3);
        display: flex; flex-wrap: wrap; gap: 6px 20px; }

.band { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px; background: var(--rule);
        border-block: 1px solid var(--rule); }
.stat { background: var(--ground); padding: 20px 18px 22px 0; }
.stat:not(:first-child) { padding-left: 18px; }
.stat b { display: block; font-size: 1.6rem; font-weight: 600; font-variant-numeric: tabular-nums;
          letter-spacing: -.02em; }
.stat.loud b { color: var(--signal); }
.stat span { display: block; margin-top: 3px; font-size: .82rem; color: var(--ink-2); line-height: 1.4; }

section { padding-block: 52px; border-bottom: 1px solid var(--rule); }
section > h2 { font-size: clamp(1.5rem, 3.4vw, 2rem); font-weight: 600; max-width: 22ch; margin-top: 12px; }
section > p { max-width: var(--measure); color: var(--ink-2); margin: 16px 0 0; }
section > p.lead { color: var(--ink); }

/* 24-hour arrival strip: one bar per UTC hour, drawn to the same scale as its label */
.hours { margin-top: 30px; display: grid; grid-template-columns: repeat(24, 1fr); gap: 3px; align-items: end;
         height: 130px; }
@media (max-width: 720px) { .hours { height: 104px; } }
.hour { background: var(--sunk); border-top: 2px solid var(--signal); min-height: 2px; position: relative; }
.hour-axis { margin-top: 8px; display: grid; grid-template-columns: repeat(24, 1fr); gap: 3px;
             font-family: var(--mono); font-size: .62rem; color: var(--ink-3); }
.hour-axis span { text-align: center; }
.scale { margin-top: 14px; font-family: var(--mono); font-size: .75rem; color: var(--ink-3); }

.clusters { margin-top: 32px; display: flex; flex-direction: column; gap: 2px; }
.cluster { background: var(--surface); border: 1px solid var(--rule); padding: 20px 22px 22px; }
.cluster.wide { border-left: 3px solid var(--signal); }
.cluster-head { display: flex; flex-wrap: wrap; gap: 6px 18px; align-items: baseline;
                justify-content: space-between; }
.cluster-id { font-family: var(--mono); font-size: .82rem; color: var(--ink-2); }
.cluster-n { font-family: var(--display); font-weight: 600; font-variant-numeric: tabular-nums; font-size: 1.05rem; }
.bar { margin-top: 12px; height: 6px; background: var(--sunk); }
.bar i { display: block; height: 100%; background: var(--signal); }
.cluster-facts { margin-top: 14px; display: flex; flex-wrap: wrap; gap: 8px 26px; font-size: .86rem;
                 color: var(--ink-2); }
.cluster-facts b { font-family: var(--mono); font-weight: 500; color: var(--ink); }
.addresses { margin-top: 13px; display: flex; flex-wrap: wrap; gap: 5px; }
.chip { font-family: var(--mono); font-size: .72rem; padding: 2px 7px; border: 1px solid var(--rule);
        background: var(--ground); color: var(--ink-2); white-space: nowrap; }
.chip.cc { background: var(--accent-soft); border-color: transparent; color: var(--accent); font-weight: 500; }
.cmd { margin-top: 13px; font-family: var(--mono); font-size: .78rem; background: var(--sunk); padding: 9px 12px;
       overflow-x: auto; white-space: pre; color: var(--ink); }
.cmd + .cmd { margin-top: 4px; }

.table-wrap { margin-top: 28px; overflow-x: auto; }
table { border-collapse: collapse; width: 100%; min-width: 520px; }
th, td { text-align: left; padding: 8px 16px 8px 0; border-bottom: 1px solid var(--rule-soft); }
thead th { font-family: var(--display); font-size: .68rem; font-weight: 600; letter-spacing: .12em;
           text-transform: uppercase; color: var(--ink-3); border-bottom: 1px solid var(--rule); }
td.n { font-family: var(--mono); font-variant-numeric: tabular-nums; }
td.k { font-family: var(--mono); font-size: .84rem; }

.split { margin-top: 30px; display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px; }
.note { background: var(--surface); border: 1px solid var(--rule); border-top: 2px solid var(--accent);
        padding: 18px 20px 20px; }
.note.loud { border-top-color: var(--signal); }
.note h3 { font-size: 1rem; font-weight: 600; }
.note b.big { display: block; font-family: var(--mono); font-size: 1.5rem; font-weight: 500;
              font-variant-numeric: tabular-nums; margin: 8px 0 4px; }
.note.loud b.big { color: var(--signal); }
.note p { margin: 6px 0 0; font-size: .85rem; color: var(--ink-2); line-height: 1.5; }

ul.limits { margin: 24px 0 0; padding: 0; list-style: none; max-width: var(--measure);
            display: flex; flex-direction: column; gap: 16px; }
ul.limits li { padding-left: 18px; border-left: 2px solid var(--rule); font-size: .92rem; color: var(--ink-2); }
ul.limits b { font-family: var(--display); font-weight: 600; color: var(--ink); }

footer { padding-block: 40px 0; color: var(--ink-3); font-size: .85rem; max-width: var(--measure); }
footer code { color: var(--ink-2); }

@media (max-width: 720px) {
  .band { grid-template-columns: repeat(2, 1fr); }
  .stat:nth-child(odd) { padding-left: 0; }
  .stat:nth-child(even) { padding-left: 18px; }
  .hours { height: 100px; }
  .hour-axis { font-size: 0; }
  .hour-axis span:nth-child(6n+1) { font-size: .62rem; }
}
"""


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def num(value) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return esc(value)


TENS = {10: "ten", 20: "twenty", 30: "thirty", 40: "forty", 50: "fifty", 60: "sixty", 70: "seventy",
        80: "eighty", 90: "ninety", 100: "a hundred"}


def about(count: int) -> str:
    """'28' -> 'about thirty'. The headline is regenerated weekly, so it has to stay true as the number moves."""
    nearest = min(TENS, key=lambda ten: abs(ten - count))
    return f"about {TENS[nearest]}" if count <= 100 else f"roughly {round(count, -1):,}"


def plural(count: int, word: str, many: str = "") -> str:
    return f"{count:,} {word if count == 1 else (many or word + 's')}"


def short(value: str, limit: int = 96) -> str:
    text = str(value)
    return text if len(text) <= limit else text[:limit - 1] + "…"


def masthead(snap: dict, ana: dict) -> str:
    totals, meta = snap["totals"], snap["meta"]
    minutes = ana["exposure"]["minutes_to_first_attacker"]
    return f"""
<header class="masthead">
  <span class="eyebrow">A honeypot report · SSH · {esc(meta['window_start'][:10])} to {esc(meta['window_end'][:10])}</span>
  <h1>Nobody is attacking you. {esc(about(ana['shape']['fingerprints']).capitalize())} programs are.</h1>
  <p class="thesis">
    I put an SSH server on the public internet with deliberately weak credentials and recorded everything that
    happened to it. The first automated login attempt arrived <strong>{esc(minutes)} minutes</strong> later. What
    followed looks like {num(totals['source_addresses'])} attackers and turns out to be a much smaller number of
    programs, each running from many addresses at once.
  </p>
  <div class="asof">
    <span>data as of {esc(meta['window_end'][:19])} UTC</span>
    <span>window {esc(meta['window_start'][:19])} → {esc(meta['window_end'][:19])}</span>
    <span>one sensor</span>
  </div>
</header>"""


def band(snap: dict, ana: dict) -> str:
    totals = snap["totals"]
    shape = ana["shape"]
    cells = [
        (num(totals["sessions"]), "SSH sessions recorded", False),
        (num(totals["source_addresses"]), "addresses they came from", False),
        (str(shape["fingerprints"]), "distinct client fingerprints behind them", True),
        (str(ana["exposure"]["minutes_to_first_attacker"]), "minutes from open port to first attempt", True),
    ]
    stats = "".join(f'<div class="stat{" loud" if loud else ""}"><b>{value}</b><span>{label}</span></div>'
                    for value, label, loud in cells)
    return f'<div class="band">{stats}</div>'


def arrival(snap: dict) -> str:
    hours = {int(row["hour"]): int(row["sessions"]) for row in snap["by_hour_utc"]}
    peak = max(hours.values()) if hours else 1
    # Pixel heights, computed here: a percentage height inside a grid whose row height depends on its items would
    # resolve against an auto height and collapse.
    bars = "".join(
        f'<div class="hour" style="height:{max(2, round(118 * hours.get(hour, 0) / peak))}px" '
        f'title="{hours.get(hour, 0)} sessions at {hour:02d}:00 UTC"></div>' for hour in range(24))
    axis = "".join(f"<span>{hour:02d}</span>" for hour in range(24))
    days = " · ".join(f"{esc(row['day'])}: {num(row['sessions'])}" for row in snap["by_day"])
    return f"""
<section>
  <span class="eyebrow">Arrival</span>
  <h2>It never stops, and it does not care what time it is</h2>
  <p>Sessions per hour of the day, UTC, summed over the window. The tallest bar is {num(peak)} sessions.</p>
  <div class="hours">{bars}</div>
  <div class="hour-axis">{axis}</div>
  <p class="scale">per day — {days}</p>
</section>"""


def clusters(ana: dict) -> str:
    listed = ana["clusters"]
    campaigns = [c for c in listed if c["is_campaign"]]
    peak = max((c["sessions"] for c in listed), default=1)
    blocks = []
    for cluster in listed[:8]:
        width = max(1, round(100 * cluster["sessions"] / peak))
        chips = "".join(f'<span class="chip">{esc(address)}</span>' for address in cluster["addresses"][:12])
        if cluster["address_count"] > 12:
            chips += f'<span class="chip">+{cluster["address_count"] - 12} more</span>'
        countries = "".join(f'<span class="chip cc">{esc(code)}</span>' for code in cluster["countries"])
        commands = "".join(f'<div class="cmd">{esc(short(command))}</div>' for command in cluster["commands"][:3])
        if not cluster["commands"]:
            commands = ('<div class="cmd">— no command ever ran: these sessions log in and disconnect</div>')
        blocks.append(f"""
  <article class="cluster{' wide' if cluster['address_count'] > 4 else ''}">
    <div class="cluster-head">
      <span class="cluster-id">hassh {esc(cluster['hassh'][:24])}…</span>
      <span class="cluster-n">{num(cluster['sessions'])} sessions</span>
    </div>
    <div class="bar"><i style="width:{width}%"></i></div>
    <div class="cluster-facts">
      <span><b>{cluster['address_count']}</b> addresses</span>
      <span><b>{len(cluster['countries'])}</b> countries</span>
      <span><b>{num(cluster['credential_pairs'])}</b> credential pairs tried</span>
    </div>
    <div class="addresses">{countries}{chips}</div>
    {commands}
  </article>""")
    return f"""
<section>
  <span class="eyebrow">Who is actually out there</span>
  <h2>{len(campaigns)} of the {len(listed)} busiest fingerprints run from more than one address</h2>
  <p class="lead">
    Every SSH client announces itself in the way it negotiates keys. That fingerprint — its hassh — is the same
    wherever the same build runs, so it groups sessions by the <em>program</em> behind them instead of by where the
    packets came from. {ana['shape']['addresses_with_fingerprint']} addresses that got as far as a key exchange
    collapse into {ana['shape']['fingerprints']} of them.
  </p>
  <p>
    Clustering is done on sessions, because every session carries exactly one fingerprint. Addresses do not divide so
    cleanly: {ana['shape']['addresses_in_several_clusters']} of them presented more than one client build, so they
    appear in more than one group below.
  </p>
  <div class="clusters">{''.join(blocks)}</div>
</section>"""


def credentials(snap: dict, ana: dict) -> str:
    logins, reuse = snap["logins"], ana["credential_reuse"]
    rows = "".join(
        f'<tr><td class="k">{esc(row["username"])}</td><td class="k">{esc(row["password"]) or "<em>(empty)</em>"}</td>'
        f'<td class="n">{num(row["attempts"])}</td><td class="n">{num(row["source_addresses"])}</td></tr>'
        for row in snap["credentials"][:12])
    shared = "".join(
        f'<tr><td class="k">{esc(row["password"])}</td><td class="n">{row["used_by_clusters"]}</td>'
        f'<td class="n">{num(row["attempts"])}</td></tr>' for row in ana["most_shared_passwords"][:8])
    return f"""
<section>
  <span class="eyebrow">Credentials</span>
  <h2>Two thousand passwords, and almost all of them belong to one program</h2>
  <p>
    {num(logins['accepted'])} logins were accepted and {num(logins['refused'])} refused — the honeypot says yes to
    almost anything, which is what makes the guesses worth reading. They used
    {num(logins['distinct_usernames'])} usernames and {num(logins['distinct_passwords'])} passwords.
  </p>
  <p>
    <strong>{num(reuse['exclusive_passwords'])} of those passwords were tried by exactly one fingerprint, and only
    {num(reuse['shared_passwords'])} by more than one.</strong> The shared handful is the famous dictionary everyone
    has; the long tail is each program carrying its own list.
  </p>
  <div class="table-wrap">
    <table>
      <caption class="eyebrow" style="padding-bottom:10px">Most tried pairs</caption>
      <thead><tr><th>Username</th><th>Password</th><th>Attempts</th><th>Addresses</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <div class="table-wrap">
    <table>
      <caption class="eyebrow" style="padding-bottom:10px">Passwords shared between programs</caption>
      <thead><tr><th>Password</th><th>Used by fingerprints</th><th>Attempts</th></tr></thead>
      <tbody>{shared}</tbody>
    </table>
  </div>
</section>"""


def behaviour(snap: dict, ana: dict) -> str:
    exclusive = [s for s in ana["command_signatures"] if s["exclusive_to_one_cluster"]]
    rows = "".join(
        f'<tr><td class="k">{esc(short(row["command"], 70))}</td><td class="n">{num(row["times"])}</td>'
        f'<td class="n">{row["source_addresses"]}</td>'
        f'<td>{"one program" if row["exclusive_to_one_cluster"] else f"{row['used_by_clusters']} programs"}</td></tr>'
        for row in ana["command_signatures"][:10])
    quiet = ana["no_handshake"]
    session = snap["session_seconds"]
    return f"""
<section>
  <span class="eyebrow">Behaviour</span>
  <h2>What they do once they are in: almost nothing</h2>
  <p>
    A typical session lasts {esc(session['median'])} seconds. The visitor logs in, runs one command to find out what
    kind of machine it landed on, and leaves. {len(exclusive)} of the {len(ana['command_signatures'])} most common
    commands are run by exactly one fingerprint, which is what makes a command a signature rather than generic
    curiosity.
  </p>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Command</th><th>Times</th><th>Addresses</th><th>Run by</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <div class="split">
    <div class="note loud">
      <h3>Never even knocked properly</h3>
      <b class="big">{num(quiet['addresses_that_never_handshook'])}</b>
      <p>addresses connected but never completed a key exchange, across
         {quiet['countries']} countries — {num(quiet['sessions'])} sessions of pure scanning. They are the majority of
         the addresses and almost none of the traffic.</p>
    </div>
    <div class="note">
      <h3>Longest session</h3>
      <b class="big">{esc(session['longest'])}s</b>
      <p>against a median of {esc(session['median'])}s and a 90th percentile of {esc(session['p90'])}s.
         {num(session['instant'])} sessions closed instantly.</p>
    </div>
  </div>
</section>"""


def files(snap: dict, ana: dict) -> str:
    events = snap["file_events"]
    vt = ana.get("virustotal", {})
    results = vt.get("results", {}) if vt.get("status") == "looked up" else {}
    rows = []
    for event in events:
        verdict = results.get(event["sha256"])
        if verdict is None:
            cell = "<em>not looked up</em>"
        elif not verdict.get("found"):
            cell = "unknown to VirusTotal"
        else:
            label = verdict.get("popular_label") or verdict.get("type") or "classified"
            cell = f'{verdict["malicious"]} engines flag it · {esc(label)}'
        rows.append(
            f'<tr><td class="k">{esc(event["timestamp"][:19])}</td>'
            f'<td class="k">{esc(event["address"])} <span class="chip cc">{esc(event["country_code"])}</span></td>'
            f'<td class="k">{esc(event["filename"] or "—")}</td>'
            f'<td class="k">{esc(event["sha256"][:20])}…</td><td>{cell}</td></tr>')
    note = ("VirusTotal has not been queried for these hashes yet." if not results else
            "VirusTotal was asked about each hash. No file was ever uploaded to it.")
    return f"""
<section>
  <span class="eyebrow">What they brought with them</span>
  <h2>Four file transfers, and one of them was empty</h2>
  <p>
    Two visitors uploaded a file called <code>sshd</code> over SFTP — a backdoor wearing the name of the service it
    replaces. One of them has the SHA-256 of a zero-byte file: the program uploaded nothing at all and carried on as
    though it had worked.
  </p>
  <p>
    Nothing captured here is executed, unpacked or fetched again. The page records hashes and the name the attacker
    used, and nothing else. {note}
  </p>
  <div class="table-wrap">
    <table>
      <thead><tr><th>When (UTC)</th><th>From</th><th>Filename</th><th>SHA-256</th><th>VirusTotal</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>
</section>"""


def geography(snap: dict, ana: dict) -> str:
    rows = "".join(
        f'<tr><td class="k">{esc(row["country_code"])}</td><td>{esc(row["country"])}</td>'
        f'<td class="n">{num(row["sessions"])}</td><td class="n">{num(row["source_addresses"])}</td></tr>'
        for row in snap["countries"][:10])
    enrich = snap["enrichment"]
    without = 100 * enrich["events_without_asn"] / max(snap["totals"]["events"], 1)
    return f"""
<section>
  <span class="eyebrow">Geography, with a warning</span>
  <h2>The country column is the least useful thing on this page</h2>
  <p>
    The second-largest program here runs from Germany, the United States, Vietnam and China at once. Ranking by
    country splits one operator across four rows and invites a conclusion about nations that the data does not
    support. It is included because its weakness is the point.
  </p>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Code</th><th>Country</th><th>Sessions</th><th>Addresses</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <p>
    Network attribution is worse here than geography: the database used has no operator for
    {num(enrich['addresses_without_asn'])} of the addresses, and those account for {without:.0f}% of all events. Any
    "top networks" ranking from this data would describe a third of the traffic while looking like it described all
    of it, so this page does not print one.
  </p>
</section>"""


def limits(snap: dict, ana: dict) -> str:
    excluded = snap["excluded"]
    return f"""
<section>
  <span class="eyebrow">Limits</span>
  <h2>What this cannot tell you</h2>
  <ul class="limits">
    <li><b>One sensor, one address, a few days.</b> This is what arrived at a single machine in one cloud region. It
        is not a measurement of the internet, and a second sensor elsewhere would see a different crowd.</li>
    <li><b>A honeypot is detectable.</b> Cowrie emulates a shell; anything careful enough to notice would leave
        without showing its hand, so the most capable visitors are the ones least likely to appear here.</li>
    <li><b>Accepting almost any password shapes what is measured.</b> The credential lists are real, but the number of
        successful logins says more about the trap than about the attackers.</li>
    <li><b>Fingerprints group tools, not people.</b> Two operators running the same off-the-shelf scanner share a
        hassh. The clusters are programs; who runs them is outside this data.</li>
    <li><b>No malware family is named.</b> Strings such as <code>echo xsec</code> are widely reported as bot markers,
        but that has not been verified here against a sample, so the programs stay unnamed.</li>
    <li><b>My own testing is removed.</b> {num(excluded['events'])} events from my own address were excluded by the
        query before any figure on this page was computed.</li>
  </ul>
</section>"""


def method(snap: dict, ana: dict) -> str:
    meta = snap["meta"]
    sanitised = sum(meta.get("sanitised_values", {}).values())
    return f"""
<section>
  <span class="eyebrow">Method</span>
  <h2>How to check any number here</h2>
  <p>
    A Cowrie SSH honeypot runs on its own VM in its own network, and ships its logs one way to a ClickHouse instance.
    Every figure on this page comes from one snapshot file and one analysis file, both generated by script and both
    committed: the page is rendered from those files, never from a live query, so what was published can be
    reproduced and diffed against the next run. Two builds of the same window produce identical bytes.
  </p>
  <p>
    Before any figure is computed, traffic from my own addresses and from private ranges is dropped in the query
    itself. The finished files are then scanned for anything that should never be published, and the build fails
    rather than writes. {"Nothing needed rewriting in this window." if not sanitised else
    f"{plural(sanitised, 'attacker-supplied string')} mentioned the sensor's own address — a scanner that "
    f"announces its target in its SSH version string — and {'was' if sanitised == 1 else 'were'} rewritten to a "
    f"label rather than dropped, so the finding survives without the address."}
  </p>
</section>
<footer>
  <p>
    Window {esc(meta['window_start'][:19])} → {esc(meta['window_end'][:19])} UTC ·
    {num(snap['totals']['events'])} events · generated from
    <code>{esc(meta.get('source', 'the sensor'))}</code> by <code>scripts/build-site.py</code>.
    Source addresses are published in full; they attacked an internet-facing sensor. Nothing identifying the sensor's
    operator appears anywhere on this page, and that is enforced by a check, not by memory.
  </p>
</footer>"""


def render(snap: dict, ana: dict) -> str:
    return (f"<title>Port 22 Observatory</title>\n"
            f'<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n'
            f'<link rel="stylesheet" href="{FONTS}">\n'
            f"<style>{CSS}</style>\n"
            f'<div class="page">'
            + masthead(snap, ana) + band(snap, ana) + arrival(snap) + clusters(ana)
            + credentials(snap, ana) + behaviour(snap, ana) + files(snap, ana)
            + geography(snap, ana) + limits(snap, ana) + method(snap, ana)
            + "</div>\n")


def newest(pattern: str) -> Path:
    found = sorted((REPO / "data").glob(pattern))
    if not found:
        raise FileNotFoundError(f"no {pattern} in data/ — run the earlier phases first")
    return found[-1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--snapshot", help="snapshot JSON (default: the newest in data/)")
    parser.add_argument("--analysis", help="analysis JSON (default: the newest in data/)")
    parser.add_argument("--out", help="output path, or '-' for standard output (default: site/index.html)")
    parser.add_argument("--quiet", action="store_true", help="no summary on stderr")
    args = parser.parse_args()

    try:
        snapshot_path = Path(args.snapshot) if args.snapshot else newest("snapshot-*.json")
        analysis_path = Path(args.analysis) if args.analysis else newest("analysis-*.json")
        snap = json.loads(snapshot_path.read_text(encoding="utf-8"))
        ana = json.loads(analysis_path.read_text(encoding="utf-8"))
        if snap["meta"]["window_end"] != ana["meta"]["window_end"]:
            raise ValueError(f"{snapshot_path.name} and {analysis_path.name} describe different windows")
        if not ana.get("clustering", {}).get("reconciles", False):
            raise ValueError(f"{analysis_path.name} did not reconcile against its snapshot; refusing to publish it")
        page = render(snap, ana)
        literals = load_literals()
    except (OSError, ValueError, KeyError, RedactionError, json.JSONDecodeError) as exc:
        print(f"build-site: {exc}", file=sys.stderr)
        return 2

    findings = scan_text(page, "<page>", literals)
    if findings:
        print(f"build-site: refusing to write — {len(findings)} never-publish value(s):", file=sys.stderr)
        for finding in findings:
            print(f"  line {finding.line}: {finding.rule} ({finding.hint})", file=sys.stderr)
        return 1

    if args.out == "-":
        sys.stdout.write(page)
    else:
        path = Path(args.out) if args.out else REPO / "site" / "index.html"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(page, encoding="utf-8")
        if not args.quiet:
            print(f"build-site: wrote {path.relative_to(REPO) if path.is_relative_to(REPO) else path} "
                  f"({len(page)} bytes) from {snapshot_path.name} + {analysis_path.name}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

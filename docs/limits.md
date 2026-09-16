# What this data cannot tell you

The page reports what arrived at one SSH honeypot. This file is the longer version of its Limits section: the things
a reader should not conclude, and why.

## The sample is one machine

One sensor, one address, one cloud region, a few days. Honeypot traffic is strongly shaped by which address block you
happen to sit in — scanners work through ranges, and a neighbouring address in the same provider will see a similar
crowd while a residential address sees a different one. Nothing here is a measurement of "the internet". A second
sensor elsewhere would produce a different top ten and might produce different conclusions.

The window also starts when the sensor did, which is not the same as "since the beginning". A program that scans on a
monthly cycle is invisible to a three-day window, and nothing here can distinguish "rare" from "not yet seen".

## The trap shapes the measurement

Cowrie accepts almost any password. That is what makes the credential lists readable — a real server would refuse
them and the attacker would move on — but it means:

- **The number of "successful" logins is a property of the honeypot, not of the attackers.** 12,843 accepted logins
  says the trap said yes 12,843 times.
- **The commands are what a program runs after an easy win.** Anything that only runs after a harder check, or after
  a working exploit, never appears.
- **Cowrie is emulated, and emulation is detectable.** Its filesystem, its responses and its timing can all be
  fingerprinted. Anything careful enough to check would disconnect without showing its hand, so the most capable
  visitors are precisely the ones least likely to be in this data. What is measured here is the automated, indifferent
  end of the spectrum.

## Fingerprints group tools, not people

The clustering uses hassh, the fingerprint of the SSH client's key-exchange offer. It identifies a **build of a
program**, which means:

- Two unrelated operators running the same off-the-shelf scanner share a fingerprint and will be shown as one cluster.
- One operator using two different tools appears as two clusters.
- A tool that randomises its key-exchange offer would not cluster at all.

So "about thirty programs" is a statement about software, not about how many people or groups are out there. Nothing
in this data supports a claim about who runs them.

## Addresses are where packets came from, and nothing more

Source addresses are published in full because they attacked an internet-facing sensor, but an address is not an
attacker:

- Many are compromised third parties — someone else's router, camera or server — so naming them identifies a victim
  as much as an aggressor.
- Cloud and hosting addresses are rented by the hour and will belong to someone else next week. Two of the clusters
  here sit in commercial hosting ranges.
- Nothing here should be used as a blocklist. A list built from one sensor over three days is stale almost
  immediately, and blocking a shared hosting address costs more than it saves.

## Geography and network attribution are weak here

- The country label comes from a geolocation database and reflects **what the database says**, not where an operator
  sits. This data contains an address labelled `KR` whose network is registered to a US entity, and a block labelled
  `US` that RIPE administers.
- The database has no network operator at all for 7 of the addresses, and those account for **68% of all events**.
  That is why the page prints no "top networks" ranking: it would describe a third of the traffic while appearing to
  describe all of it.
- Most importantly, geography cuts across operators. The second-largest cluster runs from Germany, the United States,
  Vietnam and China at once. A country ranking splits it into four rows and invites a conclusion about nations that
  the data does not support.

## Time to first attack is an external fact

The "57 minutes" figure needs one thing the honeypot cannot record: the moment the port became reachable. That comes
from the lab's own deployment record and is stored as a constant in `scripts/analyse.py`, marked as an external
input. If that record were wrong, the figure would be wrong, and no amount of honeypot data would reveal it.

It is also a single observation. It says a scanner found one address in under an hour on one occasion; it does not
establish an average.

## What is deliberately not claimed

- **No malware family is named.** Strings such as `echo xsec` and `locate D877F783D5D3EF8C` are widely reported as
  bot markers, but this project has not verified that mapping against a sample, so the clusters are described by
  behaviour and left unnamed.
- **No intent is inferred.** A program that logs in, runs `uname`, and leaves may be building an inventory, checking
  for a specific architecture, or failing at something. The data shows the command, not the reason.
- **No trend is claimed.** Three days of data, with one day partially covered at each end, cannot support "rising",
  "falling" or "seasonal".

## What would make this stronger

In rough order of value: a longer window, so rare and periodic visitors appear; a second sensor in a different address
block, to separate what the internet does from what this neighbourhood does; and a comparison against a published
baseline, so the figures here can be checked against someone else's. Until then, this is one machine's experience,
reported carefully.

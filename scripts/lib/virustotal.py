"""Ask VirusTotal what it already knows about a hash (CLAUDE.md H5).

A lookup, never an upload. Submitting a captured sample would publish someone else's data and could tell an operator
that their tool landed in a honeypot; sending a hash asks a question about a file the service has very probably
already seen. This module therefore has no code path that sends file content — only `GET /api/v3/files/<sha256>`.

Results are cached on disk, so a re-run of the analysis costs no requests and produces the same file. The free tier
allows four requests a minute; the honeypot has captured four hashes.
"""
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

API = "https://www.virustotal.com/api/v3/files/"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SECONDS_BETWEEN_REQUESTS = 16  # four a minute, with room to spare


class VirusTotalError(Exception):
    """The lookup could not be made."""


def api_key(env_file: Path) -> str | None:
    """VT_API_KEY from the environment, or from the git-ignored .env file."""
    key = os.environ.get("VT_API_KEY", "").strip()
    if key:
        return key
    if not env_file.is_file():
        return None
    for line in env_file.read_text(encoding="utf-8").splitlines():
        name, sep, value = line.partition("=")
        if sep and name.strip() == "VT_API_KEY":
            return value.strip().strip("'\"") or None
    return None


def summarise(payload: dict) -> dict:
    """The few fields worth publishing, from VirusTotal's very large response."""
    attributes = (payload.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    names = [str(name) for name in (attributes.get("names") or [])][:5]
    return {
        "found": True,
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "undetected": int(stats.get("undetected", 0)),
        "type": str(attributes.get("type_description") or ""),
        "size_bytes": int(attributes.get("size", 0)),
        "first_submitted": int(attributes.get("first_submission_date", 0)),
        "times_submitted": int(attributes.get("times_submitted", 0)),
        "popular_label": str(((attributes.get("popular_threat_classification") or {})
                              .get("suggested_threat_label")) or ""),
        "names_on_virustotal": names,
    }


def lookup(sha256: str, key: str, timeout: int = 20) -> dict:
    """One hash. Returns a summary, or {'found': False} when VirusTotal has never seen it."""
    if not SHA256_RE.match(sha256):
        raise VirusTotalError(f"{sha256!r} is not a SHA-256 hash")
    request = urllib.request.Request(API + sha256, headers={"x-apikey": key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return summarise(json.loads(response.read().decode("utf-8")))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {"found": False}
        if error.code in (401, 403):
            raise VirusTotalError("VirusTotal rejected the API key (401/403)") from None
        if error.code == 429:
            raise VirusTotalError("VirusTotal rate limit reached (429); try again later") from None
        raise VirusTotalError(f"VirusTotal returned HTTP {error.code}") from None
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        raise VirusTotalError(f"VirusTotal request failed: {exc}") from None


def lookup_all(hashes: list[str], key: str, cache_path: Path, log=None) -> dict[str, dict]:
    """Every hash, cached. Only uncached hashes cost a request."""
    cache: dict[str, dict] = {}
    if cache_path.is_file():
        try:
            cache = json.loads(cache_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            cache = {}
    wanted = [h for h in dict.fromkeys(hashes) if SHA256_RE.match(h)]
    pending = [h for h in wanted if h not in cache]
    for index, sha256 in enumerate(pending):
        if index:
            time.sleep(SECONDS_BETWEEN_REQUESTS)
        if log:
            log(f"virustotal: looking up {sha256[:16]}… ({index + 1}/{len(pending)})")
        cache[sha256] = lookup(sha256, key)
    if pending:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(cache, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return {sha256: cache[sha256] for sha256 in wanted if sha256 in cache}

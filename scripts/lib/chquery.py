"""Read-only queries against the NSM lab's `nsm` database (CLAUDE.md H1).

Everything goes through `docker exec … clickhouse-client`, so no credentials live in this repository and no port is
exposed. This module runs SELECTs and nothing else: the lab owns that data, and this project only reads it.
"""
import json
import os
import shutil
import subprocess

CONTAINER = os.environ.get("HP_CH_CONTAINER", "nsm-clickhouse")
DATABASE = os.environ.get("HP_CH_DATABASE", "nsm")


class QueryError(Exception):
    """ClickHouse is unreachable, or the query failed."""


def query(sql: str, params: dict | None = None) -> list[dict]:
    """Run a SELECT and return its rows as dicts.

    Values that come from outside the code (a window bound, a dataset name) are passed as ClickHouse query
    parameters — `{name:String}` in the SQL — never formatted into the statement.
    """
    if not sql.lstrip().upper().startswith(("SELECT", "WITH")):
        raise QueryError("only SELECT/WITH statements belong here (H1: this project never writes to nsm)")
    if shutil.which("docker") is None:
        raise QueryError("docker is not installed")
    command = ["docker", "exec", "-i", CONTAINER, "clickhouse-client", "--database", DATABASE,
               "--format", "JSONEachRow"]
    for name, value in (params or {}).items():
        command.append(f"--param_{name}={value}")
    command += ["--query", sql]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise QueryError(f"could not run clickhouse-client: {exc}") from None
    if result.returncode != 0:
        # clickhouse-client echoes the whole query after the error, so pick the exception line, not the last line
        lines = [line.strip() for line in (result.stderr or "").splitlines() if line.strip()]
        detail = next((line for line in lines if "Exception" in line), lines[0] if lines else "")
        raise QueryError(detail or f"clickhouse-client exited {result.returncode}")
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def scalar(sql: str, params: dict | None = None):
    rows = query(sql, params)
    return next(iter(rows[0].values())) if rows else None

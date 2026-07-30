#!/usr/bin/env python3
"""Bulk-enrich file hashes with PolySwarm threat intelligence.

A standalone reference utility for analysts. Takes hashes from the command line,
a file, or standard input; looks each one up in the PolySwarm v3 API; and emits
JSON, CSV, or STIX 2.1.

Operates on hashes only. It never reads, opens, or uploads file contents, which
makes it safe to run against hash lists exported from environments where the
files themselves must not leave the network.

Requires Python 3.10+. Standard library only; no third-party dependencies.
Needs outbound HTTPS to api.polyswarm.network.

  export POLYSWARM_API_KEY=...
  ./polyswarm_enrich.py 5da5a1e3983982a92341953929d4c7726da65fe5125d264dd8932a870f2f154a
  ./polyswarm_enrich.py --input-file hashes.txt --format csv --output out.csv
  defender-export.csv | cut -d, -f3 | ./polyswarm_enrich.py - --format stix
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

DEFAULT_BASE_URL = "https://api.polyswarm.network/v3"
DEFAULT_COMMUNITY = "default"
DEFAULT_THRESHOLD = 0.8
DEFAULT_RATE_LIMIT = 60  # requests per minute
DEFAULT_RETRIES = 3
DEFAULT_TIMEOUT = 30
USER_AGENT = "polyswarm-enrich/1.0 (+https://polyswarm.io)"

# Hash type is derived from length rather than trusting any upstream label.
HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}
HEX_RE = re.compile(r"\A[0-9a-fA-F]+\Z")

# STIX 2.1 hash key names differ from ours.
STIX_HASH_KEYS = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}

CSV_COLUMNS = [
    "query", "hash_type", "found", "assessment", "polyscore",
    "malicious", "benign", "total", "malware_family", "labels",
    "malicious_engines", "imphash", "packer", "file_type", "size",
    "first_seen", "last_seen", "permalink", "error",
]


class FatalError(Exception):
    """Unrecoverable: bad credentials, bad configuration. Aborts the run."""


# --------------------------------------------------------------------------- #
# Input
# --------------------------------------------------------------------------- #

def detect_hash_type(value: str) -> str | None:
    """Return 'md5', 'sha1', 'sha256', or None if it isn't a usable hash."""
    if not HEX_RE.match(value):
        return None
    return HASH_TYPES.get(len(value))


def read_hashes(args: argparse.Namespace) -> list[str]:
    """Collect hashes from positional args, --input-file, and/or stdin.

    Order is preserved and duplicates are dropped, so a 5000-row export with
    repeats costs one lookup per distinct hash.
    """
    raw: list[str] = []

    for item in args.hashes:
        if item == "-":
            raw.extend(sys.stdin.read().split())
        else:
            raw.append(item)

    if args.input_file:
        with open(args.input_file, "r", encoding="utf-8") as fh:
            raw.extend(fh.read().split())

    if not raw and not sys.stdin.isatty():
        raw.extend(sys.stdin.read().split())

    seen: set[str] = set()
    ordered: list[str] = []
    for item in raw:
        # Tolerate CSV fragments and quoting from spreadsheet exports.
        cleaned = item.strip().strip('"\'').strip(",").lower()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            ordered.append(cleaned)
    return ordered


def resolve_api_key(args: argparse.Namespace) -> str:
    """Precedence: --api-key, then --key-file, then POLYSWARM_API_KEY."""
    if args.api_key:
        return args.api_key.strip()
    if args.key_file:
        try:
            with open(args.key_file, "r", encoding="utf-8") as fh:
                key = fh.read().strip()
        except OSError as exc:
            raise FatalError(f"could not read key file: {exc}") from exc
        if not key:
            raise FatalError(f"key file is empty: {args.key_file}")
        return key
    key = os.environ.get("POLYSWARM_API_KEY", "").strip()
    if not key:
        raise FatalError(
            "no API key. Set POLYSWARM_API_KEY, or pass --api-key / --key-file."
        )
    return key


# --------------------------------------------------------------------------- #
# API client
# --------------------------------------------------------------------------- #

class PolySwarmClient:
    """Minimal v3 client with throttling and retry.

    Community-tier accounts are limited to 60 requests per hour, so the default
    of 60/minute will exhaust that quota in one minute. Pass --rate-limit 1 on a
    community key.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        community: str = DEFAULT_COMMUNITY,
        rate_limit: int = DEFAULT_RATE_LIMIT,
        retries: int = DEFAULT_RETRIES,
        timeout: int = DEFAULT_TIMEOUT,
        verbose: bool = False,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.community = community
        self.min_interval = 60.0 / rate_limit if rate_limit > 0 else 0.0
        self.retries = retries
        self.timeout = timeout
        self.verbose = verbose
        self._last_request = 0.0

    def _log(self, message: str) -> None:
        if self.verbose:
            print(f"[polyswarm] {message}", file=sys.stderr)

    def _throttle(self) -> None:
        if self.min_interval <= 0:
            return
        elapsed = time.monotonic() - self._last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)

    def get(self, path: str, params: dict[str, str]) -> tuple[int, Any]:
        """GET with retry. Returns (status_code, decoded_body_or_None).

        404 is a normal outcome (artifact never scanned), not an error, so it is
        returned rather than raised.
        """
        query = urllib.parse.urlencode({**params, "community": self.community})
        url = f"{self.base_url}{path}?{query}"

        for attempt in range(1, self.retries + 2):
            self._throttle()
            request = urllib.request.Request(
                url,
                headers={
                    "Authorization": self.api_key,
                    "Accept": "application/json",
                    "User-Agent": USER_AGENT,
                },
                method="GET",
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    self._last_request = time.monotonic()
                    return response.status, json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                self._last_request = time.monotonic()
                if exc.code in (401, 403):
                    raise FatalError(
                        f"authentication failed (HTTP {exc.code}). Check the API key."
                    ) from exc
                if exc.code == 404:
                    return 404, None
                if exc.code in (408, 429) or exc.code >= 500:
                    if attempt <= self.retries:
                        backoff = min(2 ** attempt, 60)
                        self._log(f"HTTP {exc.code}, retrying in {backoff}s")
                        time.sleep(backoff)
                        continue
                return exc.code, None
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                self._last_request = time.monotonic()
                if attempt <= self.retries:
                    backoff = min(2 ** attempt, 60)
                    self._log(f"{type(exc).__name__}, retrying in {backoff}s")
                    time.sleep(backoff)
                    continue
                raise RuntimeError(str(exc)) from exc

        return 0, None


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

def _tool_metadata(record: dict[str, Any], tool: str) -> dict[str, Any]:
    """Pull one tool's metadata out of the scan record's metadata[] array."""
    for entry in record.get("metadata") or []:
        if isinstance(entry, dict) and entry.get("tool") == tool:
            return entry.get("tool_metadata") or {}
    return {}


def assess(polyscore: float | None, threshold: float) -> str:
    """Derive an assessment from PolyScore.

    Deliberately does NOT use the record's `result` field. Despite the name it
    tracks scan settlement, not maliciousness: a live scan of https://polyswarm.io
    returns result=true with 0 of 2 engines asserting malicious and a PolyScore of
    0.33. Treating it as a verdict marks known-good artifacts as malicious.
    """
    if polyscore is None:
        return "unknown"
    if polyscore >= threshold:
        return "malicious"
    if polyscore >= threshold / 2:
        return "suspicious"
    return "likely_benign"


def parse_scan_record(record: dict[str, Any], threshold: float) -> dict[str, Any]:
    """Flatten a v3 scan instance into the tool's output record."""
    detections = record.get("detections") or {}
    polyunite = _tool_metadata(record, "polyunite")
    pefile = _tool_metadata(record, "pefile")

    # verdict is True / False / None; None means the engine did not assert.
    engines = [
        a.get("engine", {}).get("name") or a.get("author_name")
        for a in record.get("assertions") or []
        if a.get("verdict") is True
    ]

    polyscore = record.get("polyscore")
    return {
        "found": True,
        "assessment": assess(polyscore, threshold),
        "polyscore": polyscore,
        "sha256": record.get("sha256"),
        "sha1": record.get("sha1"),
        "md5": record.get("md5"),
        "malicious": detections.get("malicious"),
        "benign": detections.get("benign"),
        "total": detections.get("total"),
        "malicious_engines": [e for e in engines if e],
        "malware_family": polyunite.get("malware_family"),
        "labels": polyunite.get("labels") or [],
        "imphash": pefile.get("imphash") or None,
        "packer": pefile.get("peid") or None,
        "file_type": record.get("extended_type"),
        "size": record.get("size"),
        "first_seen": record.get("first_seen"),
        "last_seen": record.get("last_seen"),
        "permalink": record.get("permalink"),
        "scan_settled": record.get("result"),
        "error": None,
    }


def empty_record(reason: str | None = None) -> dict[str, Any]:
    return {
        "found": False, "assessment": "not_found", "polyscore": None,
        "sha256": None, "sha1": None, "md5": None,
        "malicious": None, "benign": None, "total": None,
        "malicious_engines": [], "malware_family": None, "labels": [],
        "imphash": None, "packer": None, "file_type": None, "size": None,
        "first_seen": None, "last_seen": None, "permalink": None,
        "scan_settled": None, "error": reason,
    }


def enrich(
    client: PolySwarmClient, hashes: Iterable[str], threshold: float
) -> Iterator[dict[str, Any]]:
    for value in hashes:
        hash_type = detect_hash_type(value)
        if hash_type is None:
            yield {"query": value, "hash_type": None,
                   **empty_record("not a valid MD5, SHA1 or SHA256 hash")}
            continue

        client._log(f"{hash_type} {value}")
        try:
            status, payload = client.get(f"/search/hash/{hash_type}", {"hash": value})
        except RuntimeError as exc:
            yield {"query": value, "hash_type": hash_type,
                   **empty_record(f"request failed: {exc}")}
            continue

        if status == 404:
            yield {"query": value, "hash_type": hash_type, **empty_record()}
            continue
        if status != 200 or not isinstance(payload, dict):
            yield {"query": value, "hash_type": hash_type,
                   **empty_record(f"HTTP {status}")}
            continue

        results = payload.get("result") or []
        if not results:
            yield {"query": value, "hash_type": hash_type, **empty_record()}
            continue

        yield {"query": value, "hash_type": hash_type,
               **parse_scan_record(results[0], threshold)}


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def render_json(records: list[dict[str, Any]]) -> str:
    return json.dumps(records, indent=2, sort_keys=False)


def render_csv(records: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for record in records:
        row = dict(record)
        row["labels"] = ";".join(record.get("labels") or [])
        row["malicious_engines"] = ";".join(record.get("malicious_engines") or [])
        writer.writerow(row)
    return buffer.getvalue()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def render_stix(records: list[dict[str, Any]], threshold: float) -> str:
    """Emit a STIX 2.1 bundle of indicators.

    Only artifacts assessed malicious or suspicious become indicators; emitting
    an indicator for a benign or unseen hash would assert something the data
    does not support.
    """
    timestamp = _now()
    objects: list[dict[str, Any]] = []

    for record in records:
        if record.get("assessment") not in ("malicious", "suspicious"):
            continue
        hash_type = record.get("hash_type") or "sha256"
        value = record.get(hash_type) or record.get("query")
        stix_key = STIX_HASH_KEYS.get(hash_type, "SHA-256")

        name = record.get("malware_family") or "PolySwarm detection"
        polyscore = record.get("polyscore")

        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": timestamp,
            "modified": timestamp,
            "name": f"{name} ({value[:12]}…)",
            "description": (
                f"PolySwarm assessed this artifact as {record['assessment']} "
                f"(PolyScore {polyscore}). "
                f"{record.get('malicious')} of {record.get('total')} engines "
                f"asserted malicious."
            ),
            "indicator_types": ["malicious-activity"],
            "pattern": f"[file:hashes.'{stix_key}' = '{value}']",
            "pattern_type": "stix",
            "valid_from": record.get("first_seen") or timestamp,
        }
        if isinstance(polyscore, (int, float)):
            indicator["confidence"] = max(0, min(100, round(polyscore * 100)))
        if record.get("labels"):
            indicator["labels"] = record["labels"]
        if record.get("permalink"):
            indicator["external_references"] = [
                {"source_name": "PolySwarm", "url": record["permalink"]}
            ]
        objects.append(indicator)

    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    return json.dumps(bundle, indent=2)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="polyswarm_enrich.py",
        description="Bulk-enrich file hashes with PolySwarm threat intelligence.",
        epilog=(
            "Operates on hashes only. Never reads or uploads file contents.\n\n"
            "Community-tier keys allow 60 requests per HOUR: use --rate-limit 1.\n"
            "Enterprise keys can use the default of 60 per minute or higher."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("hashes", nargs="*",
                        help="hashes to enrich; use '-' to read from stdin")
    parser.add_argument("-i", "--input-file", help="file containing whitespace- or newline-separated hashes")
    parser.add_argument("-f", "--format", choices=("json", "csv", "stix"), default="json",
                        help="output format (default: json)")
    parser.add_argument("-o", "--output", help="write to this file instead of stdout")
    parser.add_argument("--api-key", help="API key (prefer POLYSWARM_API_KEY or --key-file)")
    parser.add_argument("--key-file", help="file containing the API key")
    parser.add_argument("-c", "--community", default=DEFAULT_COMMUNITY,
                        help=f"PolySwarm community (default: {DEFAULT_COMMUNITY})")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=argparse.SUPPRESS)
    parser.add_argument("-t", "--threshold", type=float, default=DEFAULT_THRESHOLD,
                        help=f"PolyScore at or above which an artifact is assessed malicious "
                             f"(default: {DEFAULT_THRESHOLD}); half this value is 'suspicious'")
    parser.add_argument("-r", "--rate-limit", type=int, default=DEFAULT_RATE_LIMIT,
                        help=f"maximum requests per minute, 0 to disable (default: {DEFAULT_RATE_LIMIT})")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES,
                        help=f"retries on 429/5xx/timeout (default: {DEFAULT_RETRIES})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"per-request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="progress to stderr")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not 0.0 < args.threshold <= 1.0:
        print("error: --threshold must be between 0 and 1", file=sys.stderr)
        return 2

    try:
        api_key = resolve_api_key(args)
    except FatalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    hashes = read_hashes(args)
    if not hashes:
        print("error: no hashes supplied. See --help.", file=sys.stderr)
        return 2

    client = PolySwarmClient(
        api_key=api_key, base_url=args.base_url, community=args.community,
        rate_limit=args.rate_limit, retries=args.retries,
        timeout=args.timeout, verbose=args.verbose,
    )

    try:
        records = list(enrich(client, hashes, args.threshold))
    except FatalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130

    if args.format == "csv":
        output = render_csv(records)
    elif args.format == "stix":
        output = render_stix(records, args.threshold)
    else:
        output = render_json(records)

    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as fh:
            fh.write(output)
        if args.verbose:
            print(f"[polyswarm] wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(output if output.endswith("\n") else output + "\n")

    if args.verbose:
        found = sum(1 for r in records if r["found"])
        flagged = sum(1 for r in records if r["assessment"] in ("malicious", "suspicious"))
        print(f"[polyswarm] {len(records)} queried, {found} found, {flagged} flagged",
              file=sys.stderr)

    return 1 if any(r.get("error") for r in records) else 0


if __name__ == "__main__":
    sys.exit(main())

# PolySwarm bulk hash enrichment tool

A standalone command-line utility that enriches file hashes with PolySwarm threat
intelligence and emits JSON, CSV or STIX 2.1.

It is designed for the manual analyst workflow: take a list of hashes exported from a
SIEM or EDR hunting query, get verdicts and context back in a form you can paste into
a case note, load into a spreadsheet, or ingest as indicators.

**It operates on hashes only.** It never reads, opens, or uploads file contents. That
makes it safe to run against hash lists exported from environments where the files
themselves must not leave the network.

---

## Requirements

- Python 3.10 or newer
- Standard library only — no `pip install`, no virtualenv
- Outbound HTTPS to `api.polyswarm.network`
- A PolySwarm API key ([generate one](https://polyswarm.network/account/api-keys))

## Setup

```bash
export POLYSWARM_API_KEY=your-key-here
chmod +x polyswarm_enrich.py
```

The key can also come from `--key-file /path/to/key` or, less safely, `--api-key`.
A key passed on the command line is visible in your shell history and process list;
prefer the environment variable or a mode-600 key file.

## Usage

```bash
# one hash
./polyswarm_enrich.py 5da5a1e3983982a92341953929d4c7726da65fe5125d264dd8932a870f2f154a

# a file of hashes, to CSV
./polyswarm_enrich.py --input-file hashes.txt --format csv --output enriched.csv

# a column piped from a hunting export, to STIX
cut -d, -f3 defender-export.csv | ./polyswarm_enrich.py - --format stix -o iocs.json

# large batch, unthrottled
./polyswarm_enrich.py -i hashes.txt --rate-limit 0 --verbose
```

MD5, SHA1 and SHA256 are auto-detected from length and routed to the matching
endpoint, so mixed lists work. Input is de-duplicated case-insensitively with order
preserved — a 5,000-row export with repeats costs one lookup per distinct hash.

## Options

| Option | Default | Notes |
| --- | --- | --- |
| `-i`, `--input-file` | — | Whitespace- or newline-separated hashes |
| `-f`, `--format` | `json` | `json`, `csv` or `stix` |
| `-o`, `--output` | stdout | Write to a file instead |
| `-c`, `--community` | `default` | Set this if you use a private community |
| `-t`, `--threshold` | `0.8` | PolyScore at or above which an artifact is assessed malicious; half this value is "suspicious" |
| `-r`, `--rate-limit` | `600` | Max requests per minute. `0` disables throttling |
| `--retries` | `3` | Retries on 429, 5xx and timeouts, with exponential backoff |
| `--timeout` | `30` | Per-request timeout in seconds |
| `-v`, `--verbose` | off | Progress and a summary line to stderr |

**Rate limits.** The default of 600 requests/minute is a deliberately conservative
enterprise-tier setting — comfortably inside the quota while leaving headroom for
anything else using the same key. Raise it or pass `--rate-limit 0` to disable
throttling if your quota allows.

Throttling is client-side only: it paces requests, it does not know your actual quota.
If you see `429`s, lower it. The tool retries `429` with exponential backoff regardless.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | All lookups completed |
| `1` | Completed, but at least one hash errored (malformed input, HTTP failure) |
| `2` | Fatal: no API key, bad credentials, bad arguments, no input |
| `130` | Interrupted |

A `404` is **not** an error. It means PolySwarm has never scanned that artifact, which
is a meaningful result — those rows come back with `assessment: not_found` and a null
`error`, and the run still exits `0`.

## Output

Every record carries `query`, `hash_type`, `found`, `assessment`, `polyscore`,
detection counts, `malicious_engines`, `malware_family`, `labels`, `imphash`,
`packer`, `file_type`, `size`, `first_seen`, `last_seen` and `permalink`.

`assessment` is one of `malicious`, `suspicious`, `likely_benign`, `unknown` or
`not_found`.

### STIX 2.1

`--format stix` emits a bundle of `indicator` objects with a
`[file:hashes.'SHA-256' = '…']` pattern, `confidence` scaled from PolyScore, PolyUnite
labels, and an external reference to the PolySwarm report.

Only artifacts assessed **malicious or suspicious** become indicators. Emitting an
indicator for a benign or never-seen hash would assert something the data does not
support, and would pollute whatever consumes the bundle.

---

## A note on the `result` field

The v3 API returns a boolean `result` on each scan record. **It is not a maliciousness
verdict** — it tracks scan settlement. A live scan of `https://polyswarm.io` returns
`result: true` alongside 0 of 2 engines asserting malicious and a PolyScore of 0.33.

This tool derives `assessment` from **PolyScore only**, and carries the raw field
through as `scan_settled` so it cannot be mistaken for a verdict. There is a
regression test covering exactly this. If you write your own integration against the
v3 API, do the same.

## Tests

No API key or network needed — the HTTP layer is stubbed and the fixtures are trimmed
copies of real v3 responses.

```bash
python3 -m unittest test_polyswarm_enrich -v
```

## Support

PolySwarm Customer Success — customersuccess@polyswarm.io

API reference: <https://docs.polyswarm.io/customers/polyswarm-rest-api-v3>

#!/usr/bin/env python3
"""Splunk external lookup for Reput.io.

Splunk sends a CSV on stdin with the lookup fields as headers and expects the
same CSV back on stdout with the output fields filled in. Unique indicators are
looked up in batches, so a search over thousands of events costs one query per
distinct IP or domain.

Copy this file and ../../python/reputio.py into $SPLUNK_HOME/etc/apps/<app>/bin/
and set the API key in the environment Splunk runs scripts with (REPUTIO_API_KEY),
or in local/reputio_api_key.txt as shown in the README. If the API call fails,
rows are returned unenriched and the error goes to stderr (search.log).
"""

import csv
import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _here)  # Splunk: reputio.py copied next to this script
sys.path.insert(1, os.path.join(_here, "..", "..", "python"))  # running from the repo
from reputio import Reputio, normalize  # noqa: E402

OUTPUT = {
    "reputio_status": lambda r: r.get("status", ""),
    "reputio_verdict": lambda r: r.get("verdict", ""),
    "reputio_risk": lambda r: r.get("risk_level", ""),
    "reputio_provider": lambda r: (r.get("provider") or {}).get("name", ""),
    "reputio_action": lambda r: (r.get("recommendation") or {}).get("action", ""),
    "reputio_categories": lambda r: "|".join(r.get("categories") or []),
}


def api_key():
    key = os.environ.get("REPUTIO_API_KEY")
    if key:
        return key
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "local", "reputio_api_key.txt")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip() or None
    return None


def main():
    infield = sys.argv[1] if len(sys.argv) > 1 else "indicator"
    batch = int(os.environ.get("REPUTIO_BATCH_SIZE", "10"))
    reader = csv.DictReader(sys.stdin)
    fields = list(reader.fieldnames or [])
    rows = list(reader)

    unique = sorted({normalize(r.get(infield)) for r in rows} - {""})
    results = {}
    if unique:
        try:
            results = Reputio(api_key=api_key(), batch_size=batch).lookup_map(unique)
        except Exception as e:  # fail soft: return rows unenriched, never break the search
            print(f"reputio_lookup: lookup failed: {e}", file=sys.stderr)

    out = csv.DictWriter(sys.stdout, fieldnames=fields)
    out.writeheader()
    for row in rows:
        res = results.get(normalize(row.get(infield)))
        if res:
            for name, get in OUTPUT.items():
                if name in row:
                    row[name] = get(res)
        out.writerow(row)


if __name__ == "__main__":
    main()

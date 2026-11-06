"""Enrich a CSV of indicators with Reput.io verdicts.

    export REPUTIO_API_KEY=rpt_...
    python enrich_csv.py alerts.csv --column src_ip --batch-size 10 > enriched.csv

Adds reputio_status, reputio_verdict, reputio_risk, reputio_provider,
reputio_action and reputio_categories columns. Rows are kept in their original
order; indicators are deduplicated before lookup so repeated IPs cost one query.
"""

import argparse
import csv
import sys

from reputio import Reputio, normalize

EXTRA = ["reputio_status", "reputio_verdict", "reputio_risk", "reputio_provider",
         "reputio_action", "reputio_categories"]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("csv_file")
    ap.add_argument("--column", required=True, help="column holding the indicator")
    ap.add_argument("--batch-size", type=int, default=10, help="10 Free/Starter, 50 Pro, 100 Team/Enterprise")
    args = ap.parse_args()

    with open(args.csv_file, newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fields = list(reader.fieldnames or [])

    unique = sorted({normalize(r[args.column]) for r in rows if r.get(args.column)} - {""})
    by_indicator = Reputio(batch_size=args.batch_size).lookup_map(unique)

    out = csv.DictWriter(sys.stdout, fieldnames=fields + EXTRA)
    out.writeheader()
    for row in rows:
        res = by_indicator.get(normalize(row.get(args.column)), {})
        row.update({
            "reputio_status": res.get("status", ""),
            "reputio_verdict": res.get("verdict", ""),
            "reputio_risk": res.get("risk_level", ""),
            "reputio_provider": (res.get("provider") or {}).get("name", ""),
            "reputio_action": (res.get("recommendation") or {}).get("action", ""),
            "reputio_categories": "|".join(res.get("categories") or []),
        })
        out.writerow(row)


if __name__ == "__main__":
    main()

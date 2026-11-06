"""Enrich recent Elastic Security alerts with Reput.io verdicts.

Reads alerts from the last N hours, looks up each distinct source/destination IP
once, and writes the result back to the alert document under `reputio.*`.

    pip install -r requirements.txt
    export ES_URL=https://your-cluster:9200 ES_API_KEY=... REPUTIO_API_KEY=rpt_...
    python enrich_alerts.py --index ".alerts-security.alerts-default" --hours 1

Uses only the Elasticsearch REST API (search + update), so it works with any
recent Elastic Stack version. Run it from cron or a scheduled job.
"""

import argparse
import os
import sys

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))
from reputio import Reputio, normalize  # noqa: E402

FIELDS = ["source.ip", "destination.ip"]
# Worst verdict wins when an alert has several indicators.
SEVERITY = {"malicious": 4, "suspicious": 3, "investigate": 2, "context_only": 1, "likely_benign": 0}


def es(method, path, **kw):
    r = requests.request(method, os.environ["ES_URL"].rstrip("/") + path,
                         headers={"Authorization": "ApiKey " + os.environ["ES_API_KEY"]},
                         timeout=60, **kw)
    r.raise_for_status()
    return r.json()


def values(hit, field):
    """Field values from the search `fields` section (handles dotted keys and arrays)."""
    return [v for v in (hit.get("fields") or {}).get(field, []) if v]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default=".alerts-security.alerts-default")
    ap.add_argument("--hours", type=int, default=1)
    ap.add_argument("--batch-size", type=int, default=10)
    args = ap.parse_args()

    hits = es("POST", f"/{args.index}/_search", json={
        "size": 1000,
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": f"now-{args.hours}h"}}}],
            "must_not": [{"exists": {"field": "reputio.verdict"}}],
        }},
        "_source": False,
        "fields": FIELDS,
    })["hits"]["hits"]

    ips = sorted({normalize(v) for h in hits for f in FIELDS for v in values(h, f)} - {""})
    results = Reputio(batch_size=args.batch_size).lookup_map(ips)

    updated = 0
    for h in hits:
        doc, worst = {}, None
        for f in FIELDS:
            for v in values(h, f):
                res = results.get(normalize(v))
                if not res:
                    continue
                doc[f.split(".")[0]] = {
                    "status": res.get("status"),
                    "verdict": res.get("verdict"),
                    "risk_level": res.get("risk_level"),
                    "provider": (res.get("provider") or {}).get("name"),
                    "categories": res.get("categories"),
                }
                if worst is None or SEVERITY.get(res.get("verdict"), 2) > SEVERITY.get(worst, 2):
                    worst = res.get("verdict")
        if doc:
            doc["verdict"] = worst
            es("POST", f"/{h['_index']}/_update/{h['_id']}", json={"doc": {"reputio": doc}})
            updated += 1
    print(f"enriched {updated} of {len(hits)} alerts, {len(ips)} distinct IPs (first 1000 alerts per run)")


if __name__ == "__main__":
    main()

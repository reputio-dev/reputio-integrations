# curl

```bash
export REPUTIO_API_KEY=rpt_your_key_here

curl -s -X POST https://api.reput.io/lookup \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $REPUTIO_API_KEY" \
  -d '{"indicators": ["8.8.8.8", "cloudflare.com", "91.202.233.27"]}' | jq .
```

One line per result, for quick triage:

```bash
curl -s -X POST https://api.reput.io/lookup \
  -H "Content-Type: application/json" -H "X-Api-Key: $REPUTIO_API_KEY" \
  -d '{"indicators": ["8.8.8.8", "cloudflare.com", "91.202.233.27"]}' \
| jq -r '.results[] | [.indicator, .status, .verdict, .risk_level, (.provider.name // "-")] | @tsv'
```

Example output:

```
8.8.8.8         whitelisted  likely_benign  info    Public DNS Resolver
cloudflare.com  whitelisted  investigate    medium  Cloudflare
91.202.233.27   threat       malicious      high    -
```

Check your remaining quota in the response headers:

```bash
curl -s -D - -o /dev/null -X POST https://api.reput.io/lookup \
  -H "Content-Type: application/json" -H "X-Api-Key: $REPUTIO_API_KEY" \
  -d '{"indicators": ["8.8.8.8"]}' | grep -i x-ratelimit
```

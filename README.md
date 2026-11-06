# Reput.io integrations

Examples for wiring the [Reput.io](https://www.reput.io) reputation API into SOC
tooling. Reput.io classifies IPs, domains, hostnames and URLs in one call, so an
analyst can clear known-good infrastructure quickly and spot known-bad
infrastructure without switching tools.

| Folder | What's inside |
|---|---|
| [`openapi.yaml`](openapi.yaml) | OpenAPI 3.1 description of the Lookup API |
| [`python/`](python/) | Dependency-free Python client and a CSV enrichment script |
| [`splunk/`](splunk/) | External lookup to enrich any search |
| [`sentinel/`](sentinel/) | Logic App playbook steps to enrich incidents |
| [`elastic/`](elastic/) | Script that writes verdicts back onto Elastic Security alerts |
| [`curl/`](curl/) | One-liners for quick checks |

## Quick start

1. Create a free account at [reput.io](https://www.reput.io) and copy your API key.
2. Run a lookup:

   ```bash
   curl -s -X POST https://api.reput.io/lookup \
     -H "Content-Type: application/json" \
     -H "X-Api-Key: rpt_your_key_here" \
     -d '{"indicators": ["8.8.8.8", "cloudflare.com"]}'
   ```

3. Or from Python:

   ```python
   from reputio import Reputio
   for r in Reputio(api_key="rpt_...").lookup(["8.8.8.8", "cloudflare.com"]):
       print(r["indicator"], r["status"], r["verdict"])
   ```

## How to read a result

| `status` | Meaning |
|---|---|
| `whitelisted` | Known-good source matched |
| `enrichment` | Known infrastructure with context, not auto-trusted |
| `threat` | Listed by a threat intelligence feed (always wins over a whitelist match) |
| `unknown` | No intel on this indicator |

| `verdict` | What to do |
|---|---|
| `likely_benign` | First-party infrastructure that doesn't sell general hosting. Deprioritise. |
| `context_only` | Free plan, enrichment results: known infrastructure, analysis fields are on paid plans. |
| `investigate` | Look at it. Cloud, CDN, VPN and hosting addresses land here on purpose, because anyone can rent them. |
| `suspicious` | Reported for hostile behaviour such as scanning or brute force. |
| `malicious` | Listed as attack infrastructure. Escalate or block. |

Two rules shape every verdict:

- **Asymmetric trust.** A big brand's cloud is never automatically benign, because
  attackers rent VMs there too. Only services that don't sell general hosting
  earn `likely_benign`.
- **Shared infrastructure is never `malicious`.** If a threat feed lists a CDN edge
  or a big platform hostname, the verdict stays `investigate`: the feed caught one
  tenant, and blocking the shared address would break unrelated services.

Raw feed `reasons` and `categories` are always included, so you can see why.

## Batch sizes and limits

Indicators per request: Free 10, Starter 10, Pro 50, Team 100, Enterprise 100.
Daily and burst limits are returned in `X-RateLimit-*` headers; on `429`, honour
`Retry-After`. The Python client does this for you.

## Links

- [API documentation](https://www.reput.io/docs)
- [Lookup endpoint reference](https://www.reput.io/docs/lookup)
- [Pricing](https://www.reput.io/pricing)
- [Blog: Reputation Radar](https://www.reput.io/blog)

## License

The code in this repository is released under the MIT License. Use of the
Reput.io API itself is subject to the [terms of service](https://www.reput.io/terms-of-service).

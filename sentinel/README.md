# Microsoft Sentinel: enrich incident entities

Two ways to add Reput.io context to Sentinel incidents. Both call the same
`POST https://api.reput.io/lookup` endpoint.

## Option A: Logic App playbook (no code)

Create a playbook triggered by **Microsoft Sentinel incident**, then:

1. **Entities - Get IPs** (and/or **Get URLs / Get hosts**) from the incident.
2. **Select** the `Address` of each entity into an array.
3. **HTTP** action:

   ```json
   {
     "method": "POST",
     "uri": "https://api.reput.io/lookup",
     "headers": {
       "Content-Type": "application/json",
       "X-Api-Key": "@{parameters('ReputioApiKey')}"
     },
     "body": { "indicators": "@body('Select_IPs')" }
   }
   ```

   Keep the key in a secure parameter or Key Vault, not in the workflow body.
   Split arrays longer than your plan's batch size (10 Free/Starter, 50 Pro,
   100 Team/Enterprise) with a `chunk()` expression and a loop.
4. **Parse JSON** with the response schema from [`../openapi.yaml`](../openapi.yaml)
   (`components.schemas.LookupResponse`).
5. **Add comment to incident** with one line per result, for example
   `@{items('For_each')?['indicator']}: @{items('For_each')?['status']} / @{items('For_each')?['verdict']}`.
6. Optionally **add a tag** such as `reputio:malicious` when any result has
   `verdict == "malicious"`, and route those incidents to the top of the queue.

## Option B: Azure Function (Python)

Use [`../python/reputio.py`](../python/reputio.py) inside an HTTP-triggered
function that the playbook calls. Useful when you also want caching or custom
logic before writing back to the incident.

## Reading the results

- `status: threat` with `verdict: malicious`: listed by a threat feed as attack
  infrastructure. Escalate.
- `verdict: suspicious`: hostile behaviour reported (scanning, brute force).
- `verdict: investigate` on cloud, CDN or VPN addresses is intentional: they are
  shared or rentable, so check the hostname, tenant or user behind the traffic.
- `verdict: likely_benign`: first-party infrastructure that doesn't sell general
  hosting (public resolvers, first-party SaaS). Safe to deprioritise, not to ignore.

# Splunk: external lookup

Enrich any search with Reput.io verdicts using a standard Splunk external lookup.

## Install

1. Copy `bin/reputio_lookup.py` and `../python/reputio.py` into
   `$SPLUNK_HOME/etc/apps/<your_app>/bin/`.
2. Add the lookup definition to `$SPLUNK_HOME/etc/apps/<your_app>/local/transforms.conf`:

   ```ini
   [reputio]
   external_cmd = reputio_lookup.py indicator
   external_type = python
   python.version = python3
   fields_list = indicator, reputio_status, reputio_verdict, reputio_risk, reputio_provider, reputio_action, reputio_categories
   ```

3. Give the script your API key, either as `REPUTIO_API_KEY` in the environment
   Splunk runs with, or as the only line of
   `$SPLUNK_HOME/etc/apps/<your_app>/local/reputio_api_key.txt`. Restrict that file
   to the Splunk user. For Splunk Cloud or vetted apps, store the key in
   `storage/passwords` instead and adapt `api_key()` in the script. Set `REPUTIO_BATCH_SIZE` to your plan's
   batch size (10 Free/Starter, 50 Pro, 100 Team/Enterprise).

4. Restart Splunk or reload the app.

## Use

```spl
index=firewall action=allowed
| stats count by dest_ip
| lookup reputio indicator AS dest_ip OUTPUT reputio_status reputio_verdict reputio_provider reputio_action
| where reputio_verdict!="likely_benign"
| sort - count
```

Typical triage pattern: drop `likely_benign` results, look at `malicious` and
`suspicious` first, then review `investigate` results with the provider label.
Cloud and CDN addresses stay `investigate` on purpose: anyone can rent them, so
check the hostname or tenant behind the traffic.

Run the lookup after `stats` so each distinct indicator is queried once.

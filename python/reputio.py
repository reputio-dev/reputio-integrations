"""Minimal Python client for the Reput.io Lookup API.

Standard library only, so it drops into a SOAR action, a Splunk script or a cron
job without extra installs.

    from reputio import Reputio
    client = Reputio(api_key="rpt_...")          # or set REPUTIO_API_KEY
    for r in client.lookup(["8.8.8.8", "cloudflare.com"]):
        print(r["indicator"], r["status"], r["verdict"])

`lookup()` splits long lists into plan-sized batches, honours `Retry-After` on
429 responses and retries 503s and timeouts with exponential backoff.

The API returns each indicator normalised (trimmed and lowercased), so match
results with `normalize()` or use `lookup_map()`, never the raw input string.
"""

import json
import os
import random
import time
import urllib.error
import urllib.request

API_URL = "https://api.reput.io/lookup"
USER_AGENT = "reputio-integrations-python/1.0"


def normalize(indicator):
    """The form the API echoes back: trimmed and lowercased."""
    return (indicator or "").strip().lower()


class ReputioError(Exception):
    """Raised for non-retryable API errors (400, 401, 403...)."""

    def __init__(self, status, body):
        super().__init__(f"HTTP {status}: {body}")
        self.status = status
        self.body = body


class Reputio:
    def __init__(self, api_key=None, batch_size=10, timeout=30, max_retries=5, url=API_URL):
        """batch_size: indicators per request for your plan (Free/Starter 10, Pro 50, Team/Enterprise 100)."""
        self.api_key = api_key or os.environ.get("REPUTIO_API_KEY")
        if not self.api_key:
            raise ValueError("Pass api_key or set REPUTIO_API_KEY")
        self.batch_size = batch_size
        self.timeout = timeout
        self.max_retries = max_retries
        self.url = url

    def lookup(self, indicators):
        """Look up any number of indicators; returns a list of result dicts.

        Raises ReputioError on a non-retryable error; results from batches that
        already succeeded are not returned in that case.
        """
        items = [i.strip() for i in indicators if i and i.strip()]
        results = []
        for start in range(0, len(items), self.batch_size):
            results.extend(self._post(items[start:start + self.batch_size]))
        return results

    def lookup_map(self, indicators):
        """Like lookup(), but keyed by normalize(indicator) for safe matching."""
        return {normalize(r.get("indicator")): r for r in self.lookup(indicators)}

    def lookup_one(self, indicator):
        res = self.lookup([indicator])
        return res[0] if res else None

    def _post(self, batch):
        body = json.dumps({"indicators": batch}).encode()
        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(self.url, data=body, method="POST", headers={
                "Content-Type": "application/json",
                "X-Api-Key": self.api_key,
                "User-Agent": USER_AGENT,
            })
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.load(resp).get("results", [])
            except urllib.error.HTTPError as e:
                text = e.read().decode(errors="replace")
                if e.code in (429, 503) and attempt < self.max_retries:
                    wait = e.headers.get("Retry-After")
                    delay = float(wait) if wait and wait.isdigit() else min(60, 2 ** attempt)
                    time.sleep(delay + random.uniform(0, 1))
                    continue
                raise ReputioError(e.code, text)
            except (urllib.error.URLError, TimeoutError):
                if attempt < self.max_retries:
                    time.sleep(min(60, 2 ** attempt) + random.uniform(0, 1))
                    continue
                raise


def summarize(result):
    """One-line triage summary for logs or ticket comments."""
    provider = (result.get("provider") or {}).get("name") or "-"
    action = (result.get("recommendation") or {}).get("action") or "-"
    return (f"{result.get('indicator')}: {result.get('status')}/{result.get('verdict')} "
            f"risk={result.get('risk_level')} provider={provider} action={action}")

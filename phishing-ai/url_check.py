import os, time, requests
from typing import Dict, Any, Optional

URLSCAN_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT_URL = "https://urlscan.io/api/v1/result/{uuid}/"

def urlscan_check_url(
    url: str,
    *,
    api_key: Optional[str] = None,
    visibility: str = "public",
    timeout_s: int = 60,          # give urlscan time
    poll_interval_s: float = 2.0,
    submit_timeout_s: int = 10,
    poll_timeout_s: int = 6,
) -> Dict[str, Any]:
    api_key = api_key or os.getenv("URLSCAN_API_KEY")
    if not api_key:
        raise RuntimeError("Missing urlscan API key (set URLSCAN_API_KEY)")

    submit_headers = {"API-Key": api_key, "Content-Type": "application/json"}
    submit_payload = {"url": url, "visibility": visibility}

    r = requests.post(URLSCAN_SUBMIT_URL, headers=submit_headers, json=submit_payload, timeout=submit_timeout_s)

    # Handle rate limit on submit gracefully
    if r.status_code == 429:
        raise TimeoutError("urlscan submit rate-limited (429)")

    if r.status_code >= 400:
        raise RuntimeError(f"urlscan submit failed [{r.status_code}]: {r.text[:300]}")

    submit_json = r.json()
    uuid = submit_json.get("uuid")
    if not uuid:
        raise RuntimeError("urlscan submit did not return a uuid")

    result_headers = {"API-Key": api_key}
    deadline = time.time() + timeout_s
    last_status = None

    while time.time() < deadline:
        rr = requests.get(URLSCAN_RESULT_URL.format(uuid=uuid), headers=result_headers, timeout=poll_timeout_s)
        last_status = rr.status_code

        # Not ready / still processing
        if rr.status_code in (404, 202):
            time.sleep(poll_interval_s)
            continue

        # Rate limited → backoff and keep trying within budget
        if rr.status_code == 429:
            time.sleep(max(poll_interval_s, 5))
            continue

        if rr.status_code >= 400:
            raise RuntimeError(f"urlscan result failed [{rr.status_code}]: {rr.text[:300]}")

        return {"uuid": uuid, "result": rr.json()}

    raise TimeoutError(f"urlscan result not ready within {timeout_s}s (last_status={last_status}, uuid={uuid})")
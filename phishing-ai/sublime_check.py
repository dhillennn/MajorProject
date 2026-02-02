import requests
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

SUBLIME_ATTACK_SCORE_URL = "https://analyzer.sublime.security/v0/messages/attack_score"


def sublime_attack_score(
    raw_message_rfc822: str,
    *,
    timeout_s: int = 20,
    raise_for_http_errors: bool = True
) -> Dict[str, Any]:
    """
    HTTP Request:

      POST https://analyzer.sublime.security/v0/messages/attack_score
      JSON: { "raw_message": "<rfc822>" }

    Returns the raw JSON response from Sublime.
    """
    payload = {"raw_message": raw_message_rfc822}
    
    # 🔍 DEBUG: Log what we're sending to Sublime
    logger.info(f"🔍 Sublime API call - Message length: {len(raw_message_rfc822)} chars")
    logger.info(f"🔍 First 200 chars of payload: {raw_message_rfc822[:200]}")
    logger.info(f"🔍 Last 200 chars of payload: {raw_message_rfc822[-200:]}")

    resp = requests.post(
        SUBLIME_ATTACK_SCORE_URL,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=timeout_s
    )
    
    # 🔍 DEBUG: Log response
    logger.info(f"🔍 Sublime response status: {resp.status_code}")
    logger.info(f"🔍 Sublime response text: {resp.text[:500]}")

    # Minimal + predictable error handling
    if raise_for_http_errors and resp.status_code >= 400:
        raise RuntimeError(f"Sublime attack_score failed [{resp.status_code}]: {resp.text[:300]}")

    # Some endpoints might return non-json errors; handle gracefully
    try:
        data = resp.json()
        logger.info(f"🔍 Sublime JSON response: {data}")
    except Exception as e:
        logger.error(f"🔍 Failed to parse Sublime response as JSON: {e}")
        data = {"error": "Non-JSON response", "status_code": resp.status_code, "text": resp.text[:500]}

    return data
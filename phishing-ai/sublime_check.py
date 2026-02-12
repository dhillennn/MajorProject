import requests
import base64
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
      JSON: { "raw_message": "<base64-encoded-rfc822>" }

    Returns the raw JSON response from Sublime.
    
    Args:
        raw_message_rfc822: Plain text RFC822 email (will be base64 encoded before sending)
    """
    
    # Sublime requires base64-encoded email in the raw_message field
    try:
        # Encode the RFC822 email as base64
        raw_bytes = raw_message_rfc822.encode('utf-8')
        base64_encoded = base64.b64encode(raw_bytes).decode('ascii')
        
        logger.info(f"Encoding email for Sublime: {len(raw_message_rfc822)} chars → {len(base64_encoded)} base64 chars")
        
    except Exception as e:
        logger.error(f"Failed to base64 encode email: {e}")
        raise
    
    payload = {"raw_message": base64_encoded}

    resp = requests.post(
        SUBLIME_ATTACK_SCORE_URL,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=timeout_s
    )

    # Minimal + predictable error handling
    if raise_for_http_errors and resp.status_code >= 400:
        logger.error(f"Sublime API error: {resp.text[:500]}")
        raise RuntimeError(f"Sublime attack_score failed [{resp.status_code}]: {resp.text[:300]}")

    # Some endpoints might return non-json errors; handle gracefully
    try:
        data = resp.json()
        logger.info(f"🔍 Sublime JSON response: {data}")
    except Exception as e:
        logger.error(f"❌ Failed to parse Sublime response as JSON: {e}")
        data = {"error": "Non-JSON response", "status_code": resp.status_code, "text": resp.text[:500]}

    return data
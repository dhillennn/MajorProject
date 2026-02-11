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
      JSON: { "raw_message": "<rfc822>" }

    Returns the raw JSON response from Sublime.
    
    Args:
        raw_message_rfc822: Either base64-encoded or plain RFC822 email text
    """
    
    # Decode if base64-encoded
    try:
        # Try to decode as base64
        decoded = base64.b64decode(raw_message_rfc822).decode('utf-8')
        email_text = decoded
        logger.info("Decoded base64-encoded email for Sublime API")
    except Exception:
        # If decoding fails, assume it's already plain text
        email_text = raw_message_rfc822
        logger.info("Using plain text email for Sublime API")
    
    payload = {"raw_message": email_text}

    resp = requests.post(
        SUBLIME_ATTACK_SCORE_URL,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=timeout_s
    )

    # Minimal + predictable error handling
    if raise_for_http_errors and resp.status_code >= 400:
        raise RuntimeError(f"Sublime attack_score failed [{resp.status_code}]: {resp.text[:300]}")

    # Some endpoints might return non-json errors; handle gracefully
    try:
        data = resp.json()
        logger.info(f"🔍 Sublime JSON response: {data}")
    except Exception as e:
        logger.error(f"❌ Failed to parse Sublime response as JSON: {e}")
        data = {"error": "Non-JSON response", "status_code": resp.status_code, "text": resp.text[:500]}

    return data
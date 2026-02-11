import requests
import logging
import json
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
    
    # ==================================================================
    # RAILWAY-COMPATIBLE DIAGNOSTIC LOGGING
    # All output goes to logger so it appears in Railway logs
    # ==================================================================
    
    logger.info("\n" + "="*80)
    logger.info("SUBLIME API CALL - FULL DIAGNOSTIC")
    logger.info("="*80)
    
    # Check 1: What type of data did we receive?
    logger.info(f"\n1️⃣ INPUT TYPE: {type(raw_message_rfc822)}")
    logger.info(f"   Length: {len(raw_message_rfc822)} characters")
    
    # Check 2: Show the first 500 characters
    logger.info(f"\n2️⃣ FIRST 500 CHARACTERS:")
    logger.info("-" * 80)
    logger.info(raw_message_rfc822[:500])
    logger.info("-" * 80)
    
    # Check 3: Show the last 200 characters
    logger.info(f"\n3️⃣ LAST 200 CHARACTERS:")
    logger.info("-" * 80)
    logger.info(raw_message_rfc822[-200:])
    logger.info("-" * 80)
    
    # Check 4: Does it look like RFC822 or base64?
    first_line = raw_message_rfc822.split('\n')[0] if raw_message_rfc822 else ""
    logger.info(f"\n4️⃣ FIRST LINE: {repr(first_line)}")
    
    if first_line.lower().startswith(('from:', 'received:', 'return-path:')):
        logger.info("   ✅ GOOD: Looks like RFC822 email")
    elif all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r' for c in first_line):
        logger.info("   ❌ BAD: Looks like base64 data!")
    else:
        logger.info("   ⚠️  UNKNOWN: Cannot determine format")
    
    # Check 5: Look for problematic patterns
    logger.info(f"\n5️⃣ CHECKING FOR PROBLEMS:")
    
    if "Content-Transfer-Encoding: base64" in raw_message_rfc822:
        count = raw_message_rfc822.count("Content-Transfer-Encoding: base64")
        logger.warning(f"   ❌ Found {count} 'Content-Transfer-Encoding: base64' sections!")
        
        # Find the location and show context
        idx = raw_message_rfc822.find("Content-Transfer-Encoding: base64")
        logger.warning(f"   First occurrence at position {idx}")
        logger.warning(f"   Context around it:")
        logger.warning(raw_message_rfc822[max(0, idx-100):idx+200])
    else:
        logger.info("   ✅ No 'Content-Transfer-Encoding: base64' found")
    
    if raw_message_rfc822.startswith("__BASE64_EML__:"):
        logger.error("   ❌ CRITICAL: Input still has __BASE64_EML__: prefix!")
        logger.error("      This means parse_email() didn't decode it!")
    else:
        logger.info("   ✅ No __BASE64_EML__: prefix")
    
    # Check 6: Count suspicious patterns
    base64_lines = 0
    suspicious_lines = []
    for i, line in enumerate(raw_message_rfc822.split('\n')[:100]):  # Check first 100 lines
        if len(line) > 60 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in line.strip()):
            base64_lines += 1
            if len(suspicious_lines) < 3:  # Show first 3 examples
                suspicious_lines.append(f"Line {i}: {line[:80]}...")
    
    logger.info(f"\n6️⃣ SUSPICIOUS BASE64 LINES: {base64_lines}")
    if base64_lines > 0:
        logger.warning("   ❌ Found lines that look like base64 content!")
        for sl in suspicious_lines:
            logger.warning(f"      {sl}")
    
    # Check 7: Prepare the payload
    payload = {"raw_message": raw_message_rfc822}
    payload_json = json.dumps(payload)
    
    logger.info(f"\n7️⃣ JSON PAYLOAD:")
    logger.info(f"   Total size: {len(payload_json)} bytes")
    logger.info(f"   First 300 chars of JSON:")
    logger.info(payload_json[:300])
    
    # CRITICAL: Log the COMPLETE email being sent (chunked for Railway logs)
    logger.info(f"\n8️⃣ COMPLETE EMAIL BEING SENT TO SUBLIME:")
    logger.info("="*80)
    # Split into chunks to avoid log truncation
    chunk_size = 2000
    for i in range(0, len(raw_message_rfc822), chunk_size):
        chunk = raw_message_rfc822[i:i+chunk_size]
        logger.info(f"[Chunk {i//chunk_size + 1}]: {chunk}")
    logger.info("="*80)
    
    logger.info("\n" + "="*80)
    logger.info("SENDING REQUEST TO SUBLIME...")
    logger.info("="*80 + "\n")
    
    # Make the actual request
    try:
        resp = requests.post(
            SUBLIME_ATTACK_SCORE_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=timeout_s
        )

        logger.info(f"\n9️⃣ RESPONSE:")
        logger.info(f"   Status Code: {resp.status_code}")
        logger.info(f"   Response Headers: {dict(resp.headers)}")
        logger.info(f"   Response Text: {resp.text}")
        logger.info("\n" + "="*80 + "\n")
        
    except Exception as e:
        logger.error(f"Request exception: {e}")
        raise

    # Minimal + predictable error handling
    if raise_for_http_errors and resp.status_code >= 400:
        raise RuntimeError(f"Sublime attack_score failed [{resp.status_code}]: {resp.text[:300]}")

    # Some endpoints might return non-json errors; handle gracefully
    try:
        data = resp.json()
        logger.info(f"✅ Sublime JSON response: {data}")
    except Exception as e:
        logger.error(f"❌ Failed to parse Sublime response as JSON: {e}")
        data = {"error": "Non-JSON response", "status_code": resp.status_code, "text": resp.text[:500]}

    return data
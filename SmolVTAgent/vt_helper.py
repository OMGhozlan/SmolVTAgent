import streamlit as st
import requests
import re
from datetime import datetime, timezone
from rich_logger import RichLogger

from config import VT_API_KEY # Import the loaded key

# Logger Setup 
logger_vt = RichLogger.get_logger(__name__)

# VirusTotal Helper Functions 

def is_valid_hash(hash_string):
    """Checks if the string looks like a valid MD5, SHA1, or SHA256 hash."""
    logger_vt.debug(f"Validating hash: {hash_string}")
    if not isinstance(hash_string, str):
         logger_vt.debug(f"Validation failed: Input is not a string ({type(hash_string)})")
         return False
    hash_string = hash_string.strip()
    is_md5 = re.fullmatch(r"[a-fA-F0-9]{32}", hash_string)
    is_sha1 = re.fullmatch(r"[a-fA-F0-9]{40}", hash_string)
    is_sha256 = re.fullmatch(r"[a-fA-F0-9]{64}", hash_string)
    valid = bool(is_md5 or is_sha1 or is_sha256)
    logger_vt.debug(f"Hash validation result for '{hash_string}': {valid}")
    return valid

def format_vt_analysis_stats(stats):
    """Formats the analysis stats dictionary into a readable string."""
    if not stats: return "No analysis statistics available."
    stat_order = {"malicious": "Malicious", "suspicious": "Suspicious", "undetected": "Undetected", "harmless": "Harmless", "timeout": "Timeout"}
    parts = [f"{name}: {stats.get(key, 0)}" for key, name in stat_order.items() if key in stats]
    return ", ".join(parts) if parts else "No analysis statistics available."

def format_vt_result(vt_data):
    """Formats the VirusTotal file data dictionary into a decorated markdown report for analysts, with flexibility for extra fields."""
    attributes = vt_data.get('attributes', {})
    file_id = vt_data.get('id', 'N/A')
    last_stats = attributes.get("last_analysis_stats", {})
    result_summary = format_vt_analysis_stats(last_stats)
    malicious_count = last_stats.get("malicious", 0)
    suspicious_count = last_stats.get("suspicious", 0)

    if malicious_count > 0:
        status_icon, color, verdict = "💀 Malicious", "red", "Malicious"
    elif suspicious_count > 0:
        status_icon, color, verdict = "⚠️ Suspicious", "orange", "Suspicious"
    else:
        status_icon, color, verdict = "✅ Likely Clean", "green", "Likely Clean"

    # Format all timestamps in UTC and label as such
    last_analysis_date_str = (
        datetime.fromtimestamp(attributes.get("last_analysis_date", 0), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        if attributes.get("last_analysis_date") else "N/A"
    )
    first_submission_date_str = (
        datetime.fromtimestamp(attributes.get("first_submission_date", 0), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        if attributes.get("first_submission_date") else "N/A"
    )
    names = attributes.get("meaningful_name", "N/A")
    if isinstance(names, list):
        names = ", ".join(names) if names else "N/A"
    elif names is None:
        names = "N/A"
    vt_link = f"https://www.virustotal.com/gui/file/{file_id}"

    md5 = attributes.get('md5', 'N/A')
    sha1 = attributes.get('sha1', 'N/A')
    sha256 = attributes.get('sha256', 'N/A')
    file_size = attributes.get('size', 'N/A')
    type_desc = attributes.get('type_description', 'N/A')
    type_tag = attributes.get('type_tag', 'N/A')

    # Threat names and categories (flexible fields)
    threat_names = attributes.get('popular_threat_classification', {}).get('suggested_threat_label', None)
    if not threat_names:
        threat_names = attributes.get('meaningful_name', None)
    if isinstance(threat_names, list):
        threat_names = ", ".join(threat_names)
    if not threat_names:
        threat_names = "N/A"
    categories = attributes.get('popular_threat_classification', {}).get('category', [])
    if isinstance(categories, list):
        categories = ", ".join(categories)
    if not categories:
        categories = "N/A"

    # Top engines detections (flexible, show up to 3)
    top_engines_md = ""
    engines = attributes.get('last_analysis_results', {})
    if engines:
        # Sort by malicious verdicts
        top = [ (e, v) for e, v in engines.items() if v.get('category') == 'malicious']
        top = top[:3] if len(top) > 3 else top
        if top:
            top_engines_md = "\n".join([f"    - {engine}: `{result.get('result','N/A')}`" for engine, result in top])
        else:
            # If no malicious, show any 3 engines
            top = list(engines.items())[:3]
            top_engines_md = "\n".join([f"    - {engine}: `{result.get('result','N/A')}`" for engine, result in top])
    else:
        top_engines_md = "    - N/A"

    # Extra fields (flexible for model/agent to append)
    extra_info = ""
    for k, v in vt_data.items():
        if k not in {'id', 'attributes', 'type'}:
            extra_info += f"- **{k.capitalize()}:** {v}\n"
    for k, v in attributes.items():
        if k not in {'md5','sha1','sha256','size','type_description','type_tag','last_analysis_stats','last_analysis_date','first_submission_date','meaningful_name','popular_threat_classification','last_analysis_results'}:
            if isinstance(v, (str, int, float)) and v:
                if 'date' in k.lower() and isinstance(v, int):
                    v_fmt = datetime.fromtimestamp(v, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                    extra_info += f"- **{k.replace('_',' ').capitalize()}:** {v_fmt}\n"
                else:
                    extra_info += f"- **{k.replace('_',' ').capitalize()}:** {v}\n"

    report = f"""
## 🕵️‍♂️ File Reputation Report

**Hash:** `{sha256}`

**Verdict:**  
<span style="color:{color}; font-weight:bold">**{verdict}**</span> ({result_summary})

**First Seen:** {first_submission_date_str}  
**Last Analysis:** {last_analysis_date_str}

---

### 🚩 Threat Details

- **Threat Names:** {threat_names}
- **Categories:** {categories}
- **Top Engines:**
{top_engines_md}

---

### 🔗 [View Full VirusTotal Report]({vt_link})

---

#### ℹ️ Additional Information
{extra_info if extra_info else '- None'}
"""
    return report


def get_file_reputation_from_vt(file_hash):
    """
    Gets file reputation from VirusTotal using a hash via the requests library.
    Uses VT_API_KEY from config.
    """
    logger_vt.info(f"Getting file reputation for hash: {file_hash} using requests")

    if not VT_API_KEY:
        logger_vt.error("VT API Key is missing. Cannot make request.")
        return "Error: VirusTotal API Key is not configured."

    if not is_valid_hash(file_hash):
         logger_vt.warning(f"Invalid hash format provided: {file_hash}")
         return f"Error: '{file_hash}' is not recognized as a valid MD5, SHA1, or SHA256 hash format."

    cleaned_hash = file_hash.strip()
    url = f"https://www.virustotal.com/api/v3/files/{cleaned_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }

    try:
        logger_vt.debug(f"Making GET request to {url}")
        response = requests.get(url, headers=headers, timeout=30, verify=False) # Added timeout
        logger_vt.debug(f"Received response with status code: {response.status_code}")

        # Check for specific HTTP errors
        if response.status_code == 404:
            logger_vt.warning(f"Hash {cleaned_hash} not found in VirusTotal (404).")
            return f"Hash `{cleaned_hash}` was not found in the VirusTotal database."
        elif response.status_code == 401:
            logger_vt.error("VirusTotal API Authentication failed (401). Check API key.")
            return "Error: VirusTotal API Authentication failed. Check your API key."
        elif response.status_code == 429:
             logger_vt.warning("VirusTotal API quota exceeded (429).")
             return "Error: VirusTotal API quota exceeded. Please try again later."

        # Raise an exception for other bad status codes (e.g., 5xx)
        response.raise_for_status()

        # Process successful response
        vt_data = response.json().get('data') # Get the 'data' part of the JSON
        if not vt_data:
             logger_vt.warning(f"VT response for {cleaned_hash} missing 'data' field.")
             return f"Error: Received unexpected response format from VirusTotal for hash {cleaned_hash}."

        logger_vt.info(f"Successfully retrieved VT data for hash {cleaned_hash}. Returning raw data dict.")
        return format_vt_result(vt_data)

    except requests.exceptions.HTTPError as e:
        # Handle errors raised by raise_for_status() that weren't caught above
        logger_vt.error(f"HTTP error during VT lookup for hash {cleaned_hash}: {e}", exc_info=True)
        return f"Error: An HTTP error occurred while contacting VirusTotal: {str(e)}"
    except requests.exceptions.Timeout:
         logger_vt.error(f"Timeout connecting to VirusTotal API for hash {cleaned_hash}")
         return f"Error: Timeout connecting to VirusTotal API for hash `{cleaned_hash}`."
    except requests.exceptions.RequestException as e:
        # Catch other requests errors (connection, etc.)
        logger_vt.exception(f"Network error during VT lookup for hash {cleaned_hash}: {e}")
        return f"Error: A network error occurred while contacting VirusTotal: {str(e)}"
    except Exception as e:
        # Catch any other unexpected errors (e.g., JSON parsing issues not caught above)
        logger_vt.exception(f"Unexpected error during VT lookup for hash {cleaned_hash}: {e}")
        st.error(f"Unexpected error during VT lookup: {e}")
        return f"Error: An unexpected error occurred: {str(e)}"
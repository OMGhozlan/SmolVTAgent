import streamlit as st
import requests
import re
from datetime import datetime
import logging

from config import VT_API_KEY # Import the loaded key

# Logger Setup 
logger_vt = logging.getLogger(__name__)

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
    """Formats the VirusTotal file data dictionary into a markdown string for display."""
    attributes = vt_data.get('attributes', {}) # Use .get for safety
    file_id = vt_data.get('id', 'N/A') # Get ID from data dict

    last_stats = attributes.get("last_analysis_stats", {})
    result_summary = format_vt_analysis_stats(last_stats)
    malicious_count = last_stats.get("malicious", 0)
    suspicious_count = last_stats.get("suspicious", 0)

    if malicious_count > 0: status_icon, color = "💀 Malicious", "red"
    elif suspicious_count > 0: status_icon, color = "⚠️ Suspicious", "orange"
    else: status_icon, color = "✅ Likely Clean", "green"

    last_analysis_date_str = datetime.fromtimestamp(attributes.get("last_analysis_date", 0)).strftime('%Y-%m-%d %H:%M:%S UTC') if attributes.get("last_analysis_date") else "N/A"
    first_submission_date_str = datetime.fromtimestamp(attributes.get("first_submission_date", 0)).strftime('%Y-%m-%d %H:%M:%S UTC') if attributes.get("first_submission_date") else "N/A"
    names = attributes.get("meaningful_name", "N/A")
    if isinstance(names, list): names = ", ".join(names) if names else "N/A"
    elif names is None: names = "N/A"
    vt_link = f"https://www.virustotal.com/gui/file/{file_id}"

    report = f"""
    #### VirusTotal Report for `{file_id}`
    
    **Status:** :{color}[{status_icon}]
    **Analysis Results:** {result_summary}
    **Detected Names:** {names}
    **MD5:** `{attributes.get('md5', 'N/A')}` | **SHA1:** `{attributes.get('sha1', 'N/A')}` | **SHA256:** `{attributes.get('sha256', 'N/A')}`
    **File Size:** {attributes.get('size', 'N/A')} bytes | **Type:** `{attributes.get('type_description', 'N/A')}` ({attributes.get('type_tag', 'N/A')})
    **First Seen:** {first_submission_date_str} | **Last Analysis:** {last_analysis_date_str}
    [**View Full Report on VirusTotal**]({vt_link})
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
        return vt_data

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
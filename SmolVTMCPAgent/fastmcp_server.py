import signal
import sys

import logging
from dotenv import load_dotenv
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from typing import Dict, Any, Union

import requests
import re

# Load environment variables from .env file BEFORE importing vt_helper
load_dotenv()

# Import VT helper functions AFTER loading env vars
from vt_helper import get_file_reputation_from_vt, is_valid_hash

# Logging Setup 
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("FastMCPServer")

# FastMCP Server Initialization 
mcp = FastMCP(
    "VirusTotalChecker",
    dependencies=["requests", "python-dotenv", "pydantic"]
)

class HashInput(BaseModel):
    file_hash: str = Field(..., description="The file hash (MD5, SHA1, or SHA256) to check.")

@mcp.tool()
def check_hash_reputation(hash_input: HashInput) -> Union[Dict[str, Any], str]:
    """
    Check the reputation of a file hash using VirusTotal.
    Args:
        hash_input: An object with a 'file_hash' field (MD5, SHA1, SHA256)
    Returns:
        VirusTotal reputation result or error string. If a reputation result is returned, Do not change the formatting
    """
    cleaned_hash = hash_input.file_hash.strip()
    logger.info(f"Received hash: {cleaned_hash}")
    if not is_valid_hash(cleaned_hash):
        logger.warning(f"Invalid hash: {cleaned_hash}")
        return "Invalid hash format."
    try:
        result = get_file_reputation_from_vt(cleaned_hash)
        import json
        pretty_result = json.dumps(result, indent=2, ensure_ascii=False) if isinstance(result, dict) else str(result)
        logger.info(f"VT helper returned result of type: {type(result)}\nPretty VT Result:\n{pretty_result}")
        return result
    except Exception as e:
        logger.exception(f"Error while checking hash reputation: {e}")
        return f"Error: {e}"

class MalpediaInput(BaseModel):
    family_name: str = Field(..., description="The malware family name to search on Malpedia.")

@mcp.tool()
def malpedia_family_writeup(input: MalpediaInput) -> Dict[str, str]:
    """
    Search Malpedia for a given malware family and return a summary and link if found.
    Args:
        input: An object with a 'family_name' field (malware family name, e.g., win.redline_stealer)
    Returns:
        Dict with 'summary' and 'url'. If not found, summary may be None.
    """
    base_url = "https://malpedia.caad.fkie.fraunhofer.de/details/"
    fam_url_name = input.family_name.lower().replace(' ', '_').replace('-', '_')
    url = base_url + fam_url_name
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            summary_match = re.search(r'<div class="card-body">\s*<p>(.*?)</p>', resp.text, re.DOTALL)
            if summary_match:
                summary = summary_match.group(1).strip()
            else:
                summary = None
            return {"summary": summary, "url": url}
        else:
            return {"summary": None, "url": url}
    except Exception as e:
        logger.warning(f"Malpedia search failed for {input.family_name}: {e}")
        return {"summary": None, "url": url, "error": str(e)}

def shutdown_handler(signum, frame):
    logger.info("Received termination signal. Shutting down FastMCP server gracefully...")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    try:
        mcp.run(transport="sse") # , host="127.0.0.1", port=9000)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received. Shutting down FastMCP server gracefully...")
        sys.exit(0)

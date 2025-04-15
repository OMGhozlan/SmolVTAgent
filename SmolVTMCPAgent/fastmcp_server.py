import logging
from dotenv import load_dotenv
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from typing import Dict, Any, Union

# Load environment variables from .env file BEFORE importing vt_helper
load_dotenv()

# Import VT helper functions AFTER loading env vars
from vt_helper import get_file_reputation_from_vt, is_valid_hash, format_vt_result
from config import VT_API_KEY # Ensure API key is loaded/checked

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
        VirusTotal reputation result or error string.
    """
    cleaned_hash = hash_input.file_hash.strip()
    logger.info(f"Received hash: {cleaned_hash}")
    if not is_valid_hash(cleaned_hash):
        logger.warning(f"Invalid hash: {cleaned_hash}")
        return "Invalid hash format."
    try:
        result = get_file_reputation_from_vt(cleaned_hash)
        logger.info(f"VT helper returned result of type: {type(result)}")
        return result
    except Exception as e:
        logger.exception(f"Error while checking hash reputation: {e}")
        return f"Error: {e}"

if __name__ == "__main__":
    mcp.run(transport="sse") # , host="127.0.0.1", port=9000)

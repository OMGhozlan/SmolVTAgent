import os
import json
import re
import logging
import requests
from config import OLLAMA_MODEL_ID

log_file = 'app.log'
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

FASTMCP_SERVER_BASE_URL = "http://localhost:8000/sse"
HEALTH_CHECK_ENDPOINT = f"{FASTMCP_SERVER_BASE_URL}"
HASH_CACHE_PATH = os.path.join(os.path.dirname(__file__), 'hash_cache.json')
CONTEXT_SIZE = 5  # Number of Q/A pairs to keep

def load_hash_cache():
    try:
        with open(HASH_CACHE_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def save_hash_cache(cache):
    try:
        with open(HASH_CACHE_PATH, 'w', encoding='utf-8') as f:
            json.dump(cache, f)
    except Exception as e:
        logging.warning(f"Could not save hash cache: {e}")

def extract_hashes(text):
    import logging
    # Only match hashes NOT already enclosed in <checkedhash> tags
    pattern = r'(?<!<checkedhash>)(\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b)(?!</checkedhash>)'
    matches = re.findall(pattern, text or "")
    logging.info(f"[extract_hashes] Input: {text}")
    logging.info(f"[extract_hashes] Matches: {matches}")
    return matches


def extract_entities(text, vt_result=None):
    hashes = extract_hashes(text)
    verdict = None
    threat_names = []
    categories = []
    if vt_result and isinstance(vt_result, dict):
        verdict = vt_result.get('malicious', None)
        threat_names = vt_result.get('threat_names', [])
        categories = vt_result.get('categories', [])
    return {
        'hashes': hashes,
        'verdict': verdict,
        'threat_names': threat_names,
        'categories': categories
    }


def get_ollama_models(base_url):
    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        return [m["name"] for m in data.get("models", []) if "embed" not in m["name"]]
    except Exception as e:
        logging.warning(f"Could not fetch Ollama models: {e}")
        return [OLLAMA_MODEL_ID]

def check_server_status(url=HEALTH_CHECK_ENDPOINT, timeout=2):
    """
    Checks if the FastMCP server SSE endpoint is reachable by searching for 'event: endpoint' in the response stream.
    """
    try:
        with requests.get(url, timeout=timeout, stream=True) as response:
            if response.status_code >= 400:
                logger.warning(f"Server status check failed for {url} (Status: {response.status_code})")
                return False
            try:
                for chunk in response.iter_lines(decode_unicode=True):
                    if chunk and 'event: endpoint' in chunk:
                        logger.info(f"Server status check successful for {url} (found 'event: endpoint')")
                        return True
                logger.warning(f"Server status check failed: 'event: endpoint' not found in initial SSE stream from {url}")
                return False
            except Exception as e:
                logger.error(f"Error reading SSE stream for server status check: {e}", exc_info=True)
                return False
    except requests.exceptions.ConnectionError:
        logger.warning(f"Server status check failed: Connection error for {url}")
        return False
    except requests.exceptions.Timeout:
        logger.warning(f"Server status check failed: Timeout for {url}")
        return False
    except Exception as e:
        logger.error(f"Server status check failed: Unexpected error for {url}: {e}", exc_info=True)
        return False

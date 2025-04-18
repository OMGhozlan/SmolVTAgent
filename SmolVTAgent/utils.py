import os
import json
import re
import requests
from config import OLLAMA_MODEL_ID
from rich_logger import RichLogger

logger = RichLogger.get_logger(__name__)


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
        logger.warning(f"Could not fetch Ollama models: {e}")
        return [OLLAMA_MODEL_ID]

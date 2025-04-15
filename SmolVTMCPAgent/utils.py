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

def get_ollama_models(base_url):
    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        return [m["name"] for m in data.get("models", [])]
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

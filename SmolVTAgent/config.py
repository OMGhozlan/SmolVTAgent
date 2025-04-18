import os
import streamlit as st
from dotenv import load_dotenv
from rich_logger import RichLogger

logger_config = RichLogger.get_logger(__name__)

# Load environment variables from .env file if it exists (for local dev)
logger_config.debug("Attempting to load environment variables from .env file...")
loaded = load_dotenv()
logger_config.debug(f".env file loaded: {loaded}")

def get_vt_api_key():
    """Retrieves the VirusTotal API key from Streamlit secrets or environment variables."""
    vt_key = None
    source = "Not found"
    try:
        # Try Streamlit secrets first (for deployed apps)
        logger_config.debug("Attempting to retrieve VT_API_KEY from Streamlit secrets.")
        vt_key = st.secrets.get("VT_API_KEY")
        if vt_key:
            logger_config.info("VT_API_KEY retrieved from Streamlit secrets.")
            source = "Streamlit secrets"
            return vt_key
    except Exception as e:
        # st.secrets might not exist in all local environments initially
        logger_config.debug(f"Could not read Streamlit secrets (this is normal in some environments): {e}")
        pass
    # Fallback to environment variable (local dev, Docker, etc.)
    logger_config.debug("Attempting to retrieve VT_API_KEY from environment variables.")
    vt_key = os.getenv("VT_API_KEY")
    if vt_key:
        logger_config.info("VT_API_KEY retrieved from environment variables.")
        source = "Environment variable"
    else:
        logger_config.warning("VT_API_KEY not found in Streamlit secrets or environment variables.")
    return vt_key

# Constants 
VT_API_KEY = get_vt_api_key()
# IMPORTANT: The model name must be prefixed with 'ollama/' for LiteLLM compatibility
OLLAMA_MODEL_ID = os.getenv("OLLAMA_MODEL_ID", "ollama/qwen2.5:7b") # Default model, prefixed with 'ollama/' for LiteLLM compatibility
OLLAMA_API_BASE = os.getenv("OLLAMA_API_BASE", "http://localhost:11434") # Default Ollama URL

# Log final config values (except the sensitive key itself)
logger_config.info(f"VT_API_KEY loaded: {'Yes' if VT_API_KEY else 'No'}")
logger_config.info(f"OLLAMA_MODEL_ID set to: {OLLAMA_MODEL_ID}")
logger_config.info(f"OLLAMA_API_BASE set to: {OLLAMA_API_BASE}")
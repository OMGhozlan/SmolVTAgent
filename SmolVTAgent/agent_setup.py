import streamlit as st
from smolagents import ToolCallingAgent, LiteLLMModel, tool
import logging
from typing import Union, Dict, Any

# Import functions/config needed for the tool and agent
from config import OLLAMA_MODEL_ID, OLLAMA_API_BASE
from vt_helper import get_file_reputation_from_vt, is_valid_hash

# Tool Definition 

logger_agent = logging.getLogger(__name__)

@tool
def check_file_hash_reputation_tool(file_hash: str) -> str:
    """
    Checks the reputation of a given file hash (MD5, SHA1, or SHA256) using the VirusTotal API.
    Use this tool ONLY when a user explicitly provides a string that looks like a valid file hash
    (a 32, 40, or 64 character hexadecimal string) and asks about its safety, origin, or reputation.
    Do NOT use this tool for URLs, domain names, IP addresses, or general text.

    Args:
        file_hash: The file hash (MD5, SHA1, or SHA256) to check. It must be a valid hash string.

    Returns:
        A string containing either the raw VirusTotal data summary (as JSON or similar) on success,
        or a string describing the error (e.g., invalid hash, API error, not found).
        The application will format the successful data for display.
    """
    logger_agent.info(f"Tool 'check_file_hash_reputation_tool' called with hash: {file_hash}")
    # Basic input validation (redundant with is_valid_hash check below, but good practice)
    if not isinstance(file_hash, str) or not file_hash:
        logger_agent.warning("Invalid input type or empty string received by tool.")
        return "Error: Invalid input provided to the hash check tool."

    # Define cleaned_hash early
    cleaned_hash = file_hash.strip()
    if not is_valid_hash(cleaned_hash): # Check the cleaned hash
        logger_agent.warning(f"Invalid hash provided: {file_hash}")
        return f"Input '{file_hash}' is not a valid MD5, SHA1, or SHA256 hash. Cannot check reputation."

    # Call the actual VT lookup function from vt_helper
    logger_agent.info(f"Calling VT helper for hash: {cleaned_hash}")
    result = get_file_reputation_from_vt(cleaned_hash)

    # Log the type and potentially part of the result for debugging
    if isinstance(result, dict):
        logger_agent.info(f"VT helper returned a dictionary for {cleaned_hash}. Keys: {list(result.keys())}")
    elif isinstance(result, str):
        logger_agent.info(f"VT helper returned an error string for {cleaned_hash}: {result}")
    else:
        logger_agent.warning(f"VT helper returned an unexpected type for {cleaned_hash}: {type(result)}")

    return result 

# Agent Initialization (Cached) 

@st.cache_resource 
def get_chat_agent():
    """Initializes and returns the SmolAgents ToolCallingAgent."""
    logger_agent.info("Initializing SmolAgents ToolCallingAgent...")
    try:
        logger_agent.debug(f"Creating LiteLLMModel with ID: {OLLAMA_MODEL_ID} and Base: {OLLAMA_API_BASE}")
        ollama_model = LiteLLMModel(
            model_id=OLLAMA_MODEL_ID,
            api_base=OLLAMA_API_BASE,
            # Add other LiteLLM params like temperature, max_tokens if needed
            # Example: temperature=0.7
        )

        agent = ToolCallingAgent(
            tools=[check_file_hash_reputation_tool], 
            model=ollama_model
        )
        logger_agent.info("SmolAgents ToolCallingAgent initialized successfully.")
        return agent
    except Exception as e:
        logger_agent.error(f"Failed to initialize LLM agent: {e}", exc_info=True)
        st.error(f"Failed to initialize LLM agent: {e}", icon="🔥")
        st.error(f"Ensure Ollama is running at {OLLAMA_API_BASE} and model '{OLLAMA_MODEL_ID}' is pulled.", icon="🔌")
        return None
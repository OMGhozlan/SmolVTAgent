import streamlit as st
import logging
import requests # Need requests for the health check
from ollama_agent import check_hash_sync
# from fastmcp.client.transports import SSETransport


# Import setup functions from other modules
from config import VT_API_KEY, OLLAMA_MODEL_ID, OLLAMA_API_BASE # Need Ollama config again
from ollama_agent import get_agent, VirusTotalOllamaAgent

# Helper to get available Ollama models
import json

def get_ollama_models(base_url):
    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        # Ollama returns {"models": [{"name": ...}, ...]}
        return [m["name"] for m in data.get("models", [])]
    except Exception as e:
        logging.warning(f"Could not fetch Ollama models: {e}")
        return [OLLAMA_MODEL_ID]


# Logging Configuration
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
logger.info("Streamlit Application starting...")

# Server Health Check Function 
FASTMCP_SERVER_BASE_URL = "http://localhost:8000/sse"
HEALTH_CHECK_ENDPOINT = f"{FASTMCP_SERVER_BASE_URL}"

def check_server_status(url=HEALTH_CHECK_ENDPOINT, timeout=2):
    """Checks if the FastMCP server SSE endpoint is reachable by searching for 'event: endpoint' in the response stream."""
    try:
        with requests.get(url, timeout=timeout, stream=True) as response:
            if response.status_code >= 400:
                logger.warning(f"Server status check failed for {url} (Status: {response.status_code})")
                return False
            # Read a small chunk of the stream for 'event: endpoint'
            try:
                for chunk in response.iter_lines(decode_unicode=True):
                    if chunk and 'event: endpoint' in chunk:
                        logger.info(f"Server status check successful for {url} (found 'event: endpoint')")
                        return True
                    # Only scan the first few lines to avoid hanging
                    # (SSE will keep streaming pings forever)
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

# Page Configuration 
st.set_page_config(page_title="Chat & File Reputation", layout="wide")
st.title("💬 Chat with Ollama & 🔬 Check File Reputation (via FastMCP)")
st.caption(f"Using {OLLAMA_MODEL_ID} via {OLLAMA_API_BASE}. Provide a file hash for VirusTotal check using the FastMCP tool server.")

# Initialization 
# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = [{"role": "assistant", "content": "Hi! Ask me anything or provide a file hash (MD5, SHA1, SHA256) to check its VirusTotal reputation via the tool server."}]
    logger.info("Chat history initialized.")

# Initialize server status check
if 'server_status' not in st.session_state:
    st.session_state.server_status = check_server_status()

# Sidebar: Ollama model selection
if "ollama_models" not in st.session_state:
    st.session_state.ollama_models = get_ollama_models(OLLAMA_API_BASE)

if "selected_model" not in st.session_state:
    st.session_state.selected_model = OLLAMA_MODEL_ID

with st.sidebar:
    st.markdown("**Ollama Model Selection:**")
    model_choice = st.selectbox("Choose Ollama model", st.session_state.ollama_models, index=st.session_state.ollama_models.index(st.session_state.selected_model) if st.session_state.selected_model in st.session_state.ollama_models else 0)
    if model_choice != st.session_state.selected_model:
        st.session_state.selected_model = model_choice
        st.session_state.agent_instance = VirusTotalOllamaAgent(model_choice)
        st.rerun()

# Get Agent Instance
logger.info("Initializing Ollama agent...")
if "agent_instance" not in st.session_state:
    st.session_state.agent_instance = VirusTotalOllamaAgent(st.session_state.selected_model)
agent_instance = st.session_state.agent_instance

# Sidebar Info 
st.sidebar.header("Configuration Status")

# Display Server Status 
st.sidebar.markdown("**FastMCP Server (Tool Host):**")
if st.session_state.server_status:
    st.sidebar.success(f"Status: ✅ Reachable at {FASTMCP_SERVER_BASE_URL}")
else:
    st.sidebar.error(f"Status: ❌ Unreachable at {FASTMCP_SERVER_BASE_URL}")
    st.sidebar.caption("Ensure `python fastmcp_server.py` is running.")

# Add a button to re-check status
if st.sidebar.button("🔄 Re-check Server Status"):
    st.session_state.server_status = check_server_status()
    st.rerun() # Rerun the script to update the display

st.sidebar.markdown(" ")

# Display Other Config Status 
st.sidebar.markdown("**Other Components:**")
if VT_API_KEY:
    st.sidebar.success("VirusTotal API Key: Loaded (for server).", icon="🔑")
    # logger.info("VirusTotal API Key Loaded.") # Less verbose logging
else:
    st.sidebar.error("VirusTotal API Key: Missing!", icon="🚨")
    st.sidebar.markdown("Set `VT_API_KEY` in `.env`. The FastMCP server needs this.")
    logger.error("VirusTotal API Key is missing.")

if agent_instance and agent_instance.llm:
     st.sidebar.success(f"Ollama Agent ({st.session_state.selected_model}): Initialized.", icon="🤖")
else:
     st.sidebar.error(f"Ollama Agent ({st.session_state.selected_model}): Failed.", icon="🔥")
     st.sidebar.markdown(f"Check Ollama server at `{OLLAMA_API_BASE}`.")
     logger.error(f"Ollama Agent Initialization failed. Check Ollama server at {OLLAMA_API_BASE}")

# Chat UI 
# Display chat messages from history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# React to user input
if prompt := st.chat_input("Ask something or enter a file hash..."):
    # Add user message to state and display it
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)
    logger.info(f"User input received: {prompt}")

    # Check if agent is available before proceeding
    if not agent_instance or not agent_instance.chain:
        st.error("Chat agent is not available. Cannot process request.", icon="⚠️")
        logger.error("Agent instance or chain not available when processing user input.")
        # Don't st.stop() here, let the message be displayed
    else:
        # If the prompt is a hash, call FastMCP directly for reputation
        if hasattr(agent_instance, 'is_valid_hash') and agent_instance.is_valid_hash(prompt):
            with st.chat_message("assistant"):
                message_placeholder = st.empty()
                message_placeholder.markdown("Checking hash reputation via MCP...")
                try:
                    result = check_hash_sync(prompt)
                    message_placeholder.markdown(str(result))
                    st.session_state.messages.append({"role": "assistant", "content": str(result)})
                except Exception as e:
                    logger.error(f"Error during MCP hash check: {e}", exc_info=True)
                    error_message = f"Sorry, error checking hash reputation: {str(e)}"
                    message_placeholder.error(error_message, icon="💥")
                    st.session_state.messages.append({"role": "assistant", "content": error_message})
        else:
            # Get response from the agent as before
            with st.chat_message("assistant"):
                message_placeholder = st.empty()
                message_placeholder.markdown("Thinking...")
                try:
                    logger.info("Calling agent.run()...")
                    agent_response_text = agent_instance.run(prompt)
                    logger.info(f"Agent response received.")
                    message_placeholder.markdown(agent_response_text)
                    st.session_state.messages.append({"role": "assistant", "content": agent_response_text})
                except Exception as e:
                    logger.error(f"Error during agent execution: {e}", exc_info=True)
                    error_message = f"Sorry, I encountered an error processing your request: {str(e)}"
                    message_placeholder.error(error_message, icon="💥")
                    st.session_state.messages.append({"role": "assistant", "content": error_message})

logger.info("Streamlit app finished processing request or waiting for input.")
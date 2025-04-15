import streamlit as st
import logging
from typing import Dict, Any

# Import setup functions from other modules
from config import VT_API_KEY, OLLAMA_MODEL_ID, OLLAMA_API_BASE
from vt_helper import is_valid_hash, get_file_reputation_from_vt, format_vt_result
from agent_setup import get_chat_agent

# Logging Configuration 
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

logger.info("Application starting...")

# Page Configuration 
st.set_page_config(page_title="Chat & File Reputation", layout="wide")
st.title("💬 Chat with Ollama & 🔬 Check File Reputation")
st.caption(f"Using {OLLAMA_MODEL_ID} via {OLLAMA_API_BASE}. Provide a file hash for VirusTotal check.")

# Initialization 
# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = [{"role": "assistant", "content": "Hi! Ask me anything or provide a file hash (MD5, SHA1, SHA256) to check its VirusTotal reputation."}]
    logger.info("Chat history initialized.")

# Get VT Client and Agent (uses caching from helper modules)
logger.info("Initializing Ollama agent...")
agent_instance = get_chat_agent()

# Sidebar Info 
st.sidebar.header("Configuration Status")
if VT_API_KEY:
    st.sidebar.success("VirusTotal API Key Loaded.", icon="✅")
    logger.info("VirusTotal API Key Loaded.")
else:
    st.sidebar.error("VirusTotal API Key Missing!", icon="🚨")
    st.sidebar.markdown("Set `VT_API_KEY` in `.env` or Streamlit secrets.")
    logger.error("VirusTotal API Key is missing.")

if agent_instance:
     st.sidebar.success("Ollama Agent Initialized.", icon="🤖")
     st.sidebar.markdown(f"Model: `{OLLAMA_MODEL_ID}`")
     logger.info(f"Ollama Agent Initialized successfully with model: {OLLAMA_MODEL_ID}")
else:
     st.sidebar.error("Ollama Agent Failed.", icon="🔥")
     st.sidebar.markdown(f"Check Ollama server at `{OLLAMA_API_BASE}`.")
     logger.error(f"Ollama Agent Initialization failed. Check Ollama server at {OLLAMA_API_BASE}")

st.sidebar.markdown("")
st.sidebar.info("VirusTotal tool uses the free API (rate limits apply).")

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
    if not agent_instance:
        st.error("Chat agent is not available. Cannot process request.", icon="⚠️")
        logger.error("Agent instance not available when processing user input.")
        st.stop() # Stop execution if agent isn't loaded

    # Get response from the agent
    with st.chat_message("assistant"):
        message_placeholder = st.empty()
        # Basic spinner - consider more robust loading indicators if needed
        message_placeholder.markdown("Thinking... <img src='https://cdnjs.cloudflare.com/ajax/libs/semantic-ui/0.16.1/images/loader-large.gif' width='20' style='vertical-align: middle;'>", unsafe_allow_html=True)

        agent_response_text = ""
        vt_report_markdown = None

        try:
            logger.info("Calling agent instance...")
            # Call the agent's run method
            agent_response_text = agent_instance.run(prompt)
            logger.info(f"Agent response received: {agent_response_text[:100]}...") # Truncated

            # Display the agent's textual response first
            message_placeholder.markdown(agent_response_text)
            # Add assistant text response to state
            st.session_state.messages.append({"role": "assistant", "content": agent_response_text})

            #  Add logic to display formatted VT report if input was a hash 
            cleaned_prompt = prompt.strip()
            if is_valid_hash(cleaned_prompt):
                logger.info(f"Input '{cleaned_prompt}' is a valid hash. Attempting to fetch and format VT report directly.")
                # Call VT helper again to get raw data
                vt_result_data = get_file_reputation_from_vt(cleaned_prompt)
                if isinstance(vt_result_data, dict):
                    logger.info("Successfully retrieved VT data dictionary directly. Formatting report.")
                    # Format the dictionary into markdown
                    vt_report_markdown = format_vt_result(vt_result_data)
                elif isinstance(vt_result_data, str):
                    # If the direct call resulted in an error string (e.g., not found)
                    logger.warning(f"Direct VT call for hash '{cleaned_prompt}' returned an error string: {vt_result_data}")
                    # Optionally display this error? For now, we just log it.
                    pass # Don't overwrite agent response with this error

        except Exception as e:
            logger.error(f"Error during agent execution or VT formatting: {e}", exc_info=True)
            st.error(f"An error occurred: {e}", icon="💥")
            error_message = f"Sorry, I encountered an error processing your request: {str(e)}"
            message_placeholder.markdown(error_message)
            # Add error response to state
            st.session_state.messages.append({"role": "assistant", "content": error_message})

        # If a formatted VT report was generated, display it below the agent's text
        if vt_report_markdown:
            with st.expander("View Full VirusTotal Report Details", expanded=False):
                 st.markdown(vt_report_markdown, unsafe_allow_html=True)
            # Add the VT report to history *after* the main text, if needed for context
            # Or maybe just display it without adding to history?
            # For now, let's just display it.
            logger.info("Displaying formatted VT report in expander.")

logger.info("Application finished processing request or waiting for input.")
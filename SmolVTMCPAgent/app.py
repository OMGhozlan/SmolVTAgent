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

# Utility functions are now in utils.py
from utils import get_ollama_models, check_server_status



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

# --- RAG: Document Upload and Embedding Model Selection ---
from rag_utils import create_vectorstore

# Document processing utilities are now in doc_processing.py
from doc_processing import extract_text_from_file, chunk_markdown

# --- RAG Persistence Option ---
persist_chroma = st.sidebar.checkbox("Enable persistent RAG vector store (Chroma)", value=True)
persist_dir = "chroma_db"

# --- RAG Progress UI ---
rag_status_placeholder = st.sidebar.empty()
rag_progress_bar = st.sidebar.progress(0)


def get_ollama_embedding_models(base_url):
    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        # Filter for models with 'embedding' in the name
        return [m["name"] for m in data.get("models", []) if "embedding" in m["name"]]
    except Exception as e:
        logging.warning(f"Could not fetch Ollama embedding models: {e}")
        return []

with st.sidebar:
    st.markdown("**Ollama Model Selection:**")
    model_choice = st.selectbox("Choose Ollama model", st.session_state.ollama_models, index=st.session_state.ollama_models.index(st.session_state.selected_model) if st.session_state.selected_model in st.session_state.ollama_models else 0)
    if model_choice != st.session_state.selected_model:
        st.session_state.selected_model = model_choice
        st.session_state.agent_instance = VirusTotalOllamaAgent(model_choice)
        st.rerun()
    st.markdown("---")
    st.markdown("**RAG: Document Retrieval**")
    uploaded_files = st.file_uploader("Attach documents for RAG", type=["pdf", "txt", "docx"], accept_multiple_files=True)
    # List available embedding models
    if "ollama_embedding_models" not in st.session_state:
        st.session_state.ollama_embedding_models = get_ollama_embedding_models(OLLAMA_API_BASE)
    emb_models = st.session_state.ollama_embedding_models
    emb_model_choice = st.selectbox("Choose Ollama embedding model", emb_models if emb_models else ["nomic-embed-text"], index=0)

import os

# --- RAG: Load persistent Chroma if enabled and available ---
rag_chunks = []
rag_documents = []
rag_chunk_sources = []  # Track source filenames for each chunk
loaded_from_persist = False
if persist_chroma and os.path.exists(persist_dir):
    try:
        from rag_utils import load_vectorstore
        st.session_state.rag_vectorstore = load_vectorstore(emb_model_choice, persist_dir)
        st.session_state.rag_documents = []  # Optionally, load docs metadata if you persist it
        st.session_state.rag_emb_model = emb_model_choice
        rag_status_placeholder.success(f"Loaded persistent RAG vector store from '{persist_dir}'.")
        st.sidebar.markdown(f"**RAG loaded (persistent):** from '{persist_dir}'")
        # Show files in vectorstore
        from rag_utils import list_vectorstore_files
        vs_files = list_vectorstore_files(st.session_state.rag_vectorstore)
        if vs_files:
            st.sidebar.markdown("**Files in Chroma DB:**\n" + "\n".join(f"- {f}" for f in vs_files))
            logger.info(f"Files in Chroma DB: {vs_files}")
        else:
            st.sidebar.markdown("**Files in Chroma DB:** None found.")
        rag_progress_bar.progress(1.0)
        loaded_from_persist = True
    except Exception as e:
        rag_status_placeholder.error(f"Failed to load persistent vector store: {e}")
        logger.error(f"Failed to load persistent vector store: {e}", exc_info=True)

if not loaded_from_persist:
    # Extract and embed docs if uploaded
    if uploaded_files:
        total_files = len(uploaded_files)
        for idx, f in enumerate(uploaded_files):
            logger.info(f"[RAG] Processing file {idx+1}/{total_files}: {f.name}")
            rag_status_placeholder.info(f"Processing document {idx+1}/{total_files}: {f.name}")
            try:
                with st.spinner(f"Extracting and chunking {f.name}..."):
                    logger.info(f"[RAG] Extracting text from {f.name}")
                    md_text = extract_text_from_file(f)
                    rag_documents.append(md_text)
                    logger.info(f"[RAG] Chunking {f.name}")
                    chunks = chunk_markdown(md_text)
                    rag_chunks.extend(chunks)
                    rag_chunk_sources.extend([f.name] * len(chunks))
                    logger.info(f"[RAG] {f.name}: {len(chunks)} chunks")
                rag_progress_bar.progress((idx+1)/total_files)
            except Exception as e:
                logger.error(f"Failed to extract {f.name}: {e}", exc_info=True)
                st.warning(f"Failed to extract {f.name}: {e}")
        rag_status_placeholder.success(f"Document processing complete: {len(rag_chunks)} chunks from {len(rag_documents)} docs.")
        rag_progress_bar.progress(1.0)
    else:
        rag_progress_bar.progress(0)
        rag_status_placeholder.info("No documents uploaded for RAG.")

if rag_chunks:
    rag_status_placeholder.info("Embedding and indexing chunks...")
    logger.info(f"[RAG] Embedding {len(rag_chunks)} chunks with model {emb_model_choice}")
    if persist_chroma:
        st.session_state.rag_vectorstore = create_vectorstore(rag_chunks, emb_model_choice, persist_directory=persist_dir)
    else:
        st.session_state.rag_vectorstore = create_vectorstore(rag_chunks, emb_model_choice)
    st.session_state.rag_documents = rag_documents
    st.session_state.rag_emb_model = emb_model_choice
    rag_status_placeholder.success(f"RAG loaded: {len(rag_chunks)} chunks from {len(rag_documents)} docs.")
    st.sidebar.markdown(f"**RAG loaded:** {len(rag_chunks)} chunks from {len(rag_documents)} docs")
    rag_progress_bar.progress(1.0)


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
                    # RAG: Retrieve context from docs if available
                    rag_context = ""
                    rag_references = None
                    rag_reference_sources = None
                    if "rag_vectorstore" in st.session_state and st.session_state.rag_vectorstore and prompt:
                        docs = st.session_state.rag_vectorstore.similarity_search(prompt, k=3)
                        rag_context = "\n\n".join([doc.page_content for doc in docs])
                        if rag_context:
                            prompt = f"Context:\n{rag_context}\n\nUser: {prompt}"
                            # Prepare references for UI
                            rag_references = docs
                            # Try to find the source file for each doc chunk by matching content
                            rag_reference_sources = []
                            for d in docs:
                                try:
                                    idx = rag_chunks.index(d.page_content)
                                    source = rag_chunk_sources[idx] if idx < len(rag_chunk_sources) else "[Unknown]"
                                except Exception:
                                    source = "[Unknown]"
                                rag_reference_sources.append(source)

                    agent_response_text = agent_instance.run(prompt)
                    logger.info(f"Agent response received.")

                    # Show <think>...</think> as a collapsible section if present
                    import re
                    think_match = re.search(r'<think>(.*?)</think>', agent_response_text, re.DOTALL)
                    if think_match:
                        main_response = re.sub(r'<think>.*?</think>', '', agent_response_text, flags=re.DOTALL).strip()
                        thoughts = think_match.group(1).strip()
                        if main_response:
                            message_placeholder.markdown(main_response)
                        with st.expander("Thoughts"):
                            st.markdown(thoughts)
                    else:
                        message_placeholder.markdown(agent_response_text)

                    # Show RAG references if used
                    if rag_references:
                        refs_md = "\n".join([
                            f"**[{i+1}]** ({rag_reference_sources[i]}) {doc.page_content[:120].replace(chr(10), ' ')}..." for i, doc in enumerate(rag_references)
                        ])
                        with st.expander("References", expanded=True):
                            st.markdown(refs_md)

                    st.session_state.messages.append({"role": "assistant", "content": agent_response_text})
                except Exception as e:
                    logger.error(f"Error during agent execution: {e}", exc_info=True)
                    error_message = f"Sorry, I encountered an error processing your request: {str(e)}"
                    message_placeholder.error(error_message, icon="💥")
                    st.session_state.messages.append({"role": "assistant", "content": error_message})

logger.info("Streamlit app finished processing request or waiting for input.")
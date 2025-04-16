import streamlit as st
import logging
import requests # Need requests for the health check
from ollama_agent import check_hash_sync, VirusTotalOllamaAgent
# from fastmcp.client.transports import SSETransport

# Import setup functions from other modules
from config import VT_API_KEY, OLLAMA_MODEL_ID, OLLAMA_API_BASE # Need Ollama config again

# Helper to get available Ollama models
import os
import time
from datetime import datetime, timezone
import re
from utils import load_hash_cache, save_hash_cache, extract_hashes, extract_entities, get_ollama_models, check_server_status
import uuid
from chat_memory import save_chat_history, load_chat_history, list_sessions, set_session_name, get_session_name
from rag_utils import create_vectorstore, load_vectorstore, list_vectorstore_files
from doc_processing import extract_text_from_file, chunk_markdown

#  Hash cache disk utilities 
HASH_CACHE_PATH = os.path.join(os.path.dirname(__file__), 'hash_cache.json')

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
st.title("💬 Chat & Check 🔬 (Ollama + FastMCP)")
st.caption(f"Using {OLLAMA_MODEL_ID} via {OLLAMA_API_BASE}. Provide a file hash for VirusTotal check using the FastMCP tool server.")


#  Advanced Persistent Memory Option 

#  Double Initialization Guard 
if "just_reset" in st.session_state and st.session_state.just_reset:
    st.session_state.just_reset = False
    skip_sidebar_actions = True
else:
    skip_sidebar_actions = False

if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())

# Sidebar: Advanced Memory
st.sidebar.markdown("")
advanced_memory_enabled = st.sidebar.checkbox("Enable Advanced Memory (persistent)", value=True, key="advanced_memory")

#  Sidebar: Name Current Session 
if advanced_memory_enabled:
    current_name = get_session_name(st.session_state.session_id)
    new_name = st.sidebar.text_input("Session Name", value=current_name, key="session_name_input")
    if new_name and new_name != current_name:
        set_session_name(st.session_state.session_id, new_name)
        current_name = new_name

#  Sidebar: Previous Chats 
if advanced_memory_enabled:
    st.sidebar.markdown("**Previous Chats:**")
    all_sessions = list_sessions()
    if all_sessions:
        session_labels = []
        for sid in all_sessions:
            name = get_session_name(sid)
            label = name if name else f"{sid[:8]}..."
            session_labels.append(label)
        selected_idx = st.sidebar.selectbox("Select chat to view", options=list(range(len(all_sessions))), format_func=lambda i: session_labels[i], key="prev_chat_select")
        selected_session_id = all_sessions[selected_idx]
        col_a, col_b, col_c = st.sidebar.columns([0.34, 0.33, 0.33])
        with col_a:
            if st.button("🔄 Recall this chat", key="recall_chat") and not skip_sidebar_actions:
                st.session_state.session_id = selected_session_id
                st.session_state.messages = load_chat_history(selected_session_id)
                st.session_state.just_reset = True
                st.rerun()
        with col_b:
            if st.button("🆕 New chat", key="new_chat_from_dropdown") and not skip_sidebar_actions:
                st.session_state.session_id = str(uuid.uuid4())
                st.session_state.messages = [{"role": "assistant", "content": "Hi! Ask me anything or provide a file hash (MD5, SHA1, SHA256) to check its VirusTotal reputation via the tool server Kek."}]
                set_session_name(st.session_state.session_id, "")
                st.session_state.just_reset = True
                st.rerun()
        with col_c:
            if st.button("🧹 Clear chat", key="clear_chat_sidebar") and not skip_sidebar_actions:
                st.session_state.messages = [{"role": "assistant", "content": "Hi! Ask me anything or provide a file hash (MD5, SHA1, SHA256) to check its VirusTotal reputation via the tool server."}]
                if advanced_memory_enabled:
                    st.session_state.session_id = str(uuid.uuid4())
                    current_name = ""
                    set_session_name(st.session_state.session_id, current_name)
                st.session_state.just_reset = True
                st.rerun()
        prev_history = load_chat_history(selected_session_id)
        N = 8
        # Ensure prev_history is a list
        if not isinstance(prev_history, list):
            prev_history = []
        with st.sidebar.expander("Recent messages", expanded=False):
            for m in prev_history[-N:]:
                role = m.get("role", "user")
                st.markdown(f"- **{role.capitalize()}**: {m.get('content','')[:60]}{'...' if len(m.get('content',''))>60 else ''}")
    else:
        st.sidebar.caption("No previous chats found.")

# Robust Message Initialization
# Always ensure messages is a list, load history only once per session, and set greeting if needed.
if "history_loaded_for_session" not in st.session_state:
    st.session_state.history_loaded_for_session = None

# Ensure chat_context is initialized
if "chat_context" not in st.session_state:
    st.session_state.chat_context = []

if "messages" not in st.session_state or not isinstance(st.session_state.messages, list):
    st.session_state.messages = []

if advanced_memory_enabled:
    if st.session_state.history_loaded_for_session != st.session_state.session_id:
        loaded_history = load_chat_history(st.session_state.session_id)
        if loaded_history and isinstance(loaded_history, list) and len(loaded_history) > 0:
            st.session_state.messages = loaded_history
            logger.info(f"Loaded persistent chat history for session {st.session_state.session_id}")
        st.session_state.history_loaded_for_session = st.session_state.session_id

if not st.session_state.messages:
    st.session_state.messages = [{
        "role": "assistant",
        "content": "Hi! Ask me anything or provide a file hash (MD5, SHA1, SHA256) to check its VirusTotal reputation via the tool server."
    }]
    logger.info("Chat history initialized.")



# Initialization 
# Initialize chat history
# Initialize server status check
if 'server_status' not in st.session_state:
    st.session_state.server_status = check_server_status()

# Sidebar: Ollama model selection
if "ollama_models" not in st.session_state:
    st.session_state.ollama_models = get_ollama_models(OLLAMA_API_BASE)

if "selected_model" not in st.session_state:
    st.session_state.selected_model = OLLAMA_MODEL_ID

#  RAG: Document Upload and Embedding Model Selection 

# Document processing utilities are now in doc_processing.py

#  RAG Persistence Option 
persist_chroma = st.sidebar.checkbox("Enable persistent RAG vector store (Chroma)", value=True)
persist_dir = "chroma_db"

#  RAG Progress UI 
rag_status_placeholder = st.sidebar.empty()
rag_progress_bar = st.sidebar.progress(0)


def get_ollama_embedding_models(base_url):
    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        # Filter for models with 'embedding' in the name
        return [m["name"] for m in data.get("models", []) if "embed" in m["name"]]
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
    st.markdown("")
    st.markdown("**RAG: Document Retrieval**")
    uploaded_files = st.file_uploader("Attach documents for RAG", type=["pdf", "txt", "docx"], accept_multiple_files=True)
    # List available embedding models
    if "ollama_embedding_models" not in st.session_state:
        st.session_state.ollama_embedding_models = get_ollama_embedding_models(OLLAMA_API_BASE)
    emb_models = st.session_state.ollama_embedding_models
    emb_model_choice = st.selectbox("Choose Ollama embedding model", emb_models if emb_models else ["nomic-embed-text"], index=0)

import os

#  RAG: Load persistent Chroma if enabled and available 
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
if st.session_state.messages:
    message = st.session_state.messages[-1]
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# React to user input
if "checked_hashes" not in st.session_state or not isinstance(st.session_state.checked_hashes, dict):
    st.session_state.checked_hashes = load_hash_cache()

# Render only the latest chat message (above input bar)
if st.session_state.messages:
    message = st.session_state.messages[-1]
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Chat Input (always at the bottom)
prompt = st.chat_input("Ask something or enter a file hash...", key="chat_input")

if prompt:
    # Add user message to state and display it
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)
    logger.info(f"User input received: {prompt}")

    # Save chat history if advanced memory is enabled
    if advanced_memory_enabled:
        save_chat_history(st.session_state.session_id, st.session_state.messages)

    # Check if agent is available before proceeding
    if not agent_instance or not agent_instance.chain:
        st.error("Chat agent is not available. Cannot process request.", icon="⚠️")
        logger.error("Agent instance or chain not available when processing user input.")
        # Don't st.stop() here, let the message be displayed
    else:
        # If the prompt is a hash, call FastMCP directly for reputation, but only once per unique hash
        # Only process hashes NOT already enclosed in <checkedhash> tags
        untagged_hashes = extract_hashes(prompt)
        if (
            hasattr(agent_instance, 'is_valid_hash')
            and untagged_hashes
            and prompt == prompt  # Only if this is a direct user prompt, not a sidebar/context rerun
        ):
            for hash_val in untagged_hashes:
                with st.chat_message("assistant"):
                    message_placeholder = st.empty()
                    message_placeholder.markdown(f"Checking hash reputation for {hash_val} via MCP...")
                    try:
                        hash_key = hash_val.strip().lower()
                        logger.info(f"[VT CHECK] hash_key: {hash_key}, cache keys: {list(st.session_state.checked_hashes.keys())}, prompt: {prompt}")
                        if hash_key not in st.session_state.checked_hashes:
                            logger.info(f"[VT CHECK] Invoking VT tool for hash: {hash_key}")
                            vt_response = check_hash_sync(hash_val)
                            result_struct = {
                                'raw': vt_response,
                                'timestamp': datetime.now(timezone.utc).isoformat(),
                                'malicious': vt_response.get('malicious', None) if isinstance(vt_response, dict) else ('malicious' in str(vt_response).lower()),
                                'threat_names': vt_response.get('threat_names', []) if isinstance(vt_response, dict) else [],
                                'categories': vt_response.get('categories', []) if isinstance(vt_response, dict) else []
                            }
                            st.session_state.checked_hashes[hash_key] = result_struct
                            save_hash_cache(st.session_state.checked_hashes)
                            tagged_result = re.sub(rf'{re.escape(hash_val)}', f'<checkedhash>{hash_val}</checkedhash>', str(vt_response))
                            message_placeholder.markdown(tagged_result)
                            st.session_state.messages.append({"role": "assistant", "content": tagged_result})
                        else:
                            logger.info(f"[VT CHECK] Hash {hash_key} found in cache. Skipping VT tool.")
                            # Already cached, just return the cached result with <checkedhash> tags
                            cached = st.session_state.checked_hashes[hash_key]
                            tagged_result = re.sub(rf'{re.escape(hash_val)}', f'<checkedhash>{hash_val}</checkedhash>', str(cached['result']))
                            message_placeholder.markdown(tagged_result)
                            st.session_state.messages.append({"role": "assistant", "content": tagged_result})
                        if advanced_memory_enabled:
                            save_chat_history(st.session_state.session_id, st.session_state.messages)
                        #  Update chat context with this Q/A 
                        st.session_state.chat_context.append({
                            'user': prompt,
                            'assistant': tagged_result,
                            'entities': extract_entities(prompt, st.session_state.checked_hashes.get(hash_key)),
                            'timestamp': datetime.now(timezone.utc).isoformat()
                        })
                        
                    except Exception as e:
                        logger.error(f"Error during MCP hash check: {e}", exc_info=True)
                        error_message = f"Sorry, error checking hash reputation: {str(e)}"
                        message_placeholder.error(error_message, icon="")
                        if not already_last_assistant_response(error_message):
                            st.session_state.messages.append({"role": "assistant", "content": error_message})
                        if advanced_memory_enabled:
                            save_chat_history(st.session_state.session_id, st.session_state.messages)
        # If hashes are already tagged, and there are follow-up questions, use the saved data
        elif hasattr(agent_instance, 'is_valid_hash') and not untagged_hashes and re.search(r'<checkedhash>([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})</checkedhash>', prompt):
            # Extract the tagged hash
            tagged_hashes = re.findall(r'<checkedhash>([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})</checkedhash>', prompt)
            for hash_val in tagged_hashes:
                hash_key = hash_val.strip().lower()
                logger.info(f"[TAGGED VT CHECK] hash_key: {hash_key}, cache keys: {list(st.session_state.checked_hashes.keys())}, prompt: {prompt}")
                if hash_key not in st.session_state.checked_hashes:
                    logger.info(f"[TAGGED VT CHECK] Invoking VT tool for tagged hash: {hash_key}")
                    vt_response = check_hash_sync(hash_val)
                    result_struct = {
                        'raw': vt_response,
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    }
                    st.session_state.checked_hashes[hash_key] = result_struct
                    save_hash_cache(st.session_state.checked_hashes)
                    tagged_result = re.sub(rf'{re.escape(hash_val)}', f'<checkedhash>{hash_val}</checkedhash>', str(vt_response))
                    with st.chat_message("assistant"):
                        st.markdown(tagged_result)
                        if not already_last_assistant_response(tagged_result):
                            st.session_state.messages.append({"role": "assistant", "content": tagged_result})
                        if advanced_memory_enabled:
                            save_chat_history(st.session_state.session_id, st.session_state.messages)
                        st.session_state.chat_context.append({
                            'user': prompt,
                            'assistant': tagged_result,
                            'entities': extract_entities(prompt, result_struct),
                            'timestamp': datetime.now(timezone.utc).isoformat()
                        })
                else:
                    logger.info(f"[TAGGED VT CHECK] Tagged hash {hash_key} found in cache. Skipping VT tool.")
                    cached = st.session_state.checked_hashes[hash_key]
                    tagged_result = re.sub(rf'{re.escape(hash_val)}', f'<checkedhash>{hash_val}</checkedhash>', str(cached['result']))
                    with st.chat_message("assistant"):
                        st.markdown(tagged_result)
                        if not already_last_assistant_response(tagged_result):
                            st.session_state.messages.append({"role": "assistant", "content": tagged_result})
                        if advanced_memory_enabled:
                            save_chat_history(st.session_state.session_id, st.session_state.messages)
                        st.session_state.chat_context.append({
                            'user': prompt,
                            'assistant': tagged_result,
                            'entities': extract_entities(prompt, cached),
                            'timestamp': datetime.now(timezone.utc).isoformat()
                        })
        else:
            # Get response from the agent as before
            with st.chat_message("assistant"):
                message_placeholder = st.empty()
                message_placeholder.markdown("Thinking...")
                try:
                    logger.info("Calling agent.run()...")
                    N = 10  # or whatever fits your LLM's context window
                    context_window = st.session_state.messages[-N:]
                    rag_references = []
                    rag_reference_sources = []
                    if "rag_vectorstore" in st.session_state and st.session_state.rag_vectorstore and prompt:
                        docs = st.session_state.rag_vectorstore.similarity_search(prompt, k=3)
                        rag_context = "\n\n".join([doc.page_content for doc in docs])
                        if rag_context:
                            context_window.append({"role": "assistant", "content": rag_context})
                            context_prompt = f"Context:\n{rag_context}\n\n{context_prompt}"
                            # Prepare references for UI
                            rag_references = docs
                            # Try to find the source file for each doc chunk by matching content
                            rag_reference_sources = []
                            for idx, doc in enumerate(docs):
                                try:
                                    source = rag_chunk_sources[idx] if idx < len(rag_chunk_sources) else "[Unknown]"
                                except Exception:
                                    source = "[Unknown]"
                                rag_reference_sources.append(source)

                    #  Pass compressed chat context to LLM as part of the prompt 
                    
                    agent_response_text = agent_instance.run(st.session_state.messages, hash_cache=st.session_state.checked_hashes, max_cache_size=100)
                    logger.info("Agent response received.")

                    # Show <think>...</think> as a collapsible section if present
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

                    # Show RAG references if available
                    if rag_references and rag_reference_sources:
                        refs_md = "\n".join([
                            f"**[{i+1}]** ({rag_reference_sources[i]}) {doc.page_content[:120].replace(chr(10), ' ')}..." for i, doc in enumerate(rag_references)
                        ])
                        with st.expander("References", expanded=True):
                            st.markdown(refs_md)

                    if not (st.session_state.messages and st.session_state.messages[-1]["role"] == "assistant" and st.session_state.messages[-1]["content"] == agent_response_text):
                        st.session_state.messages.append({"role": "assistant", "content": agent_response_text})
                    if advanced_memory_enabled:
                        save_chat_history(st.session_state.session_id, st.session_state.messages)
                    #  Update chat context with this Q/A 
                    st.session_state.chat_context.append({
                        'user': prompt,
                        'assistant': agent_response_text,
                        'entities': extract_entities(prompt),
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    })
                    
                except Exception as e:
                    logger.error(f"Error during agent execution: {e}", exc_info=True)
                    error_message = f"Sorry, I encountered an error processing your request: {str(e)}"
                    message_placeholder.error(error_message, icon="💥")
                    st.session_state.messages.append({"role": "assistant", "content": error_message})
                    if advanced_memory_enabled:
                        save_chat_history(st.session_state.session_id, st.session_state.messages)
                        logger.info("Streamlit app finished processing request or waiting for input.")
                    logger.info("Calling agent.run()...")
                    # RAG: Retrieve context from docs if available
                    rag_context = ""
                    rag_references = None
                    rag_reference_sources = None

                    #  Advanced Memory: Prepend chat history to prompt 
                    if advanced_memory_enabled:
                        # Use last N messages or a summary
                        N = 8
                        history = st.session_state.messages[-N:]
                        # Format history as a chat transcript
                        history_str = "\n".join([
                            f"{m['role'].capitalize()}: {m['content']}" for m in history[:-1]  # exclude current user prompt
                        ])
                        context_prompt = f"Conversation so far:\n{history_str}\nUser: {prompt}"
                    else:
                        context_prompt = prompt

                    if "rag_vectorstore" in st.session_state and st.session_state.rag_vectorstore and prompt:
                        docs = st.session_state.rag_vectorstore.similarity_search(prompt, k=3)
                        rag_context = "\n\n".join([doc.page_content for doc in docs])
                        if rag_context:
                            context_prompt = f"Context:\n{rag_context}\n\n{context_prompt}"
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

                    agent_response_text = agent_instance.run(st.session_state.messages, hash_cache=st.session_state.checked_hashes, max_cache_size=100)
                    logger.info("Agent response received.")

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
                            f"**[{i+1}]** ({rag_reference_sources[i]}) {doc.page_content[:120].replace(chr(10), ' ')}..."
                            for i, doc in enumerate(rag_references)
                        ])
                        with st.expander("References", expanded=True):
                            st.markdown(refs_md)
                    st.session_state.messages.append({"role": "assistant", "content": error_message})
                    if advanced_memory_enabled:
                        save_chat_history(st.session_state.session_id, st.session_state.messages)

logger.info("Streamlit app finished processing request or waiting for input.")
import streamlit as st
import logging
from rich_logger import RichLogger
import requests

# Import setup functions from other modules
from config import VT_API_KEY, OLLAMA_MODEL_ID, OLLAMA_API_BASE
from agent_setup import get_chat_agent

# Helper to get available Ollama models
import os
import time
from datetime import datetime, timezone
import re
from utils import load_hash_cache, save_hash_cache, extract_hashes, extract_entities, get_ollama_models
import uuid
from chat_memory import save_agent_memory, load_agent_memory, list_sessions, set_session_name, get_session_name
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
logger = RichLogger.get_logger(__name__)
logger.info("Streamlit Application starting...")

# Page Configuration 
st.set_page_config(page_title="Chat & File Reputation", layout="wide")
st.title("💬 Chat & Check 🔬")

# Ensure selected_model is initialized before using it
if "selected_model" not in st.session_state:
    st.session_state.selected_model = OLLAMA_MODEL_ID

st.caption(f"Using {st.session_state.selected_model} via {OLLAMA_API_BASE}. Provide a file hash for VirusTotal check.")

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
        prev_history = load_agent_memory(selected_session_id)
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
        loaded_history = load_agent_memory(st.session_state.session_id)
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
        # Re-initialize agent with new model if needed (SmolAgents handles model caching)
        st.session_state.agent_instance = get_chat_agent()
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
    st.session_state.agent_instance = get_chat_agent()
agent_instance = st.session_state.agent_instance

# Sidebar Info 
st.sidebar.header("Configuration Status")

# Display Other Config Status 
st.sidebar.markdown("**Other Components:**")
if VT_API_KEY:
    st.sidebar.success("VirusTotal API Key: Loaded.", icon="🔑")
    # logger.info("VirusTotal API Key Loaded.") # Less verbose logging
else:
    st.sidebar.error("VirusTotal API Key: Missing!", icon="🚨")
    st.sidebar.markdown("Set `VT_API_KEY` in `.env`. The CheckFileHashReputationTool needs this.")
    logger.error("VirusTotal API Key is missing.")

if agent_instance:
    st.sidebar.success(f"Ollama Agent ({st.session_state.selected_model}): Initialized", icon="🤖")
else:
    st.sidebar.error(f"Ollama Agent ({st.session_state.selected_model}): Failed to initialize!", icon="🚨")
    st.sidebar.markdown(f"Check Ollama server at `{OLLAMA_API_BASE}`.")
    logger.error(f"Ollama Agent Initialization failed. Check Ollama server at {OLLAMA_API_BASE}")

# Chat UI 
# Display all chat messages from history (including the last assistant message)
if st.session_state.messages:
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

# React to user input
if "checked_hashes" not in st.session_state or not isinstance(st.session_state.checked_hashes, dict):
    st.session_state.checked_hashes = load_hash_cache()


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
        save_agent_memory(st.session_state.session_id, st.session_state)

    # Check if agent is available before proceeding
    if not agent_instance:
        st.error("Chat agent is not available. Cannot process request.", icon="⚠️")
    else:
        # Get response from the agent as before
        with st.chat_message("assistant"):
            message_placeholder = st.empty()
            message_placeholder.markdown("Thinking...")
            agent_response_text = ""  # Ensure always defined for this block
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
            except Exception as e:
                logger.error(f"Error during agent execution: {e}", exc_info=True)
                error_message = f"Sorry, I encountered an error processing your request: {str(e)}"
                message_placeholder.error(error_message, icon="💥")
                st.session_state.messages.append({"role": "assistant", "content": error_message})
                if advanced_memory_enabled:
                    save_agent_memory(st.session_state.session_id, st.session_state)
                    logger.info("Streamlit app finished processing request or waiting for input.")

            # Pass only the latest user prompt or context_prompt to agent.run()
            from think_utils import extract_think_blocks
            agent_input = context_prompt if 'context_prompt' in locals() else (st.session_state.messages[-1]['content'] if st.session_state.messages and isinstance(st.session_state.messages[-1], dict) and 'content' in st.session_state.messages[-1] else '')
            agent_response_text = ""  # Ensure this is always defined
            logger.info("Getting response from agent_instance.run()...")
            response = agent_instance.run(agent_input)  # stream=False by default
            collected = getattr(response, 'action_output', None)
            if collected is None:
                collected = str(response)
            from think_utils import extract_think_blocks
            main, _ = extract_think_blocks(collected)
            main_response = main.strip() if main.strip() else ""

            # Enhanced Output Handling for CheckFileHashReputationTool
            if not hasattr(st.session_state, 'checkreputation_output'):
                st.session_state.checkreputation_output = None

            # Robust VirusTotal Report Concatenation
            # Detect if CheckFileHashReputationTool was called and capture its output
            if "Calling tool: 'check_file_hash_reputation_tool'" in collected:
                st.session_state.checkreputation_output = main_response

            # LOGGING: Tools Called
            # Dynamically get known_tools from the agent
            if hasattr(agent_instance, 'tools') and isinstance(agent_instance.tools, dict):
                known_tools = list(agent_instance.tools.keys())
            else:
                known_tools = []
            # Find which tools were called in this response
            tools_called = [tool_name for tool_name in known_tools if f"Calling tool: '{tool_name}'" in collected]
            if tools_called:
                logger.info(f"Tools called in this response: {tools_called}")
            else:
                logger.info("No tools called in this response.")

            def is_new_hash_message():
                if len(st.session_state.messages) >= 2:
                    last_user = st.session_state.messages[-2]
                    return last_user["role"] == "user" and is_valid_hash(last_user["content"].strip())
                return False

            # Only clear checkreputation_output if a new valid hash is submitted and tool was NOT called
            if is_new_hash_message() and "Calling tool: 'check_file_hash_reputation_tool'" not in collected:
                st.session_state.checkreputation_output = None

            # Always prepend the last VT report to any LLM output, unless the tool just ran
            if st.session_state.checkreputation_output:
                if main_response and main_response != st.session_state.checkreputation_output:
                    concatenated_response = f"{st.session_state.checkreputation_output}\n\n{main_response}"
                else:
                    concatenated_response = st.session_state.checkreputation_output
            else:
                concatenated_response = main_response

            # Track last successful tool result (legacy)
            if not hasattr(st.session_state, 'last_tool_result'):
                st.session_state.last_tool_result = None

            # Dynamically get known_tools from the agent
            if hasattr(agent_instance, 'tools') and isinstance(agent_instance.tools, dict):
                known_tools = list(agent_instance.tools.keys())
            else:
                known_tools = []

            # Heuristic: If the response contains a tool call and a known tool, update last_tool_result
            for tool_name in known_tools:
                if f"Calling tool: '{tool_name}'" in collected:
                    st.session_state.last_tool_result = main_response
                    break

            # If the next tool to call cannot be found, return last tool result as 'What I have found so far'
            if 'unknown_tool' in collected or any(f"'{tool_name}'" in collected for tool_name in ['unknown_tool']):
                # If last tool was explain_text_tool, prefer its output
                if hasattr(st.session_state, 'last_tool_result') and st.session_state.last_tool_result:
                    # Try to detect if last tool was explain_text_tool by checking collected for its call
                    if "Calling tool: 'explain_text_tool'" in collected or "explain_text_tool" in collected:
                        main_response = st.session_state.last_tool_result
                    else:
                        main_response = f"What I have found so far:\n\n{st.session_state.last_tool_result}"
                else:
                    main_response = "Sorry, I couldn't recognize the requested tool. Please try rephrasing your request or ask for a supported action."
                logger.warning("Unknown tool requested by model. User notified.")
            elif any(f"Calling tool: '{tool_name}'" in collected and tool_name not in known_tools for tool_name in known_tools):
                if st.session_state.last_tool_result:
                    main_response = f"What I have found so far:\n\n{st.session_state.last_tool_result}"
                else:
                    main_response = "Sorry, the tool requested is not supported. Please try again with a supported action."
                logger.warning("Unsupported tool requested by model. User notified.")

            # Always display the concatenated CheckFileHashReputationTool output (if present) and any following output
            if concatenated_response:
                message_placeholder.markdown(concatenated_response, unsafe_allow_html=True)
                logger.info(f"Final assistant response streamed to UI: {concatenated_response}")
            else:
                logger.warning("Agent response was empty after processing.")
            agent_response_text = concatenated_response
            logger.info("Agent response collected and ready for post-processing.")

            # Show RAG references if available
            if rag_references and rag_reference_sources:
                refs_md = "\n".join([
                    f"**[{i+1}]** ({rag_reference_sources[i]}) {doc.page_content[:120].replace(chr(10), ' ')}..." for i, doc in enumerate(rag_references)
                ])
                with st.expander("References", expanded=True):
                    st.markdown(refs_md)

            # Only append the assistant's response if it's not already the last message
            if not (st.session_state.messages and st.session_state.messages[-1]["role"] == "assistant" and st.session_state.messages[-1]["content"].strip() == agent_response_text.strip()):
                st.session_state.messages.append({"role": "assistant", "content": agent_response_text})
            if advanced_memory_enabled:
                save_agent_memory(st.session_state.session_id, st.session_state)
            logger.info("Streamlit app finished processing request or waiting for input.")
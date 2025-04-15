# SmolVTAgent: Chat & VirusTotal File Reputation Checker (Just playing around)

SmolVTAgent is a Streamlit web application that provides a conversational AI interface powered by a local Ollama LLM (e.g., Qwen 2.5 7B, Llama 3). It features a tool for checking the reputation of file hashes (MD5, SHA1, SHA256) via the VirusTotal API, using a FastMCP tool.

---

## Dependencies

The following Python packages are required (see `requirements.txt`):

- streamlit
- requests
- python-dotenv
- fastmcp
- langchain
- langchain-community
- langchain-ollama
- langchain-text-splitters
- chromadb  # Used as the vector store for RAG (Windows compatible)
- markitdown[all]
- PyPDF2
- python-docx

All dependencies can be installed with:
```sh
pip install -r requirements.txt
```

---

## Features

- **Conversational AI:** Chat with a local Ollama LLM (customizable model).
- **VirusTotal Integration:** Ask about a file hash—SmolVTAgent queries VirusTotal and summarizes the results.
- **Modern Agentic Pattern:** Uses FastMCP (with SSE transport) for tool calls, ensuring reliability and scalability.
- **Health Checks:** Streamlit app checks the FastMCP server's health via SSE.
- **Configurable:** API keys, model, and endpoints are set via `.env` or environment variables.
- **Logging:** Logs to both file and console for easy troubleshooting.

---

## Setup Instructions

### Prerequisites
- Python 3.10+
- [Ollama](https://ollama.com/) installed and running locally
- A VirusTotal API Key ([get one free](https://www.virustotal.com/))
- (Recommended) Create and activate a Python virtual environment

### Installation
1. **Clone or Download the Repository:**
    ```sh
    # git clone <repository-url>
    cd SmolVTAgent
    ```

2. **Install Python dependencies:**
    ```sh
    pip install -r requirements.txt
    ```

3. **Configure Environment:**
    - Copy `.env.example` to `.env` and fill in your API keys and model settings.
    - Required env variables:
        - `VT_API_KEY` (VirusTotal)
        - `OLLAMA_MODEL_ID`, `OLLAMA_API_BASE` (Ollama LLM)

4. **Start the app:**
    ```sh
    streamlit run app.py
    ```

**Note:**
- Chroma is used as the vector store for RAG, which is compatible with Windows. No FAISS installation is needed.
- For document upload and RAG, all dependencies are included in `requirements.txt`.
2. **Create a Virtual Environment:**
    ```sh
    python -m venv venv
    # Windows:
    .\venv\Scripts\activate
    # macOS/Linux:
    # source venv/bin/activate
    ```
3. **Install Dependencies:**
    ```sh
    pip install -r requirements.txt
    ```
4. **Configure Environment:**
    - Create a `.env` file in the project root with:
      ```env
      VT_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
      OLLAMA_MODEL_ID="qwen2.5:7b"  # Or your preferred model
      OLLAMA_API_BASE="http://localhost:11434"
      ```
    - Ensure your Ollama server is running and the model is pulled (e.g., `ollama pull qwen2.5:7b`).

---

## Running the Application

1. **Start the FastMCP Tool Server (SSE mode):**
    ```sh
    python fastmcp_server.py
    ```
    - This exposes the MCP API at `http://localhost:8000/sse`.
2. **Start the Streamlit App:**
    ```sh
    streamlit run app.py
    ```
    - Open the provided local URL (usually `http://localhost:8501`).

---

## Project Structure

```
SmolVTAgent/
├── app.py               # Streamlit app (UI, chat, health checks)
├── fastmcp_server.py    # FastMCP tool server (VirusTotal tool)
├── ollama_agent.py      # LLM agent logic and MCP client
├── config.py            # Loads API keys and config
├── requirements.txt     # Python dependencies
├── .env                 # Environment variables (not committed)
├── app.log              # Log file
└── README.md            # This file
```

---

## Features

### Context-Aware Chat and Hash Caching
- **Hash Caching:**
  - Hash reputation lookups are cached in `hash_cache.json` with metadata (result, timestamp, verdict, threat names, categories, and raw VT response).
  - If a hash has already been checked, the cached result is used for instant responses and to avoid unnecessary API calls.
  - The cache is only updated when a new hash is submitted by the user, not during session/context restoration.
- **Follow-up Question Handling:**
  - The chat system tracks the last N (default 5) question/answer pairs, extracting important entities (hashes, verdicts, etc.).
  - You can ask follow-up questions like "What about the last hash?" or "What did we find earlier?" and the system will resolve these references using the recent chat context.
  - The chat context is compressed and included in LLM prompts for more accurate, context-aware answers.
- **LLM Prompt Context:**
  - When you interact with the LLM, it receives a compact, relevant summary of recent chat history and entities, improving follow-up accuracy and conversation flow.

### Cache Management
- **Location:** Hash cache is stored in `hash_cache.json` in the project directory.
- **Clearing the Cache:** You can delete or edit this file to clear all cached hash results. The cache is only written when new hash results are obtained.
- **Cache Expiry:** (Optional) You may implement cache expiry logic if you want results to auto-refresh after a certain period. By default, cached results persist until deleted.

---

## Troubleshooting
- **Server Unreachable:** Ensure `python fastmcp_server.py` is running and no firewall is blocking port 8000.
- **Ollama Errors:** Make sure Ollama is installed, running, and the model is available.
- **API Key Issues:** Confirm your VirusTotal API key is valid and not rate-limited.
- **Cache Issues:** If you notice stale or incorrect hash results, try deleting `hash_cache.json` and restarting the application.
- **Follow-up Context Issues:** If follow-up questions like "the last hash" are not resolved, ensure the chat context has at least one hash-related question/answer pair.
- **Logs:** Check `app.log` for detailed error messages.

---

## License
MIT License. See LICENSE file for details.

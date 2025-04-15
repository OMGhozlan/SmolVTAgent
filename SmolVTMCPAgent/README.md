# SmolVTAgent: Chat & VirusTotal File Reputation Checker (Just playing around)

SmolVTAgent is a Streamlit web application that provides a conversational AI interface powered by a local Ollama LLM (e.g., Qwen 2.5 7B, Llama 3). It features a tool for checking the reputation of file hashes (MD5, SHA1, SHA256) via the VirusTotal API, using a FastMCP tool.

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

## Troubleshooting
- **Server Unreachable:** Ensure `python fastmcp_server.py` is running and no firewall is blocking port 8000.
- **Ollama Errors:** Make sure Ollama is installed, running, and the model is available.
- **API Key Issues:** Confirm your VirusTotal API key is valid and not rate-limited.
- **Logs:** Check `app.log` for detailed error messages.

---

## License
MIT License. See LICENSE file for details.

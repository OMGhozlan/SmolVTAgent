# SmolVTAgent

SmolVTAgent is a Streamlit web application that provides a conversational AI interface powered by a local Ollama LLM (e.g., Qwen 2.5 7B, Llama 3). It features a tool for checking the reputation of file hashes (MD5, SHA1, SHA256) via the VirusTotal API, and can explain or summarize any text you provide. The agent uses SmolAgents for robust, multi-step tool use and reasoning.

---

## Features
- **Conversational AI:** Chat with a local Ollama LLM (customizable model).
- **Explain or Summarize Any Text:** Paste or type any text (e.g., error message, technical report, or documentation) and the agent will use the LLM to explain or summarize it in simple terms.
- **VirusTotal Integration:** Ask about a file hash—SmolVTAgent queries VirusTotal and summarizes the results.
- **Modern Agentic Pattern:** Uses SmolAgents for tool calls, ensuring reliability and scalability.
- **Dynamic Tool Handling:** The agent automatically tracks and manages its available tools.
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

---

## How to Use
- **Explain/Summarize:** Type or paste any text (e.g., error message, technical description, or documentation) and ask for an explanation or summary.
- **File Hash Reputation:** Enter a file hash (MD5, SHA1, or SHA256) to check its safety using VirusTotal.
- **Conversational Context:** The agent can answer follow-up questions and refer to previous results in the chat.

---

## Project Structure
```
SmolVTAgent/
├── app.py               # Streamlit app (UI, chat, health checks)
├── agent_setup.py       # LLM agent logic and tool setup
├── config.py            # Loads API keys and config
├── requirements.txt     # Python dependencies
├── .env                 # Environment variables (not committed)
└── app.log              # Log file
```

---

## Troubleshooting
- **Ollama Errors:** Make sure Ollama is installed, running, and the model is available. You can select the active model from the sidebar dropdown in the app UI.
- **API Key Issues:** Confirm your VirusTotal API key is valid and not rate-limited.
- **Cache Issues:** If you notice stale or incorrect hash results, try deleting `hash_cache.json` and restarting the application.
- **Logs:** Check `app.log` for detailed error messages.

---

## License
MIT License. See LICENSE file for details.

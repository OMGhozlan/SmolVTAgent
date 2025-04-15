# SmolVTAgent: Chat & File Reputation Checker

This is a Streamlit application that provides a conversational interface powered by a local Ollama Language Model (LLM). It includes a tool that allows the LLM to check the reputation of file hashes (MD5, SHA1, SHA256) using the VirusTotal API v3.

## Features

*   **Conversational AI:** Chat with an Ollama LLM (e.g., Qwen 2.5 7B, Llama 3.1) running locally.
*   **VirusTotal Integration:** Ask the agent about a file hash, and it will use a tool to query the VirusTotal API.
*   **Formatted Reports:** Displays a detailed, formatted summary of the VirusTotal report within the chat interface.
*   **Configuration:** Uses environment variables or Streamlit secrets for easy setup of API keys and model details.
*   **Logging:** Basic logging implemented for troubleshooting.

## Setup

### Prerequisites

*   Python 3.8+
*   Ollama installed and running locally ([https://ollama.com/](https://ollama.com/))
*   An Ollama model pulled (e.g., `ollama pull qwen2.5:7b`)
*   A VirusTotal API Key (Free tier available: [https://www.virustotal.com/](https://www.virustotal.com/))

### Installation

1.  **Clone the repository (or download the files):**
    ```bash
    # If using git
    # git clone <repository-url>
    # cd SmolVTAgent
    ```

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python -m venv venv
    # On Windows
    .\venv\Scripts\activate
    # On macOS/Linux
    # source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configuration:**
    *   Create a file named `.env` in the project root directory (`h:\SmolVTAgent`).
    *   Add the following variables, replacing the placeholder values:
        ```dotenv
        # .env
        VT_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
        OLLAMA_MODEL_ID="ollama_chat/qwen2.5:7b" # Or your desired Ollama model ID prefixed with ollama_chat/
        OLLAMA_API_BASE="http://localhost:11434" # Default Ollama API endpoint
        ```
    *   **Note:** For deployed Streamlit applications, you can use Streamlit Secrets instead of the `.env` file for `VT_API_KEY`.

## How to Run

1.  Ensure your Ollama server is running.
2.  Make sure you are in the project's root directory (`h:\SmolVTAgent`) with your virtual environment activated.
3.  Run the Streamlit application:
    ```bash
    streamlit run app.py
    ```
4.  Open the local URL provided by Streamlit (usually `http://localhost:8501`) in your web browser.

## Key Dependencies

*   [Streamlit](https://streamlit.io/): For creating the web application interface.
*   [SmolAgents](https://github.com/smol-ai/Smol-Developer): Framework for creating LLM agents with tools.
*   [LiteLLM](https://github.com/BerriAI/litellm): Interface for interacting with various LLMs, including Ollama.
*   [Requests](https://requests.readthedocs.io/en/latest/): For making HTTP requests to the VirusTotal API.
*   [python-dotenv](https://github.com/theskumar/python-dotenv): For loading environment variables from the `.env` file.

## Project Structure

```
h:\SmolVTAgent\
├── .env          # Local environment variables (API Key, Model ID) - Create this!
├── .gitignore    # Git ignore rules
├── app.log       # Log file generated during runtime
├── app.py        # Main Streamlit application logic and UI
├── agent_setup.py # Defines the SmolAgent tool and agent initialization
├── config.py     # Handles loading configuration (API keys, model settings)
├── vt_helper.py  # Functions for VirusTotal API interaction and result formatting
├── requirements.txt # Python package dependencies
└── README.md     # This file
```

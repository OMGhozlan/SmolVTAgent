import logging
import requests
import asyncio
from fastmcp import Client
from fastmcp.client.transports import SSETransport  # Use SSETransport for HTTP/SSE communication
import json
from langchain_ollama import OllamaLLM
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

from config import OLLAMA_MODEL_ID, OLLAMA_API_BASE # Assuming these are still in config.py
from vt_helper import is_valid_hash, format_vt_result # Keep format_vt_result here for now

import re

def extract_hashes(text):
    """Extract all valid MD5, SHA1, or SHA256 hashes from the input text."""
    patterns = [
        r'\b[a-fA-F0-9]{32}\b',  # MD5
        r'\b[a-fA-F0-9]{40}\b',  # SHA1
        r'\b[a-fA-F0-9]{64}\b',  # SHA256
    ]
    matches = []
    for pat in patterns:
        matches.extend(re.findall(pat, text))
    return list(set(matches))


# Constants 
# Deprecated, now using FastMCP Client
FASTMCP_TOOL_ENDPOINT = "http://localhost:8000/tools/check_hash_reputation/call"

class VirusTotalMCPClient:
    def __init__(self, url="http://localhost:8000/sse"):
        self.transport = SSETransport(url)

    async def check_hash(self, file_hash: str):
        try:
            async with Client(self.transport) as client:
                if not client.is_connected():
                    logger.error("Could not connect to FastMCP server.")
                    return "Error: Could not connect to FastMCP server."
                try:
                    # Optionally, list tools to check connection
                    tools = await client.list_tools()
                    if not any(tool.name == "check_hash_reputation" for tool in tools):
                        logger.error("'check_hash_reputation' tool not found on FastMCP server.")
                        return "Error: 'check_hash_reputation' tool not found on FastMCP server."
                    result = await client.call_tool("check_hash_reputation", {"hash_input": {"file_hash": file_hash}})
                    return result
                except Exception as e:
                    logger.error(f"Exception calling FastMCP tool: {e}", exc_info=True)
                    return f"Error: Exception calling FastMCP tool: {e}"
        except Exception as e:
            logger.error(f"Could not connect to FastMCP server: {e}", exc_info=True)
            return f"Error: Could not connect to FastMCP server: {e}"

def check_hash_sync(file_hash: str, url="http://localhost:8000/sse"):
    client = VirusTotalMCPClient(url)
    try:
        return asyncio.run(client.check_hash(file_hash))
    except Exception as e:
        logger.error(f"MCP client connection/call failed: {e}", exc_info=True)
        return f"Error: MCP client connection/call failed: {e}"

# Logging 
logger = logging.getLogger(__name__)

# Agent Class 
class VirusTotalOllamaAgent:
    def __init__(self, model_name=None):
        if model_name is None:
            model_name = OLLAMA_MODEL_ID
        try:
            self.llm = OllamaLLM(model=model_name, base_url=OLLAMA_API_BASE)
            logger.info(f"Ollama LLM initialized with model: {model_name} at {OLLAMA_API_BASE}")
        except Exception as e:
            logger.error(f"Failed to initialize Ollama LLM: {e}", exc_info=True)
            self.llm = None

        # Basic prompt template
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", "You are a helpful assistant. If the user provides a file hash (MD5, SHA1, SHA256), you MUST first check its reputation using the available tool before answering. If it's not a hash, answer normally."),
            ("user", "{input}")
        ])
        self.output_parser = StrOutputParser()
        
        if self.llm:
            self.chain = self.prompt | self.llm | self.output_parser
        else:
            self.chain = None

    def _call_fastmcp_tool(self, file_hash: str) -> str:
        """Calls the FastMCP server's hash check tool using FastMCP Client."""
        try:
            result = check_hash_sync(file_hash)
            return result
        except Exception as e:
            logger.exception(f"Unexpected error calling FastMCP tool: {e}")
            return f"Error: An unexpected error occurred while calling the VirusTotal tool."

    def run(self, user_input: str) -> str:
        """Process user input, checking for any hashes and summarizing results if found."""
        if not self.chain:
            return "Error: LLM is not initialized. Cannot process request."

        cleaned_input = user_input.strip()
        hashes = extract_hashes(cleaned_input)

        if hashes:
            tool_results = []
            for h in hashes:
                tool_result = self._call_fastmcp_tool(h)
                tool_results.append(f"Hash `{h}`: {tool_result}")
            tool_results_str = "\n".join(tool_results)
            prompt_with_context = (
                f"The user provided these hashes: {', '.join(hashes)}. "
                f"You checked them using a tool, and the results were:\n{tool_results_str}\n"
                f"Please summarize or inform the user based on these results."
            )
            logger.info("Invoking LLM with hash check context for multiple hashes.")
            return self.chain.invoke({"input": prompt_with_context})
        else:
            logger.info("No hashes detected. Invoking LLM directly.")
            return self.chain.invoke({"input": user_input})


# Helper function to get agent instance (similar to original setup) 
_agent_instance = None

def get_agent(model_name=None) -> VirusTotalOllamaAgent:
    global _agent_instance
    if _agent_instance is None or (model_name is not None and getattr(_agent_instance.llm, 'model', None) != model_name):
        logger.info(f"Creating new VirusTotalOllamaAgent instance for model: {model_name}")
        _agent_instance = VirusTotalOllamaAgent(model_name)
    return _agent_instance

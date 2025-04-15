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
    def __init__(self):
        try:
            self.llm = OllamaLLM(model=OLLAMA_MODEL_ID, base_url=OLLAMA_API_BASE)
            logger.info(f"Ollama LLM initialized with model: {OLLAMA_MODEL_ID} at {OLLAMA_API_BASE}")
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
        """Process user input, potentially checking hash via FastMCP tool."""
        if not self.chain:
            return "Error: LLM is not initialized. Cannot process request."

        cleaned_input = user_input.strip()
        
        # Check if input is a hash BEFORE calling the LLM
        if is_valid_hash(cleaned_input):
            logger.info(f"Input '{cleaned_input}' detected as a valid hash. Calling tool first.")
            tool_result = self._call_fastmcp_tool(cleaned_input)
            # Construct a prompt including the tool result for the LLM
            prompt_with_context = f"The user provided this hash: {cleaned_input}. You checked it using a tool, and the result was: '{tool_result}'. Please summarize this result or inform the user based on it."
            logger.info("Invoking LLM with hash check context.")
            return self.chain.invoke({"input": prompt_with_context}) 
        else:
            # If not a hash, just pass input to the LLM directly
            logger.info("Input is not a hash. Invoking LLM directly.")
            return self.chain.invoke({"input": user_input})

# Helper function to get agent instance (similar to original setup) 
_agent_instance = None

def get_agent() -> VirusTotalOllamaAgent:
    global _agent_instance
    if _agent_instance is None:
        logger.info("Creating new VirusTotalOllamaAgent instance.")
        _agent_instance = VirusTotalOllamaAgent()
    return _agent_instance
